#!/usr/bin/env python3

import argparse
import os
import sys
import threading
from time import sleep
from scapy.all import Ether, Packet, BitField, raw

import grpc
import json
from pprint import pprint

# Import P4Runtime lib from utils dir
# This approach is used to import P4Runtime library when it's located in a different directory.
# Probably there's a better way of doing this.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),'../utils/'))

# Import the necessary P4Runtime libraries
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.convert import decodeNum, decodeIPv4
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections #, connections

# Define a custom CPU header that encapsules additional information sent by the data plane
class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingressPort', 0, 16)]

# Custom function to decode Mac Addresses from a bytes object
def myDecodeMac(mac):
    return ':'.join(f'{byte:02x}' for byte in mac)

def _to_hex(v: int) -> str:
    # Format as 0x… using lowercase, adjust width if desired
    return f"0x{v:x}"

def normalize_hex_strings(param: dict) -> dict:
    if not param:
        return {}
    new_param = {}
    for k, v in param.items():
        if isinstance(v, str) and v.startswith("0x"):
            new_param[k] = int(v, 16)
        else:
            new_param[k] = v
    return new_param

# Custom function to handle gRPC errors and display useful debugging information
def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

# Function to read and print the current table rules from the switch and print them
def printTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch and prints them.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    if sw.HasP4ProgramInstalled():    
        for response in sw.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                # you can use the p4info_helper to translate
                # the IDs in the entry to names
                table_name = p4info_helper.get_tables_name(entry.table_id)
                print('%s: ' % table_name, end=' ')
                for m in entry.match:
                    print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                    print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')
                action = entry.action.action
                action_name = p4info_helper.get_actions_name(action.action_id)
                print('->', action_name, end=' ')
                for p in action.params:
                    print(p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                    print('%r' % p.value, end=' ')
                print()
    print()

# Function to install a default action entry into a table
def writeDefaultTableAction(p4info_helper, sw, table, intended_action):
    table_id = p4info_helper.get_tables_id(table)
    current_action_id = sw.getDefaultAction(table_id).action.action.action_id

    intended_action_id = p4info_helper.get_actions_id(intended_action)

    if current_action_id != intended_action_id:
        table_entry = p4info_helper.buildTableEntry(
            table_name=table,
            default_action=True,
            action_name=intended_action
        )
        sw.WriteTableEntry(table_entry)
        print(f"Updated default action in {table} on {sw.name} to {intended_action}")

# Function to write a MAC destination lookup entry to the table
def writeMacDstLookUp(p4info_helper, sw, mac, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.dMacLookup",
        match_fields = {
            "hdr.eth.dstAddr" : mac
        },
        default_action = False,
        action_name = "MyIngress.forward",
        action_params = {
            "egressPort": port
        },
        priority = 0)
    sw.WriteTableEntry(table_entry)
    print("Installed MAC DST rules on %s" % sw.name)

# Function to write a MAC source lookup entry to the table
def writeMacSrcLookUp(p4info_helper, sw, mac):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.sMacLookup",
        match_fields = {
            "hdr.eth.srcAddr" : mac
        },
        default_action = False,
        action_name = "NoAction",
        action_params = None, 
        priority = 0)
    sw.WriteTableEntry(table_entry)
    print("Installed MAC SRC rules on %s" % sw.name)
    
# Function to write an entry to a table of a switch
def writeTableEntry(helper, sw, table, match, action, params, dryrun=False, modify=False):
    # Normalize any hex-string into ints
    match  = normalize_hex_strings(match)
    params = normalize_hex_strings(params)

    table_entry = helper.buildTableEntry(
        table_name = table,
        match_fields = match,
        default_action = False,
        action_name = action,
        action_params = params,
        priority = 0)
    sw.WriteTableEntry(table_entry, dryrun, modify)
    #print("Installed rule for %s on %s" % (table, sw.name))

# Function to write a multicast group entry to the switch
def writeMcGroup(p4info_helper, sw, sessionId, broadcastReplicas):
    if not sw.isMulticastGroupInstalled(sessionId):
        mc_group = p4info_helper.buildMulticastGroupEntry(sessionId, broadcastReplicas)
        sw.WritePREEntry(mc_group)
        print(f"Installed Multicast Group {sessionId} on {sw.name}")

# Function to write a CPU session entry for packet cloning to the CPU port
def writeCpuSession(p4info_helper, sw, sessionId, cpuReplicas):
    if not sw.isCloneSessionInstalled(sessionId):
        clone_entry = p4info_helper.buildCloneSessionEntry(sessionId, cpuReplicas)
        sw.WritePREEntry(clone_entry)
        print(f"Installed clone session {sessionId} on {sw.name}")

# Function to create all P4Runtime connections to all the switches
# with gRPC and proto dump files for logging
def createConnectionsToSwitches(switches_config, connections, state):
    print("------ Connecting to the devices... ------")

    connections.clear()
    for switch in switches_config:
        name = switch["name"]
        connections[name] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=name,
            address=switch["address"],
            device_id=switch["device_id"],
            proto_dump_file=switch["proto_dump_file"]
        )
        connections["name"].MasterArbitrationUpdate()
        state[name] = {}

    print("------ Connection successful! ------\n")

# Function to load the P4 program configuration from a JSON file
def loadProgramConfig(switch_programs_path):
        
    config_data = json.load(open(switch_programs_path))
    program_config = {}
    
    for sw_name, entry in config_data.items():
        helper_path = entry['p4info_path']
        json_path = entry['json_path']
        default_actions_path = entry['default_actions_path']
        rules_path = entry['rules_path']

        helper = p4runtime_lib.helper.P4InfoHelper(helper_path)
        program_config[sw_name] = {
            "helper": helper, 
            "json": json_path,
            "default_actions": default_actions_path,
            "rules": rules_path
        }
    
    return program_config

# Function to install the P4 programs on all switches
def installP4Programs(connections, program_config, reset=False):
    print("------ Installing P4 Programs... ------")

    for sw_name, sw_conn in connections.items():
        expected_helper = program_config[sw_name]["helper"] 
        json_path = program_config[sw_name]["json"]

        if reset:
            print(f"{sw_name}: Reseting switch, installing P4 program...")
        else:
            installed_p4info = sw_conn.GetInstalledP4Info()
            if installed_p4info is None:
                print(f"{sw_name}: No P4 program found, installing...")
            elif installed_p4info != expected_helper.p4info:
                print(f"{sw_name}: Different P4 program found, re-installing...")
            else:
                print(f"{sw_name}: Correct P4 program already installed, skipping.")
                continue

        sw_conn.SetForwardingPipelineConfig(p4info=expected_helper.p4info, bmv2_json_file_path=json_path)
        print(f"{sw_name}: P4 program installed.")

    print("------ P4 Programs Installation done! ------\n")

# Function to write clone engines and their sessionId
def writeCloneEngines(connections, program_config, clone_config, clones, state):
    print("------ Installing MC Groups and Clone Sessions... ------")

    for sw_name, sw in connections.items():
        if sw_name in clone_config.values():
            cfg = clone_config[sw_name]
            helper = program_config[sw_name]["helper"]

            if "mcSessionId" in cfg:
                mc_id  = cfg["mcSessionId"]
                mc_replicas  = cfg["broadcastReplicas"]
                writeMcGroup(helper, sw, mc_id, mc_replicas)
            
            if "cpuSessionId" in cfg:
                cpu_id = cfg["cpuSessionId"]
                cpu_replicas = cfg["cpuReplicas"]
                writeCpuSession(helper, sw, cpu_id, cpu_replicas)
                clones[sw_name]["id"] = cpu_id

                # Start a thread for each switch with a cpu session id defined
                # to listen for packet-in messages
                stop_event = threading.Event()
                clones[sw_name]["stop_event"] = stop_event
                
                thread = threading.Thread(
                    target=_listen_single_switch,
                    args=(program_config[sw_name]["helper"], connections[sw_name], clones, state),
                    daemon=True
                )
                clones[sw_name]["thread"] = thread
                thread.start()
            
    print("------ MC Groups and Clone Sessions done! ------\n")
        
# Function to write the default actions on all tables from all switches
def writeDefaultActions(connections, program_config, state):
    print("------ Writing Default Actions... ------")
    
    for sw_name, sw in connections.items():
        helper = program_config[sw_name]["helper"]
        da_path = program_config[sw_name]["default_actions"]
        try:
            with open(da_path) as f:
                actions = json.load(f)
        except FileNotFoundError:
            print(f"No default actions config for {sw_name}, skipping...")
            continue

        for table_name, action_name in actions.items():
            state[sw_name][table_name] = {}
            writeDefaultTableAction(helper, sw, table_name, action_name)
    
    print("------ Write Default Actions done! ------\n")
        
# Function to write the static rules in all tables from all L3 switches
def writeStaticRules(connections, program_config, state):
    print("------ Writing Static Rules... ------")

    # Load the desired rules from JSON files
    for sw_name, switch in connections.items():
        helper = program_config[sw_name]["helper"]
        rules_path = program_config[sw_name]["rules"]
        try:
            with open(rules_path) as f:
                switch_rules = json.load(f)
        except FileNotFoundError:
            print(f"No default actions config for {sw_name}, skipping...")
            continue

        for table, rules in switch_rules.items():
            for match, action_params in rules.items():
                match_dict = json.loads(match)  # Assuming match is serialized as a JSON string
                action = action_params["action"]
                params = action_params["params"]
                compareAndWriteRules(helper, switch, table, match_dict, action, params, state)

    print("------ Write Static Rules done! ------\n")
    
# Function to compare the current rule with the expected rule and write it if they differ
def compareAndWriteRules(helper, switch, table, match, expected_action, expected_params, state):
    # Get current state for the switch and table
    current_state = state[switch.name][table]
    
    # Check if the rule already exists
    match_str = json.dumps(match, sort_keys=True)
    if match_str in current_state:
        current_action = current_state[match_str]["action"]
        current_params = current_state[match_str]["params"]
        
        # If action or params differ, modify the entry
        if current_action != expected_action or current_params != expected_params:
            print(f"Updating rule on {switch.name} for table {table}")
            writeTableEntry(helper, switch, table, match, expected_action, expected_params, modify=True)
            # Update the state
            current_state[match_str] = {
                "action": expected_action,
                "params": expected_params
            }
    else:
        # If the rule does not exist, write it
        print(f"Adding rule to {switch.name} for table {table}")
        writeTableEntry(helper, switch, table, match, expected_action, expected_params)
        # Update the state
        current_state[match_str] = {
            "action": expected_action,
            "params": expected_params
        }

# Function to read the current table rules from the switch and store the known values
def readTableRules(connections, program_config, state):
    
    print("------ Reading Tables Rules... ------\n")

    for sw_name, sw in connections.items():
        helper = program_config[sw_name]["helper"]
        if not sw.HasP4ProgramInstalled():
            continue
        
        for response in sw.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table = helper.get_tables_name(entry.table_id)

                # 1. IPv4 LPM (leave as tuple of string/int)
                if table == "MyIngress.ipv4Lpm":
                    enc_ip = helper.get_match_field_value(entry.match[0])
                    ip = (decodeIPv4(enc_ip[0]), enc_ip[1])
                    action = helper.get_actions_name(entry.action.action.action_id)
                    if action == "MyIngress.forward":
                        params = {
                            "egressPort": decodeNum(entry.action.action.params[0].value),
                            "nextHopMac": myDecodeMac(entry.action.action.params[1].value)
                        }
                    else:
                        params = {}
                    key = json.dumps({"hdr.ipv4.dstAddr": list(ip)})
                    state[sw_name][table][key] = {
                        "action": action,
                        "params": params
                    }

                # 2. Label Lookup → store label as hex string
                elif table == "MyIngress.labelLookup":
                    lbl = decodeNum(helper.get_match_field_value(entry.match[0]))
                    action = helper.get_actions_name(entry.action.action.action_id)
                    if action == "MyIngress.forwardTunnel":
                        params = {
                            "egressPort": decodeNum(entry.action.action.params[0].value),
                            "nextHopMac": myDecodeMac(entry.action.action.params[1].value)
                        }
                    else:
                        params = {}
                    key = json.dumps({ "hdr.labels[0].label": _to_hex(lbl) })
                    state[sw_name][table][key] = {
                        "action": action,
                        "params": params
                    }

                # 3. Internal MAC Lookup
                elif table == "MyIngress.internalMacLookup":
                    port = decodeNum(helper.get_match_field_value(entry.match[0]))
                    imac = myDecodeMac(entry.action.action.params[0].value)
                    params = {"srcMac": imac}
                    action = helper.get_actions_name(entry.action.action.action_id)
                    key = json.dumps({ "standard_metadata.egress_spec": port })
                    state[sw_name][table][key] = {
                        "action": action,
                        "params": params
                    }

                # 4. Tunnel Lookup → also hex
                elif table == "MyIngress.tunnelLookup":
                    tun = decodeNum(helper.get_match_field_value(entry.match[0]))
                    lbl = decodeNum(entry.action.action.params[0].value)
                    params = { "labels": _to_hex(lbl) }
                    action = helper.get_actions_name(entry.action.action.action_id)
                    key = json.dumps({ "meta.tunnel": tun })
                    state[sw_name][table][key] = {
                        "action": action, 
                        "params": params
                    }

                # 5. Check Direction
                elif table == "MyIngress.checkDirection":
                    ingress = decodeNum(helper.get_match_field_value(entry.match[0]))
                    egress = decodeNum(helper.get_match_field_value(entry.match[1]))
                    direction = decodeNum(entry.action.action.params[0].value)
                    params = { "dir": direction }
                    action = helper.get_actions_name(entry.action.action.action_id)
                    key = json.dumps({
                        "meta.ingress_port": ingress, 
                        "standard_metadata.egress_spec": egress
                    })
                    state[sw_name][table][key] = {
                        "action": action,
                        "params": params
                    }

                # 6. Allowed TCP Ports
                elif table == "MyIngress.allowedPortsTCP":
                    port = decodeNum(helper.get_match_field_value(entry.match[0]))
                    action = helper.get_actions_name(entry.action.action.action_id)
                    key = json.dumps({ "hdr.tcp.dstPort": port })
                    state[sw_name][table][key] = {
                        "action": action,
                        "params": {}
                    }
                                    
                # 7. Allowed UDP Ports
                elif table == "MyIngress.allowedPortsUDP":
                    port = decodeNum(helper.get_match_field_value(entry.match[0]))
                    action = helper.get_actions_name(entry.action.action.action_id)
                    key = json.dumps({ "hdr.udp.dstPort": port })
                    state[sw_name][table][key] = {
                        "action": action,
                        "params": {}
                    }

                # 8. sMacLookup (L2 MAC Learning)
                elif table == "MyIngress.sMacLookup":
                    mac = myDecodeMac(helper.get_match_field_value(entry.match[0]))
                    action = helper.get_actions_name(entry.action.action.action_id)
                    state[sw_name][table][str(mac)] = {
                        "action": action,
                        "params": {}
                    }

    print("------ Read Tables Rules done! ------\n")

# Function to print the current state of the controller    
def printControllerState(state):
    print("---------- Controller State ----------")
    pprint(state)
    print()

# Function to detect which tunnel state is active or initialize the first tunnel state if none is found
def init_tunnel_states(connections, program_config, tunnels_config, tunnels, state):
    """
    For each tunnel entry in tunnels_config.json:
      - Try to detect its current installed state from `state[...]`
      - If nothing is found, install state=0 and mirror into `state[...]`
    """
    cfgs  = tunnels_config["tunnels"]
    table = tunnels_config["table"]
    mf    = tunnels_config["match_field"]
    tunnels.clear() # clear any previous state

    for tcfg in cfgs:
        name = tcfg["name"]
        swA  = tcfg["switchA"]

        # ensure the nested state
        state.setdefault(swA, {}).setdefault(table, {})

        # Try to detect current state by matching labels
        found = None
        for s in tcfg["states"]:
            # build the expected mapping of JSON‐serialized match→hexlabel
            exp = {
              json.dumps({mf:int(k)}, sort_keys=True): v
              for k,v in s["labelsA"].items()
            }
            actual = {
              k: entry["params"]["labels"]
              for k,entry in state[swA][table].items()
            }
            if exp == actual:
                found = s["id"]
                break
        
        # if not found, install state 0
        if found is None:
            s0 = tcfg["states"][0]
            print(f"[{name}] no existing config, installing initial state 0")
            for side in ("A","B"):
                sw   = connections[tcfg[f"switch{side}"]]
                hlp  = program_config[tcfg[f"switch{side}"]]["helper"]
                labels = s0[f"labels{side}"]

                for match_val, hexlbl in labels.items():
                    writeTableEntry(
                        hlp, sw, table, {mf:int(match_val)},
                        "MyIngress.addMSLP",
                        {"labels": hexlbl},
                        modify=False
                    )
                    # mirror into state
                    key = json.dumps({mf:int(match_val)}, sort_keys=True)
                    state[sw.name][table][key] = {
                        "action":"MyIngress.addMSLP",
                        "params":{"labels":hexlbl}
                    }
            found = 0
        else:
            print(f"[{name}] detected existing tunnel state {found}")
        
        tunnels[name]["state"] = found

# Function to dynamicly change the tunnel selection rules according to traffic metrics
def changeTunnelRules(connections, program_config, tunnels_config, tunnels, state):
    # Load our generic tunnel config
    tcfgs     = tunnels_config["tunnels"]
    interval  = tunnels_config["check_interval"]
    threshold = tunnels_config["threshold"]
    table     = tunnels_config["table"]
    mf        = tunnels_config["match_field"]
    cntr_name = tunnels_config["counter_name"]

    # For each tunnel in the JSON, start a monitor thread
    for tcfg in tcfgs:
        name = tcfg["name"]
        stop_event = threading.Event()
        tunnels[name]["stop_event"] = stop_event
        
        thread = threading.Thread(
            target=_monitor_single_tunnel,
            args=(
                connections, program_config, tcfg, interval, 
                threshold, table, mf, cntr_name, tunnels, state
            ),
            daemon=True
        )
        tunnels[name]["thread"] = thread
        thread.start()

def _monitor_single_tunnel(connections, program_config, tcfg, interval, threshold, 
                           table, mf, cntr_name, tunnel_states, state):
    name   = tcfg["name"]
    idxs   = tcfg["counter_index"]
    states = tcfg["states"]

    swA = connections[tcfg["switchA"]]
    swB = connections[tcfg["switchB"]]
    hA  = program_config[tcfg["switchA"]]["helper"]
    hB  = program_config[tcfg["switchB"]]["helper"]

    curr_state = tunnel_states[name]["state"]
    print(f"📡 Starting tunnel monitor '{name}' between {swA.name} ⇄ {swB.name}")

    while not tunnel_states[name]["stop_event"].is_set():
        # read the counters from both switches
        upA   = read_counter(hA, swA, cntr_name, idxs["A_up"])
        downA = read_counter(hA, swA, cntr_name, idxs["A_down"])
        upB   = read_counter(hB, swB, cntr_name, idxs["B_up"])
        downB = read_counter(hB, swB, cntr_name, idxs["B_down"])

        total_up   = upA + upB
        total_down = downA + downB
        print(f"[{name}] up={total_up}, down={total_down}")
        # Print individual counter values for both switches
        print(f"[{swA.name}] up={upA}, down={downA}")
        print(f"[{swB.name}] up={upB}, down={downB}")

        if abs(total_up - total_down) > threshold:
            # toggle state
            next_state = 1 - curr_state
            nxt = states[next_state]

            # write out new label assignments for both switches
            for sw, helper, labels in [
                (swA, hA, nxt["labelsA"]),
                (swB, hB, nxt["labelsB"])
            ]:
                for match_val, lbl in labels.items():
                    writeTableEntry(
                        helper, sw, table,
                        {mf: int(match_val)},
                        "MyIngress.addMSLP",
                        {"labels": lbl},
                        modify=True
                    )
                    key = json.dumps({mf:int(match_val)}, sort_keys=True)
                    state[sw.name][table][key] = {
                        "action":"MyIngress.addMSLP",
                        "params":{"labels":lbl}
                    }

            curr_state = next_state
            tunnel_states[name] = next_state
            print(f"[{name}] switched to state {curr_state}\n")
        else:
            print(f"[{name}] no switch needed\n")

        sleep(interval)

# Function to read the counter value from the switch
def read_counter(helper, switch, counter_name, index):
    try:
        counter_id = helper.get_counters_id(counter_name)
        for response in switch.ReadCounters(counter_id, index):
            for entity in response.entities:
                if entity.HasField("counter_entry"):
                    counter_entry = entity.counter_entry
                    return counter_entry.data.packet_count
        return 0
    except Exception as e:
        print(f"Error reading counter {counter_name} [{index}]: {e}")
        return 0
            
# Function to listen for packet-in messages on a single switch            
def _listen_single_switch(helper, sw, clones, state):
    print(f"🔍 Listening for packet-ins on {sw.name}")
    
    for response in sw.stream_msg_resp:
        if clones[sw.name]["stop_event"].is_set():
            print(f"🛑 Stopping packet-in listener for {sw.name}")
            break
        
        # Check if the response contains a packet-in message
        if response.packet:
            #print("Received packet-in message:")
            packet = Ether(raw(response.packet.payload))
            if packet.type == 0x1234:
                cpu_header = CpuHeader(bytes(packet.load))
                new_mac = cpu_header.macAddr   # e.g. "aa:bb:cc:dd:ee:ff"
                match_key = json.dumps({"hdr.eth.srcAddr": new_mac})
                #print("mac: %012X ingress_port: %s " % (new_mac, cpu_header.ingressPort))

                sw_state = state.setdefault(sw.name, {}).setdefault("MyIngress.sMacLookup", {})
                if match_key not in sw_state:
                    writeMacSrcLookUp(helper, sw, new_mac)
                    writeMacDstLookUp(helper, sw, new_mac, cpu_header.ingressPort)
                    sw_state[match_key] = {
                        "action": "NoAction",
                        "params": {}
                    }
                #else:
                    #print("Rules already set")
        else:
            print(f"[{sw.name}] Received non-packet-in message: {response}")

# Function to reset a switch by reinstalling the P4 program and resetting the state
def resetSwitch(sw_name, connections, program_config, clone_config, tunnels_cfg, clones, tunnels, state):
    print(f"🔄 Resetting switch {sw_name}...")

    # Clean ALL tunnel rules from ALL switches
    # This is needed to ensure that the tunnel rules are in sync with the new switch rules
    cleanTunnelRules(tunnels_cfg["table"], connections, program_config, tunnels, state)
    
    # Clean the clone sessions on this switch
    cleanCloneEngines(sw_name, clones)

    # Clear controller-side state for this switch
    state[sw_name] = {}
    
    # Reinstall P4 program, clones, default actions, and static rules, 
    # only for this switch
    sw_conn = {sw_name: connections[sw_name]}
    sw_program_cfg = {sw_name: program_config[sw_name]}
    setupSwitches(sw_conn, sw_program_cfg, clone_config, clones, state, reset=True)
    
    # Reinstall the tunnel rules for all switches
    setupTunnels(connections, program_config, tunnels_cfg["tunnels"], tunnels, state)
        
    # Print new table state
    printTableRules(program_config[sw_name]["helper"], connections[sw_name])

    print(f"✅ {sw_name} has been reset.")

# Function to clean all tunnel rules from a switch's tunnel table using the controller's state
def cleanTunnelRules(table_name, connections, program_config, tunnels, state):

    print("🧽 Cleaning ALL tunnel rules from all switches...")

    # Stop ALL tunnel monitor threads
    for tname, tinfo in tunnels.items():
        tinfo["stop_event"].set()
        tinfo["thread"].join()
        print(f"🛑 Stopped tunnel monitor for {tname}")
    tunnels.clear()
    
    # Remove all tunnel rules from the tables and state
    for sw_name, sw in connections.items():
        # Get current state for the table
        table_state = state.get(sw_name, {}).get(table_name, {})

        # Loop over all match entries in the state
        for key_str in list(table_state.keys()):  # list() to safely modify during iteration
            match_fields = json.loads(key_str)
            try:
                # Build and delete the entry
                entry = program_config[sw_name]["helper"].buildTableEntry(
                    table_name=table_name,
                    match_fields=match_fields,
                    default_action=False
                )
                sw.DeleteTableEntry(entry)
                del table_state[key_str]
                print(f"🗑️ Removed rule with match {match_fields} from {sw_name}")
            except Exception as e:
                print(f"⚠️ Could not remove rule {match_fields} from {sw_name}: {e}")

# Function to setup tunnels and start the load balancing threads
def setupTunnels(connections, program_config, tunnels_config, tunnels, state):
        
    # Initialize the tunnel state and check if any tunnels are already active
    init_tunnel_states(connections, program_config, tunnels_config, tunnels, state)
    # Thread to handle load balancing between the tunnels
    changeTunnelRules(connections, program_config, tunnels_config, tunnels, state)

# Function to load the configuration files for switches, programs, tunnels, and clones
def loadConfigFiles(switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path):

    switches_config = json.load(open(switches_config_path))
    program_config = loadProgramConfig(switch_programs_path)
    tunnels_config = json.load(open(tunnels_config_path))
    clone_config = json.load(open(clone_config_path))
    return switches_config, program_config, tunnels_config, clone_config

# Function to perform the initial setup of the switches
# including installing P4 programs, writing clone engines, default actions, and static rules
def setupSwitches(connections, program_config, clone_config, clones, state, reset=False):
    
    installP4Programs(connections, program_config, reset)
    writeCloneEngines(connections, program_config, clone_config, clones, state)
    writeDefaultActions(connections, program_config, state)
    readTableRules(connections, program_config, state)
    writeStaticRules(connections, program_config, state)

# Function to perform a full reset of the controller and switches
def fullReset(switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path, connections, clones, tunnels, state):
    print("🔄 Performing full reset of the controller and switches...")

    # Shutdown all switch connections
    ShutdownAllSwitchConnections()
    
    # Reload config files
    switches_config, program_config, tunnels_config, clone_config = loadConfigFiles(
        switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path)
    
    # Create new connections to the switches
    createConnectionsToSwitches(switches_config, connections, state)
    
    # Do the initial setup of the switches
    setupSwitches(connections, program_config, clone_config, clones, state, reset=True)

    # Setup the tunnels and start the load balancing threads
    setupTunnels(connections, program_config, tunnels_config, tunnels, state)

    return switches_config, program_config, tunnels_config, clone_config

# Function to reset the packet count of all counters on all switches
def resetAllCounters(connections, program_config, tunnels_config):
    # Reset tunnel counters
    for tcfg in tunnels_config["tunnels"]:
        for side, role in [("switchA", "A"), ("switchB", "B")]:
            sw_name = tcfg[side]
            helper  = program_config[sw_name]["helper"]
            sw      = connections[sw_name]
            idxs    = tcfg["counter_index"]
            counter_name = tcfg["counter"]
            # Reset both up/down indices
            resetCounter(helper, sw, counter_name, idxs[f"{role}_up"])
            resetCounter(helper, sw, counter_name, idxs[f"{role}_down"])
            
# Function to reset the packet count of a specific counter on a switch
def resetCounter(p4info_helper, sw, counter_name, idx):
    """
    Reset the packet_count of a counter at a given index to zero.
    """
    counter_id = p4info_helper.get_counters_id(counter_name)
    sw.WriteCounterEntry(counter_id, idx)
    print(f"🔄 Reset counter '{counter_name}' idx={idx} on {sw.name}")
    
# Function to stop the threads of the clone engines and clean them up
def cleanCloneEngines(sw_name, clones):
    
    # Check if the switch is already in the clones dictionary
    if sw_name in clones:
        clones[sw_name]["stop_event"].set()
        clones[sw_name]["thread"].join()
        del clones[sw_name]



# Main function that initializes P4Runtime connections and performs setup
def main(switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path):

    # Variables to store the state of the tables
    switches_config = {}
    program_config = {}
    clone_config = {}
    tunnels_config = {}
    state = {}
    connections = {}
    tunnels = {}
    clones = {}

    try:
        # Load config files
        switches_config, program_config, tunnels_config, clone_config = loadConfigFiles(
            switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path)

        # Create P4Runtime connections to the switches
        createConnectionsToSwitches(switches_config, connections, state)

        # Do the initial setup of the switches
        setupSwitches(connections, program_config, clone_config, clones, state)

        # Setup the tunnels and start the load balancing threads
        setupTunnels(connections, program_config, tunnels_config, tunnels, state)

        # Loop to handle user input for resetting switches and showing state
        while True:
            user_input = input(">>> ").strip()
            parts = user_input.split()
            cmd = parts[0].lower()
            
            if cmd == "reset" and len(parts) == 2:
                target = parts[1]

                if target == "all":
                    # Perform a full reset of the controller and switches
                    switches_config, program_config, tunnels_config, clone_config = fullReset(
                        switch_programs_path, switches_config_path, tunnels_config_path, 
                        clone_config_path, connections, clones, tunnels, state)
                
                elif target == "tunnels":
                    # Clean tunnel rules from all switches
                    cleanTunnelRules(tunnels_config["table"], connections,
                                     program_config, tunnels, state)
                    # Setup the tunnels and start the load balancing threads
                    setupTunnels(connections, program_config, tunnels_config, 
                                 tunnels, state)
                    
                elif target == "counters":
                    # Reset all counters on all switches
                    resetAllCounters(connections, program_config, tunnels_config)
                    
                elif target in connections:
                    # Load config files
                    switches_config, program_config, tunnels_config, clone_config = loadConfigFiles(
                        switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path)
                    # Reset the specified switch
                    resetSwitch(target, connections, program_config, clone_config,
                                tunnels_config, clones, tunnels, state)

                else:
                    print(f"Unknown target for reset: '{target}'")

            elif cmd == "show" and len(parts) == 2:
                target = parts[1]
                
                if target == "state":
                    printControllerState(state)
                
                elif target in connections:
                    helper = program_config[target]["helper"]
                    printTableRules(helper, connections[target])
                
                else:
                    print(f"Unknown show target: '{target}'")
                    
            elif cmd in ["exit", "quit", "q"]:
                print("Shutting down controller.")
                # Cleanly shutdown all switch connections, this can cause problems
                ShutdownAllSwitchConnections()
                break
            
            else:
                print(f"Unknown command: {user_input}")

        print("out of the loop")

    except KeyboardInterrupt:
        print("Shutting down.")
        # Cleanly shutdown all switch connections, this can cause problems
        ShutdownAllSwitchConnections()
    except grpc.RpcError as e:
        printGrpcError(e) # Handle any gRPC errors that might occur


# Entry point for the script
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--config', type=str, action="store", required=True,
                        help='json file with the switches configuration')
    parser.add_argument('--programs', type=str, action="store", required=True,
                        help='json file with the P4 programs configuration')
    parser.add_argument('--tunnels', type=str, action="store", required=True,
                        help='json file with the tunnels configuration')
    parser.add_argument('--clone', type=str, action="store", required=True,
                        help='json file with the mc and clone sessions configuration')

    args = parser.parse_args()

    # Validate the provided paths for p4infos and JSONs files
    if not os.path.exists(args.config):
        parser.print_help()
        print("\nconfig file not found:")
        parser.exit(1)
    if not os.path.exists(args.programs):
        parser.print_help()
        print("\nprograms file not found:")
        parser.exit(1)
    if not os.path.exists(args.tunnels):
        parser.print_help()
        print("\ntunnels file not found:")
        parser.exit(1)
    if not os.path.exists(args.clone):
        parser.print_help()
        print("\nclone file not found:")
        parser.exit(1)
    
    main(args.config, args.programs, args.tunnels, args.clone)