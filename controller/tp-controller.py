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

# List of broadcast replicas the clone engine for the multicast group
# with egress port and the number of copies "instance"
broadcastReplicas = [
    {'egress_port': 1, 'instance': 1},
    {'egress_port': 2, 'instance': 1},
    {'egress_port': 3, 'instance': 1},
    {'egress_port': 4, 'instance': 1}
]

# List of CPU replicas, clone engine for sending packets to CPU (port 510)
cpuReplicas = [
     {'egress_port': 510, 'instance': 1}
]

# Define session IDs for multicast and CPU sessions (clone engines)
mcSessionId = 1
cpuSessionId = 100

# Custom function to decode Mac Addresses from a bytes object
def myDecodeMac(mac):
    return ':'.join(f'{byte:02x}' for byte in mac)

def _to_hex(v: int) -> str:
    # Format as 0x… using lowercase, adjust width if desired
    return f"0x{v:x}"

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
    current_action_id = sw.getDefaultAction(table_id)

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
def writeMcGroup(p4info_helper, sw, sessionId):
    if not sw.isMulticastGroupInstalled(sessionId):
        mc_group = p4info_helper.buildMulticastGroupEntry(sessionId, broadcastReplicas)
        sw.WritePREEntry(mc_group)
        print(f"Installed Multicast Group {sessionId} on {sw.name}")

# Function to write a CPU session entry for packet cloning to the CPU port
def writeCpuSession(p4info_helper, sw, sessionId):
    if not sw.isCloneSessionInstalled(sessionId):
        clone_entry = p4info_helper.buildCloneSessionEntry(sessionId, cpuReplicas)
        sw.WritePREEntry(clone_entry)
        print(f"Installed clone session {sessionId} on {sw.name}")

# Function to create all P4Runtime connections to all the switches
# with gRPC and proto dump files for logging
def createConnectionsToSwitches(switches_config_path, state):
    print("------ Connecting to the devices... ------")

    with open(switches_config_path, 'r') as f:
        switch_configs = json.load(f)

    connections = {}
    for switch in switch_configs:
        name = switch["name"]
        connections[name] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=name,
            address=switch["address"],
            device_id=switch["device_id"],
            proto_dump_file=switch["proto_dump_file"]
        )
        state[name] = {}

    print("------ Connection successful! ------\n")
    return connections

# Function to send master arbitration update messages to all switches to establish
# this controller as master
def sendMasterAtributionMessage(connections):

    print("------ Setting Master Atribution... ------")
    for sw in connections.values():
        sw.MasterArbitrationUpdate()
    print("------ Master Atribution done! ------\n")

# Function to load the P4 program configuration from a JSON file
def loadProgramConfig(programs_config_path):
    with open(programs_config_path, 'r') as f:
        config_data = json.load(f)

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
def installP4Programs(connections, program_config):
    print("------ Installing P4 Programs... ------")

    for sw_name, sw_conn in connections.items():
        expected_helper = program_config[sw_name]["helper"] 
        json_path = program_config[sw_name]["json"]
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
def writeCloneEngines(connections, program_config):
    
    print("------ Installing MC Groups and Clone Sessions... ------")
    
    s1 = connections["s1"]
    L2_helper = program_config["s1"]["helper"]
    writeMcGroup(L2_helper, s1, mcSessionId)
    writeCpuSession(L2_helper, s1, cpuSessionId)
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

    print("------ Static rules done! ------\n")
    
# Function to compare the current rule with the expected rule and write it if they differ
def compareAndWriteRules(helper, switch, table, match, expected_action, expected_params, state):
    # Get current state for the switch and table
    current_state = state[switch.name][table]
    
    # Check if the rule already exists
    match_str = str(match)
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

# Function to dynamicly change the tunnel selection rules according to traffic metrics
def changeTunnelRules(L3M_helper, L3MF_helper, r1, r4):
    # Define table and action names
    table = "MyIngress.tunnelLookup"
    action = "MyIngress.addMSLP"
    match = "meta.tunnel"
    l = "labels"
    tunnel_counter = "MyIngress.tunnel_counter"
    
    current_state = 0  

    while True:
        # Read counters for tunnel traffic at r1
        count_r1_up   = read_counter(L3M_helper, r1, tunnel_counter, 2) # port 2 is up
        count_r1_down = read_counter(L3M_helper, r1, tunnel_counter, 3) # port 3 is down

        # Read counters for tunnel traffic at r4
        count_r4_up   = read_counter(L3MF_helper, r4, tunnel_counter, 3) # port 3 is up
        count_r4_down = read_counter(L3MF_helper, r4, tunnel_counter, 2) # port 2 is down

        # Print individual counter values for r1 and r4
        print(f"r1 Tunnel UP: {count_r1_up} pacotes, r1 Tunnel DOWN: {count_r1_down} pacotes")
        print(f"r4 Tunnel UP: {count_r4_up} pacotes, r4 Tunnel DOWN: {count_r4_down} pacotes")

        # Calculate total traffic for each tunnel
        total_tunnel_up = count_r1_up + count_r4_up
        total_tunnel_down = count_r1_down + count_r4_down

        # Print the total packet count for each tunnel
        print(f"Tunnel UP total: {total_tunnel_up} packets, Tunnel DOWN total: {total_tunnel_down} packets")

        # Decide whether to change the preferred tunnel based on thresholds
        if abs(total_tunnel_up - total_tunnel_down) > 50: 
            if current_state == 0:
                # Switch to labels state 1
                writeTableEntry(L3M_helper,  r1, table, {match: 0x1}, action, {l: 0x1020202030204010}, modify=True)
                writeTableEntry(L3M_helper,  r1, table, {match: 0x0}, action, {l: 0x1030602050204010}, modify=True)
                writeTableEntry(L3MF_helper, r4, table, {match: 0x1}, action, {l: 0x4030301020101010}, modify=True)
                writeTableEntry(L3MF_helper, r4, table, {match: 0x0}, action, {l: 0x4020501060101010}, modify=True)
                current_state = 1
                print("➡️ Change to labels state 1")
            else:
                # Switch to labels state 0
                writeTableEntry(L3M_helper,  r1, table, {match: 0x0}, action, {l: 0x1020202030204010}, modify=True)
                writeTableEntry(L3M_helper,  r1, table, {match: 0x1}, action, {l: 0x1030602050204010}, modify=True)
                writeTableEntry(L3MF_helper, r4, table, {match: 0x0}, action, {l: 0x4030301020101010}, modify=True)
                writeTableEntry(L3MF_helper, r4, table, {match: 0x1}, action, {l: 0x4020501060101010}, modify=True)
                current_state = 0
                print("⬅️ Change to labels state 0")
        else:
            print("No change necessary")

        # Print the current labels state
        print(f"Current labels state: {current_state}\n")
        
        # Wait before the next iteration
        sleep(30)

def read_counter(p4info_helper, switch, counter_name, index):
    try:
        counter_id = p4info_helper.get_counters_id(counter_name)
        for response in switch.ReadCounters(counter_id, index):
            for entity in response.entities:
                if entity.HasField("counter_entry"):
                    counter_entry = entity.counter_entry
                    return counter_entry.data.packet_count
        return 0
    except Exception as e:
        print(f"Error reading counter {counter_name} [{index}]: {e}")
        return 0

# Function to read the current table rules from the switch and store the known values
def readTableRules(connections, program_config, state):
    
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
                    params = {
                        p.param_id: p.value
                        for p in entry.action.action.params
                    }
                    key = json.dumps({"hdr.ipv4.dstAddr": list(ip)})
                    state[sw_name][table][key] = {
                        "action": action,
                        "params": params
                    }

                # 2. Label Lookup → store label as hex string
                elif table == "MyIngress.labelLookup":
                    lbl = decodeNum(helper.get_match_field_value(entry.match[0]))
                    params = {
                        p.param_id: p.value
                        for p in entry.action.action.params
                    }
                    key = json.dumps({ "hdr.labels[0].label": _to_hex(lbl) })
                    state[sw_name][table][key] = {
                        "action": action,
                        "params": params
                    }

                # 3. Internal MAC Lookup
                elif table == "MyIngress.internalMacLookup":
                    mac_key = myDecodeMac(helper.get_match_field_value(entry.match[0]))
                    imac = myDecodeMac(entry.action.action.params[0].value)
                    action = helper.get_actions_name(entry.action.action.action_id)
                    state[sw_name][table][str(mac_key)] = {
                        "action": action,
                        "params": {"mac": imac}
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
                    action = helper.get_actions_name(entry.action.action.action_id)
                    state[sw_name][table][str((ingress, egress))] = {
                        "action": action,
                        "params": {}
                    }

                # 6. Allowed TCP Ports + 7. Allowed UDP Ports
                elif table == "MyIngress.allowedPortsTCP" or table == "MyIngress.allowedPortsUDP":
                    port = decodeNum(helper.get_match_field_value(entry.match[0]))
                    action = helper.get_actions_name(entry.action.action.action_id)
                    state[sw_name][table][str(port)] = {
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
    
def printControllerState(state):
    print("---------- Controller State ----------")
    pprint(state)
    print()



# Main function that initializes P4Runtime connections and performs setup
def main(switches_config_path, switch_programs_path, ):

    # Variables to store the state of the tables
    state = {}

    try:
        # Create P4Runtime connections to the switches
        connections = createConnectionsToSwitches(switches_config_path, state)
        
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        sendMasterAtributionMessage(connections)
        
        # Load config files for the p4 programs
        program_config = loadProgramConfig(switch_programs_path)

        # Install the P4 programs on the switches if not yet installed
        installP4Programs(connections, program_config)

        # Write clone engines and their sessionId, if not written yet
        writeCloneEngines(connections, program_config)

        # Write default actions, if not written yet
        writeDefaultActions(connections, program_config, state)

        # Read all entries of all tables of all routers and populate state variables
        readTableRules(connections, program_config, state)

        # Check the state of the controller
        printControllerState(state)

        # Write static rules to the L3 Switches, if not written yet
        writeStaticRules(connections, program_config, state)

        # Show all rules set in the tables
        for sw_name, switch in connections.items():
            # Note: s1 is empty before any traffic
            printTableRules(program_config[sw_name]["helper"], switch) 


        r1 = connections["r1"]
        r1_helper = program_config["r1"]["helper"]
        r4 = connections["r4"]
        r4_helper = program_config["r4"]["helper"]
        # Thread to handle load balancing between the tunnels
        t = threading.Thread(target=changeTunnelRules, args=(r1_helper, r4_helper, r1, r4,), daemon=True)
        t.start()


        s1 = connections["s1"]
        s1_helper = program_config["s1"]["helper"]
        for response in s1.stream_msg_resp:
            # Check if the response contains a packet-in message
            if response.packet:
                #print("Received packet-in message:")
                packet = Ether(raw(response.packet.payload))
                if packet.type == 0x1234:
                    cpu_header = CpuHeader(bytes(packet.load))
                    new_mac = cpu_header.macAddr  # e.g. "aa:bb:cc:dd:ee:ff"
                    match_key = json.dumps({"hdr.eth.srcAddr": new_mac})
                    #print("mac: %012X ingress_port: %s " % (cpu_header.macAddr, cpu_header.ingressPort))
                    
                    sw_state = state.setdefault("s1", {}).setdefault("MyIngress.sMacLookup", {})
                    if match_key not in sw_state:
                        writeMacSrcLookUp(s1_helper, s1, new_mac)
                        writeMacDstLookUp(s1_helper, s1, new_mac, cpu_header.ingressPort)
                        sw_state[match_key] = {
                            "action": "NoAction",
                            "params": {}
                        }
                    #else:
                        #print("Rules already set")
            else:
                print(f"Received non-packet-in message: {response}")

        print("out of the loop")        

    except KeyboardInterrupt:
        print(" Shutting down.")
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

    args = parser.parse_args()

    # Validate the provided paths for p4infos and JSONs files
    if not os.path.exists(args.config):
        parser.print_help()
        print("\nconfig file not found:")
        parser.exit(1)
    if not os.path.exists(args.programs):
        parser.print_help()
        print("\programs file not found:")
        parser.exit(1)
    
    main(args.config, args.programs)