#!/usr/bin/env python3

import argparse
import os
import sys
import json
import threading
from time import sleep
from pprint import pprint
import grpc
from scapy.all import Ether, Packet, BitField, raw

# import our utils functions
import reading_utils as rd
import writing_utils as wr

# Import P4Runtime lib from utils dir
# This approach is used to import P4Runtime library when it's located in a different directory.
# Probably there's a better way of doing this.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),'../utils/'))

# Import the necessary P4Runtime libraries
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections #, connections

# Define a custom CPU header that encapsules additional information sent by the data plane
class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingressPort', 0, 16)]


###############   LOAD JSONS   ###############
    
# Function to load the configuration files for switches, programs, tunnels, and clones
def load_config_files(switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path):
    switches_config = json.load(open(switches_config_path))
    program_config = load_program_config(switch_programs_path)
    tunnels_config = json.load(open(tunnels_config_path))
    clone_config = json.load(open(clone_config_path))
    return switches_config, program_config, tunnels_config, clone_config

# Function to load the P4 program configuration from a JSON file
def load_program_config(switch_programs_path):    
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


###############   SWITCHES FUNCTIONS   ###############

# Function to perform the initial setup of the switches
# including installing P4 programs, writing clone engines, default actions, and static rules
def setup_switches(connections, program_config, clone_config, clones, state, reset=False):
    
    install_p4_programs(connections, program_config, reset)
    write_clone_engines(connections, program_config, clone_config, clones, state)
    write_default_actions(connections, program_config, state)
    read_tables_rules(connections, program_config, state)
    write_static_rules(connections, program_config, state)

# Function to create all P4Runtime connections to all the switches
# with gRPC and proto dump files for logging
def create_connections_to_switches(switches_config, connections, state):
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
        connections[name].MasterArbitrationUpdate()
        state[name] = {}

    print("------ Connection successful! ------\n")
    
# Function to create a P4Runtime connection to one switch with gRPC and proto dump files for logging
def create_connection_to_switch(target, switches_config, connections, state):
    print("------ Connecting to the device... ------")

    for switch in switches_config:
        if target == switch["name"]:
            connections[target] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=target,
                address=switch["address"],
                device_id=switch["device_id"],
                proto_dump_file=switch["proto_dump_file"]
            )
            connections[target].MasterArbitrationUpdate()
            state[target] = {}
            break

    print("------ Connection successful! ------\n")

# Function to install the P4 programs on all switches
def install_p4_programs(connections, program_config, reset=False):
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
def write_clone_engines(connections, program_config, clone_config, clones, state):
    print("------ Installing MC Groups and Clone Sessions... ------")

    for sw_name, sw in connections.items():
        if sw_name in clone_config.keys():
            cfg = clone_config[sw_name]
            helper = program_config[sw_name]["helper"]

            if "mcSessionId" in cfg:
                mc_id  = cfg["mcSessionId"]
                mc_replicas  = cfg["broadcastReplicas"]
                wr.write_mc_group(helper, sw, mc_id, mc_replicas)
            
            if "cpuSessionId" in cfg:
                cpu_id = cfg["cpuSessionId"]
                cpu_replicas = cfg["cpuReplicas"]
                wr.write_cpu_session(helper, sw, cpu_id, cpu_replicas)

                clones.setdefault(sw_name, {})
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
                
# Function to listen for packet-in messages on a single switch            
def _listen_single_switch(helper, sw, clones, state):
    print(f"🔍 Listening for packet-ins on {sw.name}")
    
    try:
        for response in sw.stream_msg_resp:
            if clones[sw.name]["stop_event"].is_set():
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
                        wr.write_mac_src_lookup(helper, sw, new_mac)
                        wr.write_mac_dst_lookup(helper, sw, new_mac, cpu_header.ingressPort)
                        sw_state[match_key] = {
                            "action": "NoAction",
                            "params": {}
                        }
                    #else:
                        #print("Rules already set")
            else:
                print(f"[{sw.name}] Received non-packet-in message: {response}")
        
    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.CANCELLED:
            # expected on shudown
            print(f"[{sw.name}] packet-in stream cancelled, exiting listener.")
        else:
            print(f"[{sw.name}] unexpected gRPC error: {e}")
    finally:
        print(f"[{sw.name}] listener thread terminating.")
        
# Function to write the default actions on all tables from all switches
def write_default_actions(connections, program_config, state):
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
            wr.write_default_table_action(helper, sw, table_name, action_name)
    
    print("------ Write Default Actions done! ------\n")

# Function to read the current tables rules from the switches and store the known values
def read_tables_rules(connections, program_config, state):
    print("------ Reading Tables Rules... ------")

    for sw_name, sw in connections.items():
        helper = program_config[sw_name]["helper"]
        if not sw.HasP4ProgramInstalled():
            continue

        for response in sw.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table = helper.get_tables_name(entry.table_id)

                parser = rd.TABLE_PARSERS.get(table)
                if parser:
                    try:
                        key, action, params = parser(entry, helper)
                        state.setdefault(sw_name, {}).setdefault(table, {})[key] = {
                            "action": action,
                            "params": params
                        }
                    except Exception as e:
                        print(f"⚠️ Error parsing table {table} on {sw_name}: {e}")

    print("------ Read Tables Rules done! ------\n")
    
# Function to write the static rules in all tables from all L3 switches
def write_static_rules(connections, program_config, state):
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
                wr.compare_and_write_rule(helper, switch, table, match_dict, action, params, state)

    print("------ Write Static Rules done! ------\n")


###############   TUNNELS FUNCTIONS   ###############

# Function to setup tunnels and start the load balancing threads
def setup_tunnels(connections, program_config, tunnels_config, tunnels, state):
        
    # Initialize the tunnel state and check if any tunnels are already active
    init_tunnel_states(connections, program_config, tunnels_config, tunnels, state)
    # Thread to handle load balancing between the tunnels
    change_tunnel_rules(connections, program_config, tunnels_config, tunnels, state)
    
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
        sw_a  = tcfg["switchA"]

        # ensure the nested state
        state.setdefault(sw_a, {}).setdefault(table, {})

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
              for k,entry in state[sw_a][table].items()
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
                    wr.write_table_entry(
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
        
        tunnels.setdefault(name, {})
        tunnels[name]["state"] = found

# Function to dynamicly change the tunnel selection rules according to traffic metrics
def change_tunnel_rules(connections, program_config, tunnels_config, tunnels, state):
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
                           table, mf, cntr_name, tunnels, state):
    name   = tcfg["name"]
    idxs   = tcfg["counter_index"]
    states = tcfg["states"]

    sw_a = connections[tcfg["switchA"]]
    sw_b = connections[tcfg["switchB"]]
    h_a  = program_config[tcfg["switchA"]]["helper"]
    h_b  = program_config[tcfg["switchB"]]["helper"]

    curr_state = tunnels[name]["state"]
    print(f"📡 Starting tunnel monitor '{name}' between {sw_a.name} ⇄ {sw_b.name}")

    while not tunnels[name]["stop_event"].is_set():
        # read the counters from both switches
        up_a   = rd.read_counter(h_a, sw_a, cntr_name, idxs["A_up"])
        down_a = rd.read_counter(h_a, sw_a, cntr_name, idxs["A_down"])
        up_b   = rd.read_counter(h_b, sw_b, cntr_name, idxs["B_up"])
        down_b = rd.read_counter(h_b, sw_b, cntr_name, idxs["B_down"])

        total_up   = up_a + up_b
        total_down = down_a + down_b
        print(f"\n[{name}] up={total_up}, down={total_down}")
        # Print individual counter values for both switches
        print(f"[{sw_a.name}] up={up_a}, down={down_a}")
        print(f"[{sw_b.name}] up={up_b}, down={down_b}")

        sleep_boost = 1
        if abs(total_up - total_down) > threshold:
            # toggle state
            next_state = 1 - curr_state
            nxt = states[next_state]

            # write out new label assignments for both switches
            for sw, helper, labels in [
                (sw_a, h_a, nxt["labelsA"]),
                (sw_b, h_b, nxt["labelsB"])
            ]:
                for match_val, lbl in labels.items():
                    wr.write_table_entry(
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
            tunnels[name]["state"] = next_state
            sleep_boost = 3   # Leave more time for the changes to be effective
            print(f"[{name}] switched to state {curr_state}\n")
        else:
            print(f"[{name}] no switch needed\n")

        sleep(interval * sleep_boost)
        

###############   RESET FUNCTIONS   ###############

# Function to perform a full reset of the controller and switches
def full_reset(switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path, 
              connections, clones, tunnels, state):
    print("🔄 Performing full reset of the controller and switches...")

    # Stop all active threads and connections
    stop_tunnel_monitor_threads(tunnels)
    ShutdownAllSwitchConnections() # in the middle to help stopping clone threads
    stop_clone_engine_threads(clones)
    
    # Reload config files
    switches_config, program_config, tunnels_config, clone_config = load_config_files(
        switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path)
    
    # Setup everything from scratch
    create_connections_to_switches(switches_config, connections, state)
    setup_switches(connections, program_config, clone_config, clones, state, reset=True)
    setup_tunnels(connections, program_config, tunnels_config, tunnels, state)

    print("✅ All switches have been reset.")
    return switches_config, program_config, tunnels_config, clone_config

# Function to reset a switch by reinstalling the P4 program and resetting the state
def reset_switch(sw_name, switches_config_path, switch_programs_path, tunnels_config_path,
                clone_config_path, old_program_config, old_tunnels_config, connections, clones, tunnels, state):
    print(f"🔄 Resetting switch {sw_name}...")

    # Clean ALL tunnel rules from ALL switches
    # This is needed to ensure that the tunnel rules are in sync with the new switch rules
    clean_tunnel_rules(old_tunnels_config["table"], connections, old_program_config, tunnels, state)
    
    # Shut down the switch connection and clone session (if any)
    connections[sw_name].shutdown()
    stop_clone_engine_thread_switch(sw_name, clones)
    
    # Load config files
    switches_config, program_config, tunnels_config, clone_config = load_config_files(
        switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path)

    # Create a new connection to the switch and setup from scratch
    create_connection_to_switch(sw_name, switches_config, connections, state)
    sw_conn = {sw_name: connections[sw_name]}
    sw_program_cfg = {sw_name: program_config[sw_name]}
    setup_switches(sw_conn, sw_program_cfg, clone_config, clones, state, reset=True)
    
    # Reinstall the tunnel rules for ALL switches
    setup_tunnels(connections, program_config, tunnels_config, tunnels, state)

    print(f"✅ {sw_name} has been reset.")
    return switches_config, program_config, tunnels_config, clone_config

# Function to reset the packet count of all counters on all switches
def reset_all_counters(connections, program_config, tunnels_config):

    counter_name = tunnels_config["counter_name"]
    # Reset tunnel counters
    for tcfg in tunnels_config["tunnels"]:
        for side, role in [("switchA", "A"), ("switchB", "B")]:
            sw_name = tcfg[side]
            helper  = program_config[sw_name]["helper"]
            sw      = connections[sw_name]
            idxs    = tcfg["counter_index"]
            # Reset both up/down indices
            wr.reset_counter(helper, sw, counter_name, idxs[f"{role}_up"])
            wr.reset_counter(helper, sw, counter_name, idxs[f"{role}_down"])

# Function to reset all registers associated with Bloom Filters on switch r4
def reset_all_registers(connections, program_config, tunnels_config):
    print("------ Resetting All Bloom Filter Registers... ------")
    register_names = tunnels_config.get("register_names", ["bloom_filter_1", "bloom_filter_2"])
    register_size = tunnels_config.get("register_size", 4096)
    sw_name = "r4"
    if sw_name in connections:
        sw = connections[sw_name]
        helper = program_config[sw_name]["helper"]
        for register_name in register_names:
            try:
                register_id = helper.get_registers_id(register_name)
                if register_id is None:
                    print(f"Warning: Register '{register_name}' not found in {sw_name}, skipping...")
                    continue
                for index in range(register_size):
                    wr.write_register(helper, sw, register_name, index, 0)
                # Verify a sample entry
                sample_index = 0
                value = rd.read_register(helper, sw, register_name, sample_index)
                if value == 0:
                    print(f"Success: {sw_name}: Bloom Filter register '{register_name}' reset successfully.")
                else:
                    print(f"Error: {sw_name}: Bloom Filter register '{register_name}' not reset (value={value}).")
            except Exception as e:
                print(f"Error resetting register '{register_name}' on {sw_name}: {e}")
    else:
        print(f"Warning: Switch {sw_name} not found in connections.")
    print("------ Reset All Bloom Filter Registers done! ------\n")
            
            
###############   RESET UTILS   ###############

# Function to clean all tunnel rules from a switch's tunnel table using the controller's state
def clean_tunnel_rules(table_name, connections, program_config, tunnels, state):

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
                
# Function to stop the clone engine thread of one switch    
def stop_clone_engine_thread_switch(sw_name, clones):    

    if sw_name in clones:
        clones[sw_name]["stop_event"].set()
        clones[sw_name]["thread"].join()
        del clones[sw_name]
    
# Function to stop the threads of the clone engines and clean them up
def stop_clone_engine_threads(clones):
        
    # Stop all packet-in listener threads
    for sw_name, clone in clones.items():
        clone["stop_event"].set()
        clone["thread"].join()
        print(f"Stopped packet-in listener for {sw_name}")
    clones.clear()

def stop_tunnel_monitor_threads(tunnels):
    
    # Stop all tunnel monitor threads
    for tname, tinfo in tunnels.items():
        tinfo["stop_event"].set()
        tinfo["thread"].join()
        print(f"Stopped tunnel monitor for {tname}")
    tunnels.clear()


###############   USER INPUT HANDLERS   ###############

# Function to handle the reset command logic
def handle_reset(target, switches_config_path, switch_programs_path, tunnels_config_path, 
            clone_config_path, switches_config, program_config, tunnels_config, clone_config,
            connections, clones, tunnels, state):
    if target == "all":
        # Perform a full reset of the controller and switches
        switches_config, program_config, tunnels_config, clone_config = full_reset(
            switches_config_path, switch_programs_path, tunnels_config_path, 
            clone_config_path, connections, clones, tunnels, state)
    
    elif target == "tunnels":
        # Clean tunnel rules from all switches
        clean_tunnel_rules(tunnels_config["table"], connections,
                            program_config, tunnels, state)
        # Setup the tunnels and start the load balancing threads
        setup_tunnels(connections, program_config, tunnels_config, 
                        tunnels, state)
        
    elif target == "counters":
        # Reset all counters on all switches
        reset_all_counters(connections, program_config, tunnels_config)

    elif target == "BloomFilters":
        # Reset all counters on all switches
        reset_all_registers(connections, program_config, tunnels_config)
        
    elif target in connections:
        # Reset the specified switch
        switches_config, program_config, tunnels_config, clone_config = reset_switch(
            target, switches_config_path, switch_programs_path, tunnels_config_path, 
            clone_config_path, program_config, tunnels_config, connections, clones, tunnels, state)

    else:
        print(f"Unknown target for reset: '{target}'")
        
    return switches_config, program_config, tunnels_config, clone_config

# Function to handle the show command logic     
def handle_show(target, connections, program_config, state):
    if target == "state":
        print("---------- Controller State ----------")
        pprint(state)
        print()
    
    elif target in connections:
        helper = program_config[target]["helper"]
        rd.print_table_rules(helper, connections[target])
    
    else:
        print(f"Unknown show target: '{target}'")


###############   SHUTDOWN   ###############

def graceful_shutdown(clones, tunnels):
    print("Shutting down...")

    # Shut down all gRPC switch connections to break threads loops
    ShutdownAllSwitchConnections()

    stop_clone_engine_threads(clones)
    stop_tunnel_monitor_threads(tunnels)
    print("Controller exited cleanly.")
    

    
###############   MAIN EXECUTION   ###############

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
        switches_config, program_config, tunnels_config, clone_config = load_config_files(
            switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path)

        # Create P4Runtime connections to the switches
        create_connections_to_switches(switches_config, connections, state)

        # Do the initial setup of the switches
        setup_switches(connections, program_config, clone_config, clones, state)

        # Setup the tunnels and start the load balancing threads
        setup_tunnels(connections, program_config, tunnels_config, tunnels, state)

        # Loop to handle user input for resetting switches and showing state
        while True:
            user_input = input("\n>>> \n").strip()
            parts = user_input.split()
            cmd = parts[0].lower()
            
            if cmd == "reset" and len(parts) == 2:
                switches_config, program_config, tunnels_config, clone_config = handle_reset(
                        parts[1], switches_config_path, switch_programs_path,
                        tunnels_config_path, clone_config_path, switches_config,
                        program_config, tunnels_config, clone_config,
                        connections, clones, tunnels, state)

            elif cmd == "show" and len(parts) == 2:
                handle_show(parts[1], connections, program_config, state)
                                    
            elif cmd in ["exit", "quit", "q"]:
                print("Exiting by input...")
                graceful_shutdown(clones, tunnels)
                break
            
            else:
                print(f"Unknown command: {user_input}")

    except KeyboardInterrupt:
        print("Controller interrupted by user.")
        graceful_shutdown(clones, tunnels)

    except grpc.RpcError as e:
        print("gRPC Error:", e.details(), end=' ')
        status_code = e.code()
        print("(%s)" % status_code.name, end=' ')
        traceback = sys.exc_info()[2]
        print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))


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