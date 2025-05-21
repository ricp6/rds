import json 

# Function to reset the packet count of a specific counter on a switch
def reset_counter(p4info_helper, sw, counter_name, idx):
    """
    Reset the packet_count of a counter at a given index to zero.
    """
    counter_id = p4info_helper.get_counters_id(counter_name)
    sw.WriteCounterEntry(counter_id, idx)
    print(f"🔄 Reset counter '{counter_name}' idx={idx} on {sw.name}")
    
# Function to write a multicast group entry to the switch
def write_mc_group(p4info_helper, sw, session_id, broadcast_replicas):
    if not sw.isMulticastGroupInstalled(session_id):
        mc_group = p4info_helper.buildMulticastGroupEntry(session_id, broadcast_replicas)
        sw.WritePREEntry(mc_group)
        print(f"Installed Multicast Group {session_id} on {sw.name}")

# Function to write a CPU session entry for packet cloning to the CPU port
def write_cpu_session(p4info_helper, sw, session_id, cpu_replicas):
    if not sw.isCloneSessionInstalled(session_id):
        clone_entry = p4info_helper.buildCloneSessionEntry(session_id, cpu_replicas)
        sw.WritePREEntry(clone_entry)
        print(f"Installed clone session {session_id} on {sw.name}")

# Function to install a default action entry into a table
def write_default_table_action(p4info_helper, sw, table, intended_action):
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
        
# Function to compare the current rule with the expected rule and write it if they differ
def compare_and_write_rule(helper, switch, table, match, expected_action, expected_params, state):
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
            write_table_entry(helper, switch, table, match, expected_action, expected_params, modify=True)
            # Update the state
            current_state[match_str] = {
                "action": expected_action,
                "params": expected_params
            }
    else:
        # If the rule does not exist, write it
        print(f"Adding rule to {switch.name} for table {table}")
        write_table_entry(helper, switch, table, match, expected_action, expected_params)
        # Update the state
        current_state[match_str] = {
            "action": expected_action,
            "params": expected_params
        }
        
# Function to write an entry to a table of a switch
def write_table_entry(helper, sw, table, match, action, params, dryrun=False, modify=False):
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
    
# Function to write a MAC destination lookup entry to the table
def write_mac_dst_lookup(p4info_helper, sw, mac, port):
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
def write_mac_src_lookup(p4info_helper, sw, mac):
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
    

# Custom function to format hex strings        
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

# p4runtime_pb2 está mal. Ver como corrigir
# Writes a value to a specific index of a register on the switch.
def write_register(helper, switch, register_name, index, value):
    try:
        register_id = helper.get_registers_id(register_name)
        if register_id is None:
            raise ValueError(f"Register '{register_name}' not found")

        reg_entry = p4runtime_pb2.RegisterEntry()
        reg_entry.register_id = register_id
        reg_entry.index.index = index
        reg_entry.data.bitstring = bytes([value])

        switch.WriteRegisterEntry(reg_entry)
    except Exception as e:
        raise Exception(f"Failed to write to register '{register_name}' at index {index}: {e}")
