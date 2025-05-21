import json, sys, os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),'../utils/'))
from p4runtime_lib.convert import decodeNum, decodeIPv4


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
    
# Function to read and print the current table rules from the switch and print them
def print_table_rules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch and prints them.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Printing tables rules from %s -----' % sw.name)
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

# Parse IPv4 LPM rule -> store match key as tuple of string/int
def parse_ipv4_lpm(entry, helper):
    enc_ip = helper.get_match_field_value(entry.match[0])
    ip = (decodeIPv4(enc_ip[0]), enc_ip[1])
    action = helper.get_actions_name(entry.action.action.action_id)
    params = {}
    if action == "MyIngress.forward":
        params = {
            "egressPort": decodeNum(entry.action.action.params[0].value),
            "nextHopMac": my_decode_mac(entry.action.action.params[1].value)
        }
    key = json.dumps({"hdr.ipv4.dstAddr": list(ip)})
    return key, action, params

# Parse Label Lookup rule -> store label as hex string
def parse_label_lookup(entry, helper):
    lbl = decodeNum(helper.get_match_field_value(entry.match[0]))
    action = helper.get_actions_name(entry.action.action.action_id)
    params = {}
    if action == "MyIngress.forwardTunnel":
        params = {
            "egressPort": decodeNum(entry.action.action.params[0].value),
            "nextHopMac": my_decode_mac(entry.action.action.params[1].value)
        }
    key = json.dumps({"hdr.labels[0].label": convert_to_hex(lbl)})
    return key, action, params

# Parse Internal MAC Lookup rule
def parse_internal_mac(entry, helper):
    port = decodeNum(helper.get_match_field_value(entry.match[0]))
    imac = my_decode_mac(entry.action.action.params[0].value)
    params = {"srcMac": imac}
    action = helper.get_actions_name(entry.action.action.action_id)
    key = json.dumps({"standard_metadata.egress_spec": port})
    return key, action, params

# Parse Tunnel Lookup rule -> store labels as hex
def parse_tunnel_lookup(entry, helper):
    tun = decodeNum(helper.get_match_field_value(entry.match[0]))
    lbl = decodeNum(entry.action.action.params[0].value)
    params = {"labels": convert_to_hex(lbl)}
    action = helper.get_actions_name(entry.action.action.action_id)
    key = json.dumps({"meta.tunnel": tun})
    return key, action, params

# Parse Check Direction rule
def parse_check_direction(entry, helper):
    ingress = decodeNum(helper.get_match_field_value(entry.match[0]))
    egress = decodeNum(helper.get_match_field_value(entry.match[1]))
    direction = decodeNum(entry.action.action.params[0].value)
    params = {"dir": direction}
    action = helper.get_actions_name(entry.action.action.action_id)
    key = json.dumps({"meta.ingress_port": ingress, "standard_metadata.egress_spec": egress})
    return key, action, params

# Parse Allowed TCP Ports rule
def parse_allowed_tcp(entry, helper):
    port = decodeNum(helper.get_match_field_value(entry.match[0]))
    action = helper.get_actions_name(entry.action.action.action_id)
    key = json.dumps({"hdr.tcp.dstPort": port})
    return key, action, {}
                                    
# Parse Allowed UDP Ports rule
def parse_allowed_udp(entry, helper):
    port = decodeNum(helper.get_match_field_value(entry.match[0]))
    action = helper.get_actions_name(entry.action.action.action_id)
    key = json.dumps({"hdr.udp.dstPort": port})
    return key, action, {}

# Parse sMacLookup rule (L2 MAC Learning)
def parse_smac_lookup(entry, helper):
    mac = my_decode_mac(helper.get_match_field_value(entry.match[0]))
    action = helper.get_actions_name(entry.action.action.action_id)
    key = str(mac)
    return key, action, {}


# Custom function to decode Mac Addresses from a bytes object
def my_decode_mac(mac):
    return ':'.join(f'{byte:02x}' for byte in mac)

# Format as 0x… using lowercase, adjust width if desired
def convert_to_hex(v: int) -> str:
    return f"0x{v:x}"


# Dictionary marking the tables existing for deparsing and the corresponding parser
TABLE_PARSERS = {
    "MyIngress.ipv4Lpm": parse_ipv4_lpm,
    "MyIngress.labelLookup": parse_label_lookup,
    "MyIngress.internalMacLookup": parse_internal_mac,
    "MyIngress.tunnelLookup": parse_tunnel_lookup,
    "MyIngress.checkDirection": parse_check_direction,
    "MyIngress.allowedPortsTCP": parse_allowed_tcp,
    "MyIngress.allowedPortsUDP": parse_allowed_udp,
    "MyIngress.sMacLookup": parse_smac_lookup
}