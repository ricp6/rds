#!/usr/bin/env python3

import argparse
import os
import sys
import threading
from time import sleep
from scapy.all import Ether, Packet, BitField, raw

import grpc
import json

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
    print("Installed rule for %s on %s" % (table, sw.name))

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
def createConnectionsToSwitches(switches_config_path):
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
        json_path = entry['json_path']
        helper_path = entry['p4info_path']

        helper = p4runtime_lib.helper.P4InfoHelper(helper_path)
        program_config[sw_name] = (helper, json_path)

    return program_config

# Function to install the P4 programs on all switches
def installP4Programs(connections, program_config):
    print("------ Installing P4 Programs... ------")

    for sw_name, sw_conn in connections.items():
        expected_helper, json_path = program_config[sw_name]
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
    L2_helper, _ = program_config["s1"]  # Only L2 program needs to be handled here
    writeMcGroup(L2_helper, s1, mcSessionId)
    writeCpuSession(L2_helper, s1, cpuSessionId)
    print("------ MC Groups and Clone Sessions done! ------\n")
    
# Function to write the default actions on all tables from all switches
def writeDefaultActions(connections, program_config):
    print("------ Writing Default Actions... ------")
    
    for sw_name, sw in connections.items():
        p4info_helper, _ = program_config[sw_name]
        try:
            with open(f"configs/default_actions/{sw_name}.json") as f:
                actions = json.load(f)
        except FileNotFoundError:
            print(f"No default actions config for {sw_name}, skipping...")
            continue

        for table_name, action_name in actions.items():
            writeDefaultTableAction(p4info_helper, sw, table_name, action_name)
    
    print("------ Write Default Actions done! ------\n")

# Function to write the static rules in all tables from all L3 switches
def writeStaticRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6, 
                     ips, labels, iMacs, tLabels, dirs, tcpPorts, udpPorts):

    print("------ Writing Static Rules... ------")
    writeTunnelSelectionRules(L3M_helper, L3MF_helper, r1, r4, tLabels)
    writeIPv4ForwardingRules(L3M_helper, L3MF_helper, r1, r4, ips)
    writeLabelForwardingRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6, labels)
    writeMacRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6, iMacs)
    writeFirewallRules(L3MF_helper, r4, dirs, tcpPorts, udpPorts)
    print("------ Static rules done! ------\n")

# Function to write the static tunnel selection rules
def writeTunnelSelectionRules(L3M_helper, L3MF_helper, r1, r4, tLabels):
    table = "MyIngress.tunnelLookup"
    action = "MyIngress.addMSLP"
    match = "meta.tunnel"
    l = "labels"
    
    if 0x1020202030204010 not in tLabels:
        writeTableEntry(L3M_helper,  r1, table, {match: 0}, action, {l: 0x1020202030204010})
        tLabels.append(0x1020202030204010)
    if 0x1030602050204010 not in tLabels:
        writeTableEntry(L3M_helper,  r1, table, {match: 1}, action, {l: 0x1030602050204010})
        tLabels.append(0x1030602050204010)
    if 0x4030301020101010 not in tLabels:
        writeTableEntry(L3MF_helper, r4, table, {match: 0}, action, {l: 0x4030301020101010})
        tLabels.append(0x4030301020101010)
    if 0x4020501060101010 not in tLabels:
        writeTableEntry(L3MF_helper, r4, table, {match: 1}, action, {l: 0x4020501060101010})
        tLabels.append(0x4020501060101010)

# Function to write the static ipv4 forwarding rules
def writeIPv4ForwardingRules(L3M_helper, L3MF_helper, r1, r4, ips):
    table = "MyIngress.ipv4Lpm"
    action = "MyIngress.forward"
    match = "hdr.ipv4.dstAddr"
    port = "egressPort"
    mac = "nextHopMac"

    if ("10.0.1.1", 32) not in ips:
        writeTableEntry(L3M_helper,  r1, table, {match: ("10.0.1.1", 32)}, action, {port: 1, mac: "aa:00:00:00:00:01"})
        ips.append(("10.0.1.1", 32))
    if ("10.0.1.2", 32) not in ips:
        writeTableEntry(L3M_helper,  r1, table, {match: ("10.0.1.2", 32)}, action, {port: 1, mac: "aa:00:00:00:00:02"})
        ips.append(("10.0.1.2", 32))
    if ("10.0.1.3", 32) not in ips:
        writeTableEntry(L3M_helper,  r1, table, {match: ("10.0.1.3", 32)}, action, {port: 1, mac: "aa:00:00:00:00:03"})
        ips.append(("10.0.1.3", 32))
    if ("10.0.2.1", 32) not in ips:
        writeTableEntry(L3MF_helper, r4, table, {match: ("10.0.2.1", 32)}, action, {port: 1, mac: "aa:00:00:00:00:04"})
        ips.append(("10.0.2.1", 32))

# Function to write the static label forwarding rules
def writeLabelForwardingRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6, labels):
    table = "MyIngress.labelLookup"
    frwdTunnel = "MyIngress.forwardTunnel"
    removeMSLP = "MyIngress.removeMSLP"
    match = "hdr.labels[0].label"
    port = "egressPort"
    mac = "nextHopMac"

    if 0x1010 not in labels:
        writeTableEntry(L3M_helper, r1, table, {match: 0x1010}, removeMSLP, None)
        labels.append(0x1010)
    if 0x1020 not in labels:
        writeTableEntry(L3M_helper, r1, table, {match: 0x1020}, frwdTunnel, {port: 2, mac: "aa:00:00:00:02:01"})
        labels.append(0x1020)
    if 0x1030 not in labels:
        writeTableEntry(L3M_helper, r1, table, {match: 0x1030}, frwdTunnel, {port: 3, mac: "aa:00:00:00:06:01"})
        labels.append(0x1030)

    if 0x2010 not in labels:
        writeTableEntry(L3T_helper, r2, table, {match: 0x2010}, frwdTunnel, {port: 1, mac: "aa:00:00:00:01:02"})
        labels.append(0x2010)
    if 0x2020 not in labels:
        writeTableEntry(L3T_helper, r2, table, {match: 0x2020}, frwdTunnel, {port: 2, mac: "aa:00:00:00:03:01"})
        labels.append(0x2020)

    if 0x3010 not in labels:
        writeTableEntry(L3T_helper, r3, table, {match: 0x3010}, frwdTunnel, {port: 1, mac: "aa:00:00:00:02:02"})
        labels.append(0x3010)
    if 0x3020 not in labels:
        writeTableEntry(L3T_helper, r3, table, {match: 0x3020}, frwdTunnel, {port: 2, mac: "aa:00:00:00:04:03"})
        labels.append(0x3020)

    if 0x4010 not in labels:
        writeTableEntry(L3MF_helper, r4, table, {match: 0x4010}, removeMSLP, None)
        labels.append(0x4010)
    if 0x4020 not in labels:
        writeTableEntry(L3MF_helper, r4, table, {match: 0x4020}, frwdTunnel, {port: 2, mac: "aa:00:00:00:05:02"})
        labels.append(0x4020)
    if 0x4030 not in labels:
        writeTableEntry(L3MF_helper, r4, table, {match: 0x4030}, frwdTunnel, {port: 3, mac: "aa:00:00:00:03:02"})
        labels.append(0x4030)

    if 0x5010 not in labels:
        writeTableEntry(L3T_helper, r5, table, {match: 0x5010}, frwdTunnel, {port: 1, mac: "aa:00:00:00:06:02"})
        labels.append(0x5010)
    if 0x5020 not in labels:
        writeTableEntry(L3T_helper, r5, table, {match: 0x5020}, frwdTunnel, {port: 2, mac: "aa:00:00:00:04:02"})
        labels.append(0x5020)

    if 0x6010 not in labels:
        writeTableEntry(L3T_helper, r6, table, {match: 0x6010}, frwdTunnel, {port: 1, mac: "aa:00:00:00:01:03"})
        labels.append(0x6010)
    if 0x6020 not in labels:
        writeTableEntry(L3T_helper, r6, table, {match: 0x6020}, frwdTunnel, {port: 2, mac: "aa:00:00:00:05:01"})
        labels.append(0x6020)

# Function to write the static internal macs rules
def writeMacRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6, iMacs):
    table = "MyIngress.internalMacLookup"
    action = "MyIngress.rewriteMacs"
    match = "standard_metadata.egress_spec"
    mac = "srcMac"

    if "aa:00:00:00:01:01" not in iMacs:
        writeTableEntry(L3M_helper, r1, table, {match: 1}, action, {mac: "aa:00:00:00:01:01"})
        iMacs.append("aa:00:00:00:01:01")
    if "aa:00:00:00:01:02" not in iMacs:
        writeTableEntry(L3M_helper, r1, table, {match: 2}, action, {mac: "aa:00:00:00:01:02"})
        iMacs.append("aa:00:00:00:01:02")
    if "aa:00:00:00:01:03" not in iMacs:
        writeTableEntry(L3M_helper, r1, table, {match: 3}, action, {mac: "aa:00:00:00:01:03"})
        iMacs.append("aa:00:00:00:01:03")

    if "aa:00:00:00:02:01" not in iMacs:
        writeTableEntry(L3T_helper, r2, table, {match: 1}, action, {mac: "aa:00:00:00:02:01"})
        iMacs.append("aa:00:00:00:02:01")
    if "aa:00:00:00:02:02" not in iMacs:
        writeTableEntry(L3T_helper, r2, table, {match: 2}, action, {mac: "aa:00:00:00:02:02"})
        iMacs.append("aa:00:00:00:02:02")

    if "aa:00:00:00:03:01" not in iMacs:
        writeTableEntry(L3T_helper, r3, table, {match: 1}, action, {mac: "aa:00:00:00:03:01"})
        iMacs.append("aa:00:00:00:03:01")
    if "aa:00:00:00:03:02" not in iMacs:
        writeTableEntry(L3T_helper, r3, table, {match: 2}, action, {mac: "aa:00:00:00:03:02"})
        iMacs.append("aa:00:00:00:03:02")

    if "aa:00:00:00:04:01" not in iMacs:
        writeTableEntry(L3MF_helper,r4, table, {match: 1}, action, {mac: "aa:00:00:00:04:01"})
        iMacs.append("aa:00:00:00:04:01")
    if "aa:00:00:00:04:02" not in iMacs:
        writeTableEntry(L3MF_helper,r4, table, {match: 2}, action, {mac: "aa:00:00:00:04:02"})
        iMacs.append("aa:00:00:00:04:02")
    if "aa:00:00:00:04:03" not in iMacs:
        writeTableEntry(L3MF_helper,r4, table, {match: 3}, action, {mac: "aa:00:00:00:04:03"})
        iMacs.append("aa:00:00:00:04:03")
        
    if "aa:00:00:00:05:01" not in iMacs:
        writeTableEntry(L3T_helper, r5, table, {match: 1}, action, {mac: "aa:00:00:00:05:01"})
        iMacs.append("aa:00:00:00:05:01")
    if "aa:00:00:00:05:02" not in iMacs:
        writeTableEntry(L3T_helper, r5, table, {match: 2}, action, {mac: "aa:00:00:00:05:02"})
        iMacs.append("aa:00:00:00:05:02")
        
    if "aa:00:00:00:06:01" not in iMacs:
        writeTableEntry(L3T_helper, r6, table, {match: 1}, action, {mac: "aa:00:00:00:06:01"})
        iMacs.append("aa:00:00:00:06:01")
    if "aa:00:00:00:06:02" not in iMacs:
        writeTableEntry(L3T_helper, r6, table, {match: 2}, action, {mac: "aa:00:00:00:06:02"})
        iMacs.append("aa:00:00:00:06:02")

# Function to write the static firewall rules
def writeFirewallRules(L3MF_helper, r4, dirs, tcpPorts, udpPorts):
    dirTable = "MyIngress.checkDirection"
    tcpTable = "MyIngress.allowedPortsTCP"
    udpTable = "MyIngress.allowedPortsUDP"
    action = "MyIngress.setDirection"
    matchIngress = "meta.ingress_port"
    matchEgress = "standard_metadata.egress_spec"
    matchTcp = "hdr.tcp.dstPort"
    matchUdp = "hdr.udp.dstPort"
    d = "dir"

    if (1,2) not in dirs:
        writeTableEntry(L3MF_helper, r4, dirTable, {matchIngress: 1, matchEgress: 2}, action, {d: 0})
        dirs.append((1,2))
    if (1,3) not in dirs:
        writeTableEntry(L3MF_helper, r4, dirTable, {matchIngress: 1, matchEgress: 3}, action, {d: 0})
        dirs.append((1,3))
    if (2,1) not in dirs:
        writeTableEntry(L3MF_helper, r4, dirTable, {matchIngress: 2, matchEgress: 1}, action, {d: 1})
        dirs.append((2,1))
    if (2,3) not in dirs:
        writeTableEntry(L3MF_helper, r4, dirTable, {matchIngress: 2, matchEgress: 3}, action, {d: 0})
        dirs.append((2,3))
    if (3,1) not in dirs:
        writeTableEntry(L3MF_helper, r4, dirTable, {matchIngress: 3, matchEgress: 1}, action, {d: 1})
        dirs.append((3,1))
    if (3,2) not in dirs:
        writeTableEntry(L3MF_helper, r4, dirTable, {matchIngress: 3, matchEgress: 2}, action, {d: 0})
        dirs.append((3,2))

    if 81 not in tcpPorts:
        writeTableEntry(L3MF_helper, r4, tcpTable, {matchTcp: 81}, "NoAction", None)
        tcpPorts.append(81)
    if 53 not in udpPorts:
        writeTableEntry(L3MF_helper, r4, udpTable, {matchUdp: 53}, "NoAction", None)
        udpPorts.append(53)

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
        sleep(7)


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
def readTableRules(connections, program_config):
    for sw_name, sw in connections.items():
        helper, _ = program_config[sw_name]
        if sw.HasP4ProgramInstalled():

            for response in sw.ReadTableEntries():
                for entity in response.entities:
                    entry = entity.table_entry
                    table_name = helper.get_tables_name(entry.table_id)

                    # Initialize state for the switch if not already done
                    if sw_name not in state:
                        state[sw_name] = {}

                    if table_name not in state[sw_name]:
                        state[sw_name][table_name] = {}

                    # Now handle specific table and entry cases
                    if table_name == "MyIngress.ipv4Lpm":
                        enc_ip = helper.get_match_field_value(entry.match[0])
                        dec_ip = decodeIPv4(enc_ip[0])
                        mask = enc_ip[1]
                        ip = (dec_ip, mask)
                        state[sw_name][table_name][str(ip)] = {
                            "action": "MyIngress.forward",  # Example action
                            "params": {"port": 80}  # Example parameters
                        }
                    
                    elif table_name == "MyIngress.labelLookup":
                        label = decodeNum(helper.get_match_field_value(entry.match[0]))
                        state[sw_name][table_name][str(label)] = {
                            "action": "MyIngress.drop",
                            "params": {}
                        }

                    elif table_name == "MyIngress.internalMacLookup":
                        imac = myDecodeMac(entry.action.action.params[0].value)
                        state[sw_name][table_name][str(imac)] = {
                            "action": "MyIngress.learnMac",
                            "params": {}
                        }

                    elif table_name == "MyIngress.tunnelLookup":
                        tl = decodeNum(entry.action.action.params[0].value)
                        state[sw_name][table_name][str(tl)] = {
                            "action": "MyIngress.addTunnel",
                            "params": {}
                        }

                    elif table_name == "MyIngress.checkDirection":
                        ingress = helper.get_match_field_value(entry.match[0])
                        egress = helper.get_match_field_value(entry.match[1])
                        dir = (decodeNum(ingress), decodeNum(egress))
                        state[sw_name][table_name][str(dir)] = {
                            "action": "MyIngress.setDirection",
                            "params": {}
                        }
    
# Function to read the current table rules from the switch and print them
def readSwitch(helper, s1, macList):
    """
    Reads the table entries from all tables on the switch and populates 
    the correct state variable if needed.

    :param helper: the P4Info helper
    :param s1: the switch connection
    :param mac_list: variable to store the macs known by s1
    """
    if s1.HasP4ProgramInstalled():
        for response in s1.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table_name = helper.get_tables_name(entry.table_id)

                if table_name == "MyIngress.sMacLookup":
                    mac = myDecodeMac(helper.get_match_field_value(entry.match[0]))
                    if mac not in macList:
                        macList.append(mac)

# Function to read the current table rules from the tunnel routers and store the known values
def readTunnelRouter(helper, routers, labelList, iMacList):
    """
    Reads the table entries from all tables on the switch and populates 
    the correct state variable if needed.

    :param helper: the P4Info helper
    :param routers: the switches connections
    """
    for r in routers:
        if r.HasP4ProgramInstalled():    
            for response in r.ReadTableEntries():
                for entity in response.entities:
                    entry = entity.table_entry
                    table_name = helper.get_tables_name(entry.table_id)

                    if table_name == "MyIngress.labelLookup":
                        label = decodeNum(helper.get_match_field_value(entry.match[0]))
                        if label not in labelList:
                            labelList.append(label)

                    elif table_name == "MyIngress.internalMacLookup":
                        imac = myDecodeMac(entry.action.action.params[0].value)
                        if imac not in iMacList:
                            iMacList.append(imac)

# Function to read the current table rules from the tunnel routers and store the known values
def readMslpRouter(helper, routers, ips, iMacs, labels, tLabels):
    """
    Reads the table entries from all tables on the switch and populates 
    the correct state variable if needed.

    :param helper: the P4Info helper
    :param routers: the switch connections
    """
    for r in routers:
        if r.HasP4ProgramInstalled():
            for response in r.ReadTableEntries():
                for entity in response.entities:
                    entry = entity.table_entry
                    table_name = helper.get_tables_name(entry.table_id)

                    if table_name == "MyIngress.ipv4Lpm":
                        enc_ip = helper.get_match_field_value(entry.match[0])
                        dec_ip = decodeIPv4(enc_ip[0])
                        mask = enc_ip[1]
                        ip = (dec_ip, mask)
                        if ip not in ips:
                            ips.append(ip)

                    elif table_name == "MyIngress.labelLookup":
                        label = decodeNum(helper.get_match_field_value(entry.match[0]))
                        if label not in labels:
                            labels.append(label)

                    elif table_name == "MyIngress.internalMacLookup":
                        imac = myDecodeMac(entry.action.action.params[0].value)
                        if imac not in iMacs:
                            iMacs.append(imac)

                    elif table_name == "MyIngress.tunnelLookup":
                        tl = decodeNum(entry.action.action.params[0].value)
                        if tl not in tLabels:
                            tLabels.append(tl)



def printControllerState(ips, macs, labels, iMacs, tLabels, dirs, tcpPorts, udpPorts):
    print("---------- Controller State ----------")
    print("----- IPs -----")
    print(ips)
    print("----- MACs known by L2 Switch -----")
    print(macs)
    print("----- Labels -----")
    print(labels)
    print("----- MACs known by L3 Switches -----")
    print(iMacs)
    print("----- Tunnels -----")
    print(tLabels)
    print("----- Firewall Directions -----")
    print(dirs)
    print("----- TCP Open Ports -----")
    print(tcpPorts)
    print("----- UDP Open Ports -----")
    print(udpPorts)
    print()



# Main function that initializes P4Runtime connections and performs setup
def main(p4infoL2_file_path, p4infoL3M_file_path, p4infoL3MF_file_path, p4infoL3T_file_path, 
         jsonL2_file_path, jsonL3M_file_path, jsonL3MF_file_path, jsonL3T_file_path):

    # Variables to store the state of the tables
    ips = []
    macs = []
    labels = []
    iMacs = [] 
    tLabels = []
    dirs = []
    tcpPorts = []
    udpPorts = []

    try:
        # Create P4Runtime connections to the switches
        connections = createConnectionsToSwitches('configs/switches_config.json')
        
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        sendMasterAtributionMessage(connections)
        
        # Load config files for the p4 programs
        program_config = loadProgramConfig("configs/switch_programs.json")

        # Install the P4 programs on the switches if not yet installed
        installP4Programs(connections, program_config)

        # Write clone engines and their sessionId, if not written yet
        writeCloneEngines(connections, program_config)

        # Write default actions, if not written yet
        writeDefaultActions(connections, program_config)

        # Read all entries of all tables of all routers and populate state variables
        readTableRules(L2_helper, L3M_helper, L3MF_helper, L3T_helper, s1,r1,r2,r3,r4,r5,r6,
                        ips, macs, labels, iMacs, tLabels, dirs, tcpPorts, udpPorts)

        # Check the state of the controller
        printControllerState(ips, macs, labels, iMacs, tLabels, dirs, tcpPorts, udpPorts)

        # Write static rules to the L3 Switches, if not written yet
        writeStaticRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6,
                         ips, labels, iMacs, tLabels, dirs, tcpPorts, udpPorts)

        # Show all rules set in the tables
        for switch in connections.values():
            helper, _ = program_config[switch]
            printTableRules(helper, switch) # Note: s1 is empty before any traffic

        # Thread to handle load balancing between the tunnels
        t = threading.Thread(target=changeTunnelRules, args=(L3M_helper, L3MF_helper, r1, r4,), daemon=True)
        t.start()


        s1 = connections["s1"]
        L2_helper, _ = program_config["s1"]  # Only L2 program needs to be handled here
        
        for response in s1.stream_msg_resp:
            # Check if the response contains a packet-in message
            if response.packet:
                #print("Received packet-in message:")
                packet = Ether(raw(response.packet.payload))
                if packet.type == 0x1234:
                    cpu_header = CpuHeader(bytes(packet.load))
                    #print("mac: %012X ingress_port: %s " % (cpu_header.macAddr, cpu_header.ingressPort))
                    if cpu_header.macAddr not in macs:
                        writeMacSrcLookUp(L2_helper, s1, cpu_header.macAddr)
                        writeMacDstLookUp(L2_helper, s1, cpu_header.macAddr, cpu_header.ingressPort)
                        macs.append(cpu_header.macAddr)
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
    parser.add_argument('--p4infoL2', type=str, action="store", required=True,
                        help='p4info proto in text format from p4c for L2 Switch')
    parser.add_argument('--p4infoL3M', type=str, action="store", required=True,
                        help='p4info proto in text format from p4c for L3 Switch with MSLP')
    parser.add_argument('--p4infoL3MF', type=str, action="store", required=True,
                        help='p4info proto in text format from p4c for L3 Switch with MSLP and Firewall')
    parser.add_argument('--p4infoL3T', type=str, action="store", required=True,
                        help='p4info proto in text format from p4c for L3 Switch with Tunnel')
    
    parser.add_argument('--jsonL2', type=str, action="store", required=True,
                        help='BMv2 JSON file from p4c for L2 Switch')
    parser.add_argument('--jsonL3M', type=str, action="store", required=True,
                        help='BMv2 JSON file from p4c for L3 Switch with MSLP')
    parser.add_argument('--jsonL3MF', type=str, action="store", required=True,
                        help='BMv2 JSON file from p4c for L3 Switch with MSLP and Firewall')
    parser.add_argument('--jsonL3T', type=str, action="store", required=True,
                        help='BMv2 JSON file from p4c for L3 Switch with Tunnel')

    args = parser.parse_args()

    # Validate the provided paths for p4infos and JSONs files
    if not os.path.exists(args.p4infoL2):
        parser.print_help()
        print("\np4infoL2 file not found:")
        parser.exit(1)
    if not os.path.exists(args.p4infoL3M):
        parser.print_help()
        print("\np4infoL3M file not found:")
        parser.exit(1)
    if not os.path.exists(args.p4infoL3MF):
        parser.print_help()
        print("\np4infoL3MF file not found:")
        parser.exit(1)
    if not os.path.exists(args.p4infoL3T):
        parser.print_help()
        print("\np4infoL3T file not found:")
        parser.exit(1)
    
    if not os.path.exists(args.jsonL2):
        parser.print_help()
        print("\nBMv2 JSONL2 file not found:")
        parser.exit(1)
    if not os.path.exists(args.jsonL3M):
        parser.print_help()
        print("\nBMv2 JSONL3M file not found:")
        parser.exit(1)
    if not os.path.exists(args.jsonL3MF):
        parser.print_help()
        print("\nBMv2 JSONL3MF file not found:")
        parser.exit(1)
    if not os.path.exists(args.jsonL3T):
        parser.print_help()
        print("\nBMv2 JSONL3T file not found:")
        parser.exit(1)
    
    main(args.p4infoL2, args.p4infoL3M, args.p4infoL3MF, args.p4infoL3T, 
         args.jsonL2, args.jsonL3M, args.jsonL3MF, args.jsonL3T)