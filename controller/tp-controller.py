#!/usr/bin/env python3

import argparse
import os
import sys
import threading
from time import sleep
from scapy.all import Ether, Packet, BitField, raw

import grpc

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
def writeDefaultTableAction(p4info_helper, sw, table, action):
    if not sw.getDefaultAction(p4info_helper.get_tables_id(table)):
        table_entry = p4info_helper.buildTableEntry(
                table_name = table,
                default_action = True,
                action_name = action)
        sw.WriteTableEntry(table_entry)
        print("Installed default entry on %s" % sw.name)

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

# Function to instanciate the P4info helpers for all kinds of switches
def getP4Helpers(L2_fp, L3M_fp, L3MF_fp, L3T_fp):
    L2_helper   = p4runtime_lib.helper.P4InfoHelper(L2_fp)
    L3M_helper  = p4runtime_lib.helper.P4InfoHelper(L3M_fp)
    L3MF_helper = p4runtime_lib.helper.P4InfoHelper(L3MF_fp)
    L3T_helper  = p4runtime_lib.helper.P4InfoHelper(L3T_fp)
    return L2_helper, L3M_helper, L3MF_helper, L3T_helper

# Function to create all P4Runtime connections to all the switches
# with gRPC and proto dump files for logging
def createConnectionsToSwitches():

    print("------ Connecting to the devices... ------")

    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address='127.0.0.1:50051',
        device_id=1,
        proto_dump_file='logs/s1-p4runtime-request.txt') # the file need to exist
    r1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='r1',
        address='127.0.0.1:50052',
        device_id=2,
        proto_dump_file='logs/r1-p4runtime-request.txt')
    r2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='r2',
        address='127.0.0.1:50053',
        device_id=3,
        proto_dump_file='logs/r2-p4runtime-request.txt')
    r3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='r3',
        address='127.0.0.1:50054',
        device_id=4,
        proto_dump_file='logs/r3-p4runtime-request.txt')
    r4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='r4',
        address='127.0.0.1:50055',
        device_id=5,
        proto_dump_file='logs/r4-p4runtime-request.txt')
    r5 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='r5',
        address='127.0.0.1:50056',
        device_id=6,
        proto_dump_file='logs/r5-p4runtime-request.txt')
    r6 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='r6',
        address='127.0.0.1:50057',
        device_id=7,
        proto_dump_file='logs/r6-p4runtime-request.txt')
    
    print("------ Connection successful! ------\n")
    return s1,r1,r2,r3,r4,r5,r6

# Function to send master arbitration update messages to all switches to establish
# this controller as master
def sendMasterAtributionMessage(s1,r1,r2,r3,r4,r5,r6):

    print("------ Setting Master Atribution... ------")
    s1.MasterArbitrationUpdate()
    r1.MasterArbitrationUpdate()
    r2.MasterArbitrationUpdate()
    r3.MasterArbitrationUpdate()
    r4.MasterArbitrationUpdate()
    r5.MasterArbitrationUpdate()
    r6.MasterArbitrationUpdate()
    print("------ Master Atribution done! ------\n")
        
# Function to install the P4 programs on all switches
def installP4Programs(L2_helper, L3M_helper, L3MF_helper, L3T_helper, 
                      jsonL2, jsonL3M, jsonL3MF, jsonL3T,
                      s1,r1,r2,r3,r4,r5,r6):
    
    print("------ Installing P4 Programs... ------")

    if not s1.HasP4ProgramInstalled():
        s1.SetForwardingPipelineConfig(p4info=L2_helper.p4info,   bmv2_json_file_path=jsonL2)
        print("Installed P4 Program on s1")
    if not r1.HasP4ProgramInstalled():
        r1.SetForwardingPipelineConfig(p4info=L3M_helper.p4info,  bmv2_json_file_path=jsonL3M)
        print("Installed P4 Program on r1")
    if not r2.HasP4ProgramInstalled():
        r2.SetForwardingPipelineConfig(p4info=L3T_helper.p4info,  bmv2_json_file_path=jsonL3T)
        print("Installed P4 Program on r2")
    if not r3.HasP4ProgramInstalled():
        r3.SetForwardingPipelineConfig(p4info=L3T_helper.p4info,  bmv2_json_file_path=jsonL3T)
        print("Installed P4 Program on r3")
    if not r4.HasP4ProgramInstalled():
        r4.SetForwardingPipelineConfig(p4info=L3MF_helper.p4info, bmv2_json_file_path=jsonL3MF)
        print("Installed P4 Program on r4")
    if not r5.HasP4ProgramInstalled():
        r5.SetForwardingPipelineConfig(p4info=L3T_helper.p4info,  bmv2_json_file_path=jsonL3T)
        print("Installed P4 Program on r5")
    if not r6.HasP4ProgramInstalled():
        r6.SetForwardingPipelineConfig(p4info=L3T_helper.p4info,  bmv2_json_file_path=jsonL3T)
        print("Installed P4 Program on r6")
    
    print("------ P4 Programs Installation done! ------\n")
    
# Function to write the default actions on all tables from all switches
def writeDefaultActions(L2_helper, L3M_helper, L3MF_helper, L3T_helper,
                        s1,r1,r2,r3,r4,r5,r6):
    
    print("------ Writing Default Actions... ------")

    # L2 Switch
    writeDefaultTableAction(L2_helper, s1, "MyIngress.sMacLookup", "MyIngress.learnMac")
    writeDefaultTableAction(L2_helper, s1, "MyIngress.dMacLookup", "NoAction")
    # L3 MSLP Switch
    writeDefaultTableAction(L3M_helper, r1, "MyIngress.ipv4Lpm",           "NoAction")
    writeDefaultTableAction(L3M_helper, r1, "MyIngress.internalMacLookup", "MyIngress.drop")
    writeDefaultTableAction(L3M_helper, r1, "MyIngress.tunnelLookup",      "MyIngress.drop")
    writeDefaultTableAction(L3M_helper, r1, "MyIngress.labelLookup",       "MyIngress.drop")
    # L3 MSLP & Firewall Switch
    writeDefaultTableAction(L3MF_helper, r4, "MyIngress.ipv4Lpm",           "NoAction")
    writeDefaultTableAction(L3MF_helper, r4, "MyIngress.internalMacLookup", "MyIngress.drop")
    writeDefaultTableAction(L3MF_helper, r4, "MyIngress.tunnelLookup",      "MyIngress.drop")
    writeDefaultTableAction(L3MF_helper, r4, "MyIngress.labelLookup",       "MyIngress.drop")
    writeDefaultTableAction(L3MF_helper, r4, "MyIngress.checkDirection",    "NoAction")
    writeDefaultTableAction(L3MF_helper, r4, "MyIngress.allowedPortsTCP",   "NoAction")
    writeDefaultTableAction(L3MF_helper, r4, "MyIngress.allowedPortsUDP",   "NoAction")
    # L3 Tunnel Switches
    writeDefaultTableAction(L3T_helper, r2, "MyIngress.labelLookup",       "MyIngress.drop")
    writeDefaultTableAction(L3T_helper, r2, "MyIngress.internalMacLookup", "MyIngress.drop")
    writeDefaultTableAction(L3T_helper, r3, "MyIngress.labelLookup",       "MyIngress.drop")
    writeDefaultTableAction(L3T_helper, r3, "MyIngress.internalMacLookup", "MyIngress.drop")
    writeDefaultTableAction(L3T_helper, r5, "MyIngress.labelLookup",       "MyIngress.drop")
    writeDefaultTableAction(L3T_helper, r5, "MyIngress.internalMacLookup", "MyIngress.drop")
    writeDefaultTableAction(L3T_helper, r6, "MyIngress.labelLookup",       "MyIngress.drop")
    writeDefaultTableAction(L3T_helper, r6, "MyIngress.internalMacLookup", "MyIngress.drop")

    print("------ Write Default Actions done! ------\n")

# Function to write clone engines and their sessionId
def writeCloneEngines(L2_helper, L3M_helper, L3MF_helper, L3T_helper,
                      s1,r1,r2,r3,r4,r5,r6):
    
    print("------ Installing MC Groups and Clone Sessions... ------")
    
    # Multicast Groups
    writeMcGroup(L2_helper, s1, mcSessionId)
    # CPU Sessions
    writeCpuSession(L2_helper,   s1, cpuSessionId)
    writeCpuSession(L3M_helper,  r1, cpuSessionId)
    writeCpuSession(L3T_helper,  r2, cpuSessionId)
    writeCpuSession(L3T_helper,  r3, cpuSessionId)
    writeCpuSession(L3MF_helper, r4, cpuSessionId)
    writeCpuSession(L3T_helper,  r5, cpuSessionId)
    writeCpuSession(L3T_helper,  r6, cpuSessionId)

    print("------ MC Groups and Clone Sessions done! ------\n")

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
    if 0x4020501060101010 not in tLabels:
        writeTableEntry(L3MF_helper, r4, table, {match: 0}, action, {l: 0x4020501060101010})
        tLabels.append(0x4020501060101010)
    if 0x4030301020101010 not in tLabels:
        writeTableEntry(L3MF_helper, r4, table, {match: 1}, action, {l: 0x4030301020101010})
        tLabels.append(0x4030301020101010)

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
    
    preferred_tunnel = 0  

    while True:
        # Read counters for tunnel traffic at r1 (outbound traffic)
        count_r1_t0 = read_counter(L3M_helper, r1, tunnel_counter, 0)
        count_r1_t1 = read_counter(L3M_helper, r1, tunnel_counter, 1)

        # Read counters for tunnel traffic at r4 (inbound traffic)
        count_r4_t0 = read_counter(L3MF_helper, r4, tunnel_counter, 0)
        count_r4_t1 = read_counter(L3MF_helper, r4, tunnel_counter, 1)

        # Print individual counter values for r1 and r4
        print(f"r1 Tunnel 0 (saída): {count_r1_t0} pacotes, r1 Tunnel 1 (saída): {count_r1_t1} pacotes")
        print(f"r4 Tunnel 0 (entrada): {count_r4_t0} pacotes, r4 Tunnel 1 (entrada): {count_r4_t1} pacotes")

        # Calculate total traffic for each tunnel
        total_tunnel0 = count_r1_t0 + count_r4_t0
        total_tunnel1 = count_r1_t1 + count_r4_t1

        # Print the total packet count for each tunnel
        print(f"Tunnel 0 total: {total_tunnel0} packets, Tunnel 1 total: {total_tunnel1} packets")

        # Decide whether to change the preferred tunnel based on thresholds
        if abs(total_tunnel0 - total_tunnel1) > 100: 
            if preferred_tunnel != 1:
                preferred_tunnel = 1
                # Switch to prefer tunnel 1
                writeTableEntry(L3M_helper,  r1, table, {match: 0x1}, action, {l: 0x1020202030204010}, modify=True)
                writeTableEntry(L3M_helper,  r1, table, {match: 0x0}, action, {l: 0x1030602050204010}, modify=True)
                writeTableEntry(L3MF_helper, r4, table, {match: 0x1}, action, {l: 0x4020501060101010}, modify=True)
                writeTableEntry(L3MF_helper, r4, table, {match: 0x0}, action, {l: 0x4030301020101010}, modify=True)
                print("➡️ Change to tunnel 1")
            else:
                preferred_tunnel = 0
                # Switch to prefer tunnel 0
                writeTableEntry(L3M_helper,  r1, table, {match: 0x0}, action, {l: 0x1020202030204010}, modify=True)
                writeTableEntry(L3M_helper,  r1, table, {match: 0x1}, action, {l: 0x1030602050204010}, modify=True)
                writeTableEntry(L3MF_helper, r4, table, {match: 0x0}, action, {l: 0x4020501060101010}, modify=True)
                writeTableEntry(L3MF_helper, r4, table, {match: 0x1}, action, {l: 0x4030301020101010}, modify=True)
                print("⬅️ Change to tunnel 0")
        else:
            print("No change necessary")

        # Print the current preferred tunnel
        print(f"Preferred Tunnel: {preferred_tunnel}\n")
        
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
def readTableRules(L2_helper, L3M_helper, L3MF_helper, L3T_helper, s1,r1,r2,r3,r4,r5,r6,
                   ips, macs, labels, iMacs, tLabels, dirs, tcpPorts, udpPorts):
    
    readSwitch(L2_helper, s1, macs)
    readTunnelRouter(L3T_helper, (r2,r3,r5,r6), labels, iMacs)
    readMslpRouter(L3M_helper, (r1,), ips, iMacs, labels, tLabels)
    readMslpFirewallRouter(L3MF_helper, (r4,), ips, iMacs, labels, tLabels, dirs, tcpPorts, udpPorts)

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

# Function to read the current table rules from the tunnel routers and store the known values
def readMslpFirewallRouter(helper, routers, ips, iMacs, labels,
                           tLabels, dirs, tcpPorts, udpPorts):
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

                    elif table_name == "MyIngress.checkDirection":
                        ingress = helper.get_match_field_value(entry.match[0])
                        egress  = helper.get_match_field_value(entry.match[1])
                        dir = (decodeNum(ingress), decodeNum(egress))
                        if dir not in dirs:
                            dirs.append(dir)

                    elif table_name == "MyIngress.allowedPortsTCP":
                        port = decodeNum(helper.get_match_field_value(entry.match[0]))
                        if port not in tcpPorts:
                            tcpPorts.append(port)

                    elif table_name == "MyIngress.allowedPortsUDP":
                        port = decodeNum(helper.get_match_field_value(entry.match[0]))
                        if port not in udpPorts:
                            udpPorts.append(port)

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

    # Instantiate P4Runtime helpers from the p4info files
    L2_helper, L3M_helper, L3MF_helper, L3T_helper = getP4Helpers(p4infoL2_file_path, 
                                                                  p4infoL3M_file_path, 
                                                                  p4infoL3MF_file_path, 
                                                                  p4infoL3T_file_path)

    try:
        # Create P4Runtime connections to the switches
        s1,r1,r2,r3,r4,r5,r6 = createConnectionsToSwitches()
        
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        sendMasterAtributionMessage(s1,r1,r2,r3,r4,r5,r6)

        # Install the P4 programs on the switches if not yet installed
        installP4Programs(L2_helper, L3M_helper, L3MF_helper, L3T_helper, 
                          jsonL2_file_path, jsonL3M_file_path, jsonL3MF_file_path, jsonL3T_file_path,
                          s1,r1,r2,r3,r4,r5,r6)

        # Write clone engines and their sessionId, if not written yet
        writeCloneEngines(L2_helper, L3M_helper, L3MF_helper, L3T_helper,
                          s1,r1,r2,r3,r4,r5,r6)

        # Write default actions, if not written yet
        writeDefaultActions(L2_helper, L3M_helper, L3MF_helper, L3T_helper,
                            s1,r1,r2,r3,r4,r5,r6)

        # Read all entries of all tables of all routers and populate state variables
        readTableRules(L2_helper, L3M_helper, L3MF_helper, L3T_helper, s1,r1,r2,r3,r4,r5,r6,
                        ips, macs, labels, iMacs, tLabels, dirs, tcpPorts, udpPorts)

        # Check the state of the controller
        printControllerState(ips, macs, labels, iMacs, tLabels, dirs, tcpPorts, udpPorts)

        # Write static rules to the L3 Switches, if not written yet
        writeStaticRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6,
                         ips, labels, iMacs, tLabels, dirs, tcpPorts, udpPorts)

        # Show all rules set in the tables
        printTableRules(L2_helper,   s1) # s1 is empty before any traffic
        printTableRules(L3M_helper,  r1)
        printTableRules(L3T_helper,  r2)
        printTableRules(L3T_helper,  r3)
        printTableRules(L3MF_helper, r4)
        printTableRules(L3T_helper,  r5)
        printTableRules(L3T_helper,  r6)

        # Thread to handle load balancing between the tunnels
        t = threading.Thread(target=changeTunnelRules, args=(L3M_helper, L3MF_helper, r1, r4,), daemon=True)
        t.start()

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