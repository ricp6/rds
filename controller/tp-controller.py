#!/usr/bin/env python3

import argparse
import os
import sys
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

# Custom function to handle gRPC errors and display useful debugging information
def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

# Function to read the current table rules from the switch and print them
def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
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

# Function to install a default action entry into a table
def writeDefaultTableAction(p4info_helper, sw, table, action):
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
    mc_group = p4info_helper.buildMulticastGroupEntry(sessionId, broadcastReplicas)
    sw.WritePREEntry(mc_group)
    print("Installed Mc Group on %s" % sw.name)

# Function to write a CPU session entry for packet cloning to the CPU port
def writeCpuSession(p4info_helper, sw, sessionId):
    clone_entry = p4info_helper.buildCloneSessionEntry(sessionId, cpuReplicas)
    sw.WritePREEntry(clone_entry)
    print("Installed clone session on %s" % sw.name)



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
    
    print("Connection successful")
    return s1,r1,r2,r3,r4,r5,r6

# Function to send master arbitration update messages to all switches to establish
# this controller as master
def sendMasterAtributionMessage(s1,r1,r2,r3,r4,r5,r6):
    s1.MasterArbitrationUpdate()
    r1.MasterArbitrationUpdate()
    r2.MasterArbitrationUpdate()
    r3.MasterArbitrationUpdate()
    r4.MasterArbitrationUpdate()
    r5.MasterArbitrationUpdate()
    r6.MasterArbitrationUpdate()
        
# Function to install the P4 programs on all switches
def installP4Programs(L2_helper, L3M_helper, L3MF_helper, L3T_helper, 
                      jsonL2, jsonL3M, jsonL3MF, jsonL3T,
                      s1,r1,r2,r3,r4,r5,r6):
    
    s1.SetForwardingPipelineConfig(p4info=L2_helper.p4info,
                                    bmv2_json_file_path=jsonL2)
    print("Installed L2   - P4 Program using SetForwardingPipelineConfig on s1")
    r1.SetForwardingPipelineConfig(p4info=L3M_helper.p4info,
                                    bmv2_json_file_path=jsonL3M)
    print("Installed L3M  - P4 Program using SetForwardingPipelineConfig on r1")
    r4.SetForwardingPipelineConfig(p4info=L3MF_helper.p4info,
                                    bmv2_json_file_path=jsonL3MF)
    print("Installed L3MF - P4 Program using SetForwardingPipelineConfig on r4")
    r2.SetForwardingPipelineConfig(p4info=L3T_helper.p4info,
                                    bmv2_json_file_path=jsonL3T)
    r3.SetForwardingPipelineConfig(p4info=L3T_helper.p4info,
                                    bmv2_json_file_path=jsonL3T)
    r5.SetForwardingPipelineConfig(p4info=L3T_helper.p4info,
                                    bmv2_json_file_path=jsonL3T)
    r6.SetForwardingPipelineConfig(p4info=L3T_helper.p4info,
                                    bmv2_json_file_path=jsonL3T)
    print("Installed L3T  - P4 Program using SetForwardingPipelineConfig on r2, r3, r5 and r6")
    
# Function to write the default actions on all tables from all switches
def writeDefaultActions(L2_helper, L3M_helper, L3MF_helper, L3T_helper,
                        s1,r1,r2,r3,r4,r5,r6):
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

# Function to write clone engines and their sessionId
def writeCloneEngines(L2_helper, L3M_helper, L3MF_helper, L3T_helper,
                      s1,r1,r2,r3,r4,r5,r6):
    # Write Multicast Group
    writeMcGroup(L2_helper, s1, mcSessionId)
    # Write CPU Session
    writeCpuSession(L2_helper,   s1, cpuSessionId)
    writeCpuSession(L3M_helper,  r1, cpuSessionId)
    writeCpuSession(L3T_helper,  r2, cpuSessionId)
    writeCpuSession(L3T_helper,  r3, cpuSessionId)
    writeCpuSession(L3MF_helper, r4, cpuSessionId)
    writeCpuSession(L3T_helper,  r5, cpuSessionId)
    writeCpuSession(L3T_helper,  r6, cpuSessionId)

# Function to write the static rules in all tables from all L3 switches
def writeStaticRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6):
    # Ideia: em vez de passar os switches, fazer dinamico de acordo com o p4 injetado em cada um
    writeTunnelSelectionRules(L3M_helper, L3MF_helper, r1, r4)
    writeIPv4ForwardingRules(L3M_helper, L3MF_helper, r1, r4)
    writeLabelForwardingRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6)
    writeMacRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6)
    writeFirewallRules(L3MF_helper, r4)

# Function to write the static tunnel selection rules
def writeTunnelSelectionRules(L3M_helper, L3MF_helper, r1, r4):
    table = "MyIngress.tunnelLookup"
    action = "MyIngress.addMSLP"
    match = "meta.tunnel"
    l = "labels"
    
    writeTableEntry(L3M_helper,  r1, table, {match: 0x0}, action, {l: 0x1020202030204010})
    writeTableEntry(L3M_helper,  r1, table, {match: 0x1}, action, {l: 0x1030602050204010})
    writeTableEntry(L3MF_helper, r4, table, {match: 0x0}, action, {l: 0x4030301020101010})
    writeTableEntry(L3MF_helper, r4, table, {match: 0x1}, action, {l: 0x4020501060101010})

# Function to write the static ipv4 forwarding rules
def writeIPv4ForwardingRules(L3M_helper, L3MF_helper, r1, r4):
    table = "MyIngress.ipv4Lpm"
    action = "MyIngress.forward"
    match = "hdr.ipv4.dstAddr"
    port = "egressPort"
    mac = "nextHopMac"
                                            #10»0a, 10.0.0.1»0a000001
    writeTableEntry(L3M_helper,  r1, table, {match : (0x0a000101, 32)}, action, {port : 0x0001, mac : 0xaa0000000001})
    writeTableEntry(L3M_helper,  r1, table, {match : (0x0a000102, 32)}, action, {port : 0x0001, mac : 0xaa0000000002})
    writeTableEntry(L3M_helper,  r1, table, {match : (0x0a000103, 32)}, action, {port : 0x0001, mac : 0xaa0000000003})
    writeTableEntry(L3MF_helper, r4, table, {match : (0x0a000201, 32)}, action, {port : 0x0001, mac : 0xaa0000000004})

# Function to write the static label forwarding rules
def writeLabelForwardingRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6):
    table = "MyIngress.labelLookup"
    frwdTunnel = "MyIngress.forwardTunnel"
    removeMSLP = "MyIngress.removeMSLP"
    match = "hdr.labels[0].label"
    port = "egressPort"
    mac = "nextHopMac"

    writeTableEntry(L3M_helper, r1, table, {match: 0x1010}, removeMSLP, None)
    writeTableEntry(L3M_helper, r1, table, {match: 0x1020}, frwdTunnel, {port: 0x02, mac: 0xaa0000000201})
    writeTableEntry(L3M_helper, r1, table, {match: 0x1030}, frwdTunnel, {port: 0x03, mac: 0xaa0000000601})

    writeTableEntry(L3MF_helper, r4, table, {match: 0x4010}, removeMSLP, None)
    writeTableEntry(L3MF_helper, r4, table, {match: 0x4020}, frwdTunnel, {port: 0x02, mac: 0xaa0000000502})
    writeTableEntry(L3MF_helper, r4, table, {match: 0x4030}, frwdTunnel, {port: 0x03, mac: 0xaa0000000302})

    writeTableEntry(L3T_helper, r2, table, {match: 0x2010}, frwdTunnel, {port: 0x01, mac: 0xaa0000000102})
    writeTableEntry(L3T_helper, r2, table, {match: 0x2020}, frwdTunnel, {port: 0x02, mac: 0xaa0000000301})
    writeTableEntry(L3T_helper, r3, table, {match: 0x3010}, frwdTunnel, {port: 0x01, mac: 0xaa0000000202})
    writeTableEntry(L3T_helper, r3, table, {match: 0x3020}, frwdTunnel, {port: 0x02, mac: 0xaa0000000403})
    writeTableEntry(L3T_helper, r5, table, {match: 0x5010}, frwdTunnel, {port: 0x01, mac: 0xaa0000000602})
    writeTableEntry(L3T_helper, r5, table, {match: 0x5020}, frwdTunnel, {port: 0x02, mac: 0xaa0000000402})
    writeTableEntry(L3T_helper, r6, table, {match: 0x6010}, frwdTunnel, {port: 0x01, mac: 0xaa0000000103})
    writeTableEntry(L3T_helper, r6, table, {match: 0x6020}, frwdTunnel, {port: 0x02, mac: 0xaa0000000501})

# Function to write the static internal macs rules
def writeMacRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6):
    table = "MyIngress.internalMacLookup"
    action = "MyIngress.rewriteMacs"
    match = "standard_metadata.egress_spec"
    mac = "srcMac"

    writeTableEntry(L3M_helper, r1, table, {match: 0x01}, action, {mac: 0xaa0000000101})
    writeTableEntry(L3M_helper, r1, table, {match: 0x02}, action, {mac: 0xaa0000000102})
    writeTableEntry(L3M_helper, r1, table, {match: 0x03}, action, {mac: 0xaa0000000103})

    writeTableEntry(L3MF_helper,r4, table, {match: 0x01}, action, {mac: 0xaa0000000401})
    writeTableEntry(L3MF_helper,r4, table, {match: 0x02}, action, {mac: 0xaa0000000402})
    writeTableEntry(L3MF_helper,r4, table, {match: 0x03}, action, {mac: 0xaa0000000403})
    
    writeTableEntry(L3T_helper, r2, table, {match: 0x01}, action, {mac: 0xaa0000000201})
    writeTableEntry(L3T_helper, r2, table, {match: 0x02}, action, {mac: 0xaa0000000202})
    writeTableEntry(L3T_helper, r3, table, {match: 0x01}, action, {mac: 0xaa0000000301})
    writeTableEntry(L3T_helper, r3, table, {match: 0x02}, action, {mac: 0xaa0000000302})
    writeTableEntry(L3T_helper, r5, table, {match: 0x01}, action, {mac: 0xaa0000000501})
    writeTableEntry(L3T_helper, r5, table, {match: 0x02}, action, {mac: 0xaa0000000502})
    writeTableEntry(L3T_helper, r6, table, {match: 0x01}, action, {mac: 0xaa0000000601})
    writeTableEntry(L3T_helper, r6, table, {match: 0x02}, action, {mac: 0xaa0000000602})

# Function to write the static firewall rules
def writeFirewallRules(L3MF_helper, r4):
    dirTable = "MyIngress.checkDirection"
    tcpTable = "MyIngress.allowedPortsTCP"
    udpTable = "MyIngress.allowedPortsUDP"
    action = "MyIngress.setDirection"
    matchDir = "standard_metadata.egress_spec"
    matchTcp = "hdr.tcp.dstPort"
    matchUdp = "hdr.udp.dstPort"
    d = "dir"

    writeTableEntry(L3MF_helper, r4, dirTable, {matchDir: 0x01}, action, {d: 1})
    writeTableEntry(L3MF_helper, r4, dirTable, {matchDir: 0x02}, action, {d: 0})
    writeTableEntry(L3MF_helper, r4, dirTable, {matchDir: 0x03}, action, {d: 0})

    writeTableEntry(L3MF_helper, r4, tcpTable, {matchTcp: 0x51}, "NoAction", None) # decimal 81 » 0x51
    writeTableEntry(L3MF_helper, r4, udpTable, {matchUdp: 0x35}, "NoAction", None) # decimal 53 » 0x35

# Function to write an entry to a table of a switch
def writeTableEntry(helper, sw, table, match, action, params):
    table_entry = helper.buildTableEntry(
        table_name = table,
        match_fields = match,
        default_action = False,
        action_name = action,
        action_params = params,
        priority = 0)
    sw.WriteTableEntry(table_entry)
    print("Installed %s rule for %s on %s" % (action, table, sw.name))



# Main function that initializes P4Runtime connections and performs setup
def main(p4infoL2_file_path, p4infoL3M_file_path, p4infoL3MF_file_path, p4infoL3T_file_path, 
         jsonL2_file_path, jsonL3M_file_path, jsonL3MF_file_path, jsonL3T_file_path):

    # Variables to store the state of the switche's tables
    macList = []

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

        # Install the P4 programS on the switches using the SetForwardingPipelineConfig API
        installP4Programs(L2_helper, L3M_helper, L3MF_helper, L3T_helper, 
                          jsonL2_file_path, jsonL3M_file_path, jsonL3MF_file_path, jsonL3T_file_path,
                          s1,r1,r2,r3,r4,r5,r6)

        # Write default actions
        writeDefaultActions(L2_helper, L3M_helper, L3MF_helper, L3T_helper,
                            s1,r1,r2,r3,r4,r5,r6)
        
        # Write clone engines and their sessioId
        writeCloneEngines(L2_helper, L3M_helper, L3MF_helper, L3T_helper,
                          s1,r1,r2,r3,r4,r5,r6)

        # Add the static rules to the L3 Switches
        writeStaticRules(L3M_helper, L3MF_helper, L3T_helper, r1,r2,r3,r4,r5,r6)

        # readTableRules(p4info_helper, s1)
        # A good approach is to read the current table entries from the switch and populate
        # the controller internal structures (e.g., "macList"). This allows the controller to be aware of
        # the current state of the tables, enabling it to operate accordingly. 
        # This is especially useful if the controller goes down during runtime and needs
        # to be restarted, as it ensures the controller can synchronize with the switch 
        # and avoid unnecessary rule injections or reset the tables if needed.

        for response in s1.stream_msg_resp:
            # Check if the response contains a packet-in message
            if response.packet:
                print("Received packet-in message:")
                packet = Ether(raw(response.packet.payload))
                if packet.type == 0x1234:
                    cpu_header = CpuHeader(bytes(packet.load))
                    print("mac: %012X ingress_port: %s " % (cpu_header.macAddr, cpu_header.ingressPort))
                    if cpu_header.macAddr not in macList:
                        writeMacSrcLookUp(L2_helper, s1, cpu_header.macAddr)
                        writeMacDstLookUp(L2_helper, s1, cpu_header.macAddr, cpu_header.ingressPort)
                        macList.append(cpu_header.macAddr)
                    else :
                        print("Rules already set")
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