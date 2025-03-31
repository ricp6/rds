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
    {'egress_port': 4, 'instance': 1},
    {'egress_port': 5, 'instance': 1}
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

# Main function that initializes P4Runtime connections and performs setup
def main(p4info_file_path, json_file_path):
    macList = []
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a P4Runtime connection to the switch with gRPC and proto dump file for logging
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=1,
            proto_dump_file='logs/s1-p4runtime-request.txt') # the file need to exist
        print("Connection successful")

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # Install the P4 program on the switch using the SetForwardingPipelineConfig API
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=json_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        
        # Write default actions
        writeDefaultTableAction(p4info_helper, s1, "MyIngress.sMacLookup", "MyIngress.learnMac")
        writeDefaultTableAction(p4info_helper, s1, "MyIngress.dMacLookup", "NoAction")
        # write clone engines and their sessioId
        writeCpuSession(p4info_helper, s1, cpuSessionId)
        writeMcGroup(p4info_helper, s1, mcSessionId)

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
                        writeMacSrcLookUp(p4info_helper, s1, cpu_header.macAddr)
                        writeMacDstLookUp(p4info_helper, s1, cpu_header.macAddr, cpu_header.ingressPort)
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
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=True)
    parser.add_argument('--json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=True)
    args = parser.parse_args()

    # Validate the provided paths for p4info and JSON files
    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found:")
        parser.exit(1)
    if not os.path.exists(args.json):
        parser.print_help()
        print("\nBMv2 JSON file not found:")
        parser.exit(1)
    main(args.p4info, args.json)