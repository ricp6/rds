#include <core.p4>
#include <v1model.p4>

const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_t {
    macAddr_t srcAddr;
    bit<16> ingress_port; // to be read by the controller like a 16bit int
}


struct metadata {
    @field_list(0) // preserved on clone_preserving_field_list
    bit<9> ingress_port;
}


struct headers {
    ethernet_t   eth;
    cpu_t        cpu;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.eth);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { /* do nothing */  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    
    action learnMac() {
        meta.ingress_port = standard_metadata.ingress_port;
        clone_preserving_field_list(CloneType.I2E, 100, 0);
    }

    table sMacLookup{
        key = {hdr.eth.srcAddr : exact;}
        actions = { 
            learnMac;
            NoAction;
        }
        size = 256;
        default_action = learnMac;
    }

    action forward(bit<9>  egressPort) {
        standard_metadata.egress_spec = egressPort;
    }

    table dMacLookup{
        key = {hdr.eth.dstAddr : exact;}
        actions = { 
            forward;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }
     
    apply {
        if(hdr.eth.isValid()){
            sMacLookup.apply(); /* On Miss, runs the default action, on Hit the action should be NoAction */
            if(!dMacLookup.apply().hit){
                standard_metadata.mcast_grp = 1;
            }
        } else {
            mark_to_drop(standard_metadata);
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if(standard_metadata.instance_type == 1){
            hdr.cpu.setValid();
            hdr.cpu.srcAddr = hdr.eth.srcAddr;
            hdr.cpu.ingress_port = (bit<16>)meta.ingress_port;
            hdr.eth.etherType = L2_LEARN_ETHER_TYPE;
            // If the packet is a clone to be sent to CPU it will be truncated
            truncate((bit<32>)22); // it already had 22 bytes, but just to make you aware that this method exists
        }
        // Prune multicast packet to ingress port to preventing loop
        if (standard_metadata.egress_port == standard_metadata.ingress_port)
            drop();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { /* do nothing */ }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.cpu);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
/*
 * Architecture.
 *
 * M must be a struct.
 *
 * H must be a struct where every one if its members is of type
 * header, header stack, or header_union.
 *
 * package V1Switch<H, M>(Parser<H, M> p,
 *                      VerifyChecksum<H, M> vr,
 *                      Ingress<H, M> ig,
 *                      Egress<H, M> eg,
 *                      ComputeChecksum<H, M> ck,
 *                      Deparser<H> dep
 *                      );
 * you can define the blocks of your sowtware switch in the following way:
 */

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
