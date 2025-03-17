/* -*- P4_16 -*- */
/**
 * The following includes should come from /usr/share/p4c/p4include/.
 * 
 * The files:
 *   - p4/core.p4
 *   - p4/v1model.p4
 * 
 * are available if you need to reference or consult them.
 */

#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/* Simple typedef to simplify MAC address handling */
typedef bit<48> macAddr_t;

/**
 * This section defines the protocol headers we will be working with.
 * 
 * A header consists of multiple fields, each with a specific size.
 * It is essential to understand all the fields and their sizes.
 * 
 * All the necessary headers have already been declared for you.
 */

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

struct metadata {
    /* empty for now */
}

struct headers {
    ethernet_t   ethernet;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
 /**
* A parser always begins in the 'start' state.
* 
* A state can transition to another state using two methods:
*   - `transition <next-state>;` → Direct transition to a specified state.
*   - `transition select(<expression>) { ... };` → Works like a switch-case statement,
*     selecting the next state based on the given expression.
*
* A parser can be viewed as a state machine,  
* always starting in the 'start' state and ending  
* in one of two possible states: 'accept' or 'reject'.
*/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { /* empty for now */  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action setEgress(bit<9>  egressPort) {
        standard_metadata.egress_spec = egressPort;
    }

    table macLookup{
        key = {hdr.ethernet.dstAddr : exact;}
        actions = { 
            setEgress;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
     
    apply {
       if(hdr.ethernet.isValid()){
        if(!macLookup.apply().hit){
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
        // Prune multicast packets to the ingress port to prevent loops.
        if (standard_metadata.egress_port == standard_metadata.ingress_port)
            drop();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { /* empty for now */ }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
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
