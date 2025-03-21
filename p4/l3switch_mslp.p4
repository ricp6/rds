/* -*- P4_16 -*- */
/**
* The following includes 
* should come form /usr/share/p4c/p4include/
* The files :
 * ~/RDS-tut/p4/core.p4
 * ~/RDS-tut/p4/v1model.p4
* are here if you need/want to consult them
*/
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/* simple typedef to ease your task */
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_MSLP = 0x88B5;

const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;

/**
* Here we define the headers of the protocols
* that we want to work with.
* A header has many fields you need to know all of them
* and their sizes.
* All the headers that you will need are already declared.
*/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header mslp_t {
    bit<16> etherType; // L3 protocol
}

header label_t {
    bit<16> label;
    bit<8>  bos;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  rsv;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> hdrChecksum;
    bit<16> urgentPtr;
}

header tcp_options_t {
    varbit<320> tcp_options; // max size (40 bytes)
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> hdrChecksum;
}

struct metadata {
    macAddr_t nextHopMac;
    bit<8>    tcp_options_size;
    bit<2>    tunnel;
    bit<1>    toRemove;
}

struct headers {
    ethernet_t    ethernet;
    mslp_t        mslp;
    label_t[3]    labels;
    ipv4_t        ipv4;
    tcp_t         tcp;
    tcp_options_t tcp_options;
    udp_t         udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    /**
     * a parser always begins in the start state
     * a state can invoke other state with two methods
     * transition <next-state>
     * transition select(<expression>) -> works like a switch case
     */
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MSLP: parse_mslp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    
    state parse_mslp {
        packet.extract(hdr.mslp);
        transition parse_labels;
    }
    
    state parse_labels {
        packet.extract(hdr.labels.next);
        transition select(hdr.labels.last.bos) {
            0x00: parse_labels; // Create a loop
            0x01: guess_labels_payload;
        }
    }

    state guess_labels_payload {
        transition select(hdr.mslp.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);

        // Calculate TCP options size
        meta.tcp_options_size = (bit<8>)(hdr.tcp.dataOffset * 4) - 20;

        transition select(meta.tcp_options_size) {
            0: accept;
            default: parse_tcp_options;
        }
    }
    
    state parse_tcp_options {
        packet.extract(hdr.tcp_options, (bit<32>)meta.tcp_options_size);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
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

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9>  egressPort, macAddr_t nextHopMac) {
        standard_metadata.egress_spec = egressPort;
        meta.nextHopMac = nextHopMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4Lpm{
        key = {hdr.ipv4.dstAddr : lpm;}
        actions = {
            forward;
            drop;
        }
        size = 8; // 3 hosts, some extra entries to leave space for more hosts
        default_action = drop;
    }

    action rewriteMacs(macAddr_t srcMac) {
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = meta.nextHopMac;
    }

    table internalMacLookup{
        key = {standard_metadata.egress_spec: exact;}
        actions = {
            rewriteMacs;
            drop;
        }
        size = 3; // 3 ports
        default_action = drop;
    }

    action selectTunnel(bit<16> dstPort) {
        bit<1> tunnel;
        hash(
            tunnel,
            HashAlgorithm.crc32,
            (bit<1>)0,
            {
                hdr.ipv4.protocol,
                hdr.ipv4.dstAddr,
                dstPort
            },
            (bit<1>)1
        );
        if(tunnel == 0) {
            meta.tunnel = 1;
        } else {
            meta.tunnel = 2;
        }
    }
    
    action createMSLP(bit<48> labels) {
        // Populate mslp header
        hdr.mslp = {hdr.ethernet.etherType};
        hdr.mslp.setValid();
        
        // Populate label header
        hdr.labels[0] = {labels[47:32], 0x00};
        hdr.labels[1] = {labels[31:16], 0x00};
        hdr.labels[2] = {labels[15:00], 0x01};
        hdr.labels[0].setValid();
        hdr.labels[1].setValid();
        hdr.labels[2].setValid();

        // Update ethernet header
        hdr.ethernet.etherType = TYPE_MSLP;
    }

    action forwardTunnel(bit<9> egressPort, macAddr_t nextHopMac, bit<48> labels) {
        // Set forwarding info
        standard_metadata.egress_spec = egressPort;
        meta.nextHopMac = nextHopMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // Create the MSLP header
        createMSLP(labels);
    }

    table labelStack {
        key = {meta.tunnel: exact;}
        actions = {
            forwardTunnel;
            drop;
        }
        size = 2; // 2 tunnels
        default_action = drop;
    }

    apply {
        if(hdr.ipv4.isValid()){
            if(hdr.mslp.isValid()) {  // It's the end of the tunnel
                meta.toRemove = 1;  // Set flag to remove packet

                // Forward the unencapsulated packet
                if(ipv4Lpm.apply().hit){
                    internalMacLookup.apply();
                }
            
            } else {  // Start of the tunnel
                meta.toRemove = 0;
                
                // Select the tunnel
                if(hdr.tcp.isValid()) {
                    selectTunnel(hdr.tcp.dstPort);
                } else if(hdr.udp.isValid()) {
                    selectTunnel(hdr.udp.dstPort);
                } else {
                    selectTunnel(0x0000);
                }

                // Create MSLP header and forward to the tunnel
                if(labelStack.apply().hit) {
                    internalMacLookup.apply();
                }
            }

        } else {
            drop();
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    

    action removeMSLP() {
        // restore etherType
        hdr.ethernet.etherType = hdr.mslp.etherType;

        // set validity of the removed headers
        hdr.mslp.setInvalid();
        hdr.labels[0].setInvalid();
        hdr.labels[1].setInvalid(); // só vai ter uma label na stack supostamente, pode dar erro?
        hdr.labels[2].setInvalid();
    }

    apply {
        // It's the end of the tunnel
        if(meta.toRemove == 1) {
            // Remove the MSLP header
            removeMSLP();            
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    /* The IPv4 Header was changed, it needs new checksum*/
    apply { 
        update_checksum(
	        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16); }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mslp);
        packet.emit(hdr.labels);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options);
        packet.emit(hdr.udp);
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
