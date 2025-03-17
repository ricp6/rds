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

const bit<16> TYPE_IPV4 = 0x800;

const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_UDP = 17;

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1

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
    bit<8> tcp_options_size;
}

struct headers {
    ethernet_t    ethernet;
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

    register<bit<1>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;
    register<bit<1>>(BLOOM_FILTER_ENTRIES) bloom_filter_2;
    bit<32> reg_pos_1; bit<32> reg_pos_2;
    bit<1> reg_val_1; bit<1> reg_val_2;
    bit<1> direction;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2) {

        hash(
            reg_pos_1, 
            HashAlgorithm.crc16, 
            (bit<32>)0, 
            {
                ipAddr1, 
                ipAddr2, 
                port1, 
                port2, 
                hdr.ipv4.protocol
            }, 
            (bit<32>)BLOOM_FILTER_ENTRIES
        );
        
        hash(
            reg_pos_2, // second register
            HashAlgorithm.crc32, // another algorithm
            (bit<32>)0, 
            {
                ipAddr1, 
                ipAddr2, 
                port1, 
                port2, 
                hdr.ipv4.protocol
            }, 
            (bit<32>)BLOOM_FILTER_ENTRIES
        );
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
        size = 256;
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
        size = 256;
        default_action = drop;
    }
    
    action setDirection(bit<1> dir) {
        direction = dir;
    }

    table checkPorts {
        key = {
            standard_metadata.ingress_port: exact;
            standard_metadata.egress_spec: exact;
        }
        actions = { 
            setDirection;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    apply {
        if(hdr.ipv4.isValid()){
            if(ipv4Lpm.apply().hit){
                internalMacLookup.apply();
                direction = 0; // default

                // set correct direction
                if(checkPorts.apply().hit) {

                    // TCP connection
                    if(hdr.tcp.isValid()) {
                        // outgoing
                        if(direction == 0) {
                            compute_hashes(
                                hdr.ipv4.srcAddr, 
                                hdr.ipv4.dstAddr,
                                hdr.tcp.srcPort,
                                hdr.tcp.dstPort);
                        
                            // if it is a syn packet, write on bloom filters
                            if(hdr.tcp.syn == 1) {
                                bloom_filter_1.write(reg_pos_1, 1);
                                bloom_filter_2.write(reg_pos_2, 1);
                            }
                        // incoming
                        } else {
                            compute_hashes(
                                hdr.ipv4.dstAddr,
                                hdr.ipv4.srcAddr, 
                                hdr.tcp.dstPort,
                                hdr.tcp.srcPort);
                        
                            bloom_filter_1.read(reg_val_1, reg_pos_1);
                            bloom_filter_2.read(reg_val_2, reg_pos_2);

                            // if missing in some filter, deny access
                            if(reg_val_1 != 1 || reg_val_2 != 1) {
                                drop();
                            }
                        }

                    // UDP connection
                    } else if(hdr.udp.isValid()) {
                        // outgoing
                        if(direction == 0) {
                            compute_hashes(
                                hdr.ipv4.srcAddr, 
                                hdr.ipv4.dstAddr,
                                hdr.udp.srcPort,
                                hdr.udp.dstPort);

                            bloom_filter_1.read(reg_val_1, reg_pos_1);
                            bloom_filter_2.read(reg_val_2, reg_pos_2);

                            // if missing in some filter, thats a new connetcion so write it
                            if(reg_val_1 != 1 || reg_val_2 != 1) {
                                bloom_filter_1.write(reg_pos_1, 1);
                                bloom_filter_2.write(reg_pos_2, 1);
                            }

                        // incoming
                        } else {
                            compute_hashes(
                                hdr.ipv4.dstAddr,
                                hdr.ipv4.srcAddr, 
                                hdr.udp.dstPort,
                                hdr.udp.srcPort);

                            bloom_filter_1.read(reg_val_1, reg_pos_1);
                            bloom_filter_2.read(reg_val_2, reg_pos_2);

                            // if missing in some filter, deny access
                            if(reg_val_1 != 1 || reg_val_2 != 1) {
                                drop();
                            }
                        }
                    }
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
    

    apply {  /* do nothing */  }
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
