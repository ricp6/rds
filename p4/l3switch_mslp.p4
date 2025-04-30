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

const bit<8> TYPE_ICMP = 0x01;
const bit<8> TYPE_TCP  = 0x06;
const bit<8> TYPE_UDP  = 0x11;


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

header icmp_t {
    bit<8>   typ;
    bit<8>   code;
    bit<16>  hdrChecksum;
    bit<16>  identifier;
    bit<16>  sequence;
    bit<64>  timestamp;
    bit<384> payload;  // Added variable-length payload field
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

header tcp_opt_t {
    varbit<320> tcp_opt; // max size (40 bytes)
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> hdrChecksum;
}

struct metadata {
    macAddr_t nextHopMac;
    bit<8>    tcp_opt_size;
    bit<2>    tunnel;
    bit<1>    setRecirculate;
}

struct headers {
    ethernet_t  ethernet;
    mslp_t      mslp;
    label_t[4]  labels; // in the sides, the packet comes with 1 or 4 labels
    ipv4_t      ipv4;
    icmp_t      icmp;
    tcp_t       tcp;
    tcp_opt_t   tcp_opt;
    udp_t       udp;
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
            TYPE_ICMP: parse_icmp;
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }
        
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);

        // Calculate TCP options size
        meta.tcp_opt_size = (bit<8>)(hdr.tcp.dataOffset * 4) - 20;

        transition select(meta.tcp_opt_size) {
            0: accept;
            default: parse_tcp_opt;
        }
    }
    
    state parse_tcp_opt {
        packet.extract(hdr.tcp_opt, (bit<32>)meta.tcp_opt_size);
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
    
    counter(4, CounterType.packets) tunnel_counter;

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
            NoAction;
        }
        size = 16;
        default_action = NoAction;
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
        size = 16;
        default_action = drop;
    }

    action forwardTunnel(bit<9>  egressPort, macAddr_t nextHopMac) {
        standard_metadata.egress_spec = egressPort;
        meta.nextHopMac = nextHopMac;
    }

    action removeMSLP() {
        // restore etherType
        hdr.ethernet.etherType = hdr.mslp.etherType;

        // set validity of the removed headers
        hdr.mslp.setInvalid();
        hdr.labels[0].setInvalid();
        hdr.labels[1].setInvalid();  // vale a pena?
        hdr.labels[2].setInvalid();
        hdr.labels[3].setInvalid();
    }

    table labelLookup {
        key = {hdr.labels[0].label : exact;}
        actions = {
            forwardTunnel;
            removeMSLP;
            drop;
        }
        size = 16;
        default_action = drop;
    }

    action addMSLP(bit<64> labels) {
        // Populate mslp header
        hdr.mslp = {hdr.ethernet.etherType};
        hdr.mslp.setValid();
        
        // Populate label header
        hdr.labels[0] = {labels[63:48], 0x00};
        hdr.labels[1] = {labels[47:32], 0x00};
        hdr.labels[2] = {labels[31:16], 0x00};
        hdr.labels[3] = {labels[15:00], 0x01};
        hdr.labels[0].setValid();
        hdr.labels[1].setValid();
        hdr.labels[2].setValid();
        hdr.labels[3].setValid();

        // Update ethernet header
        hdr.ethernet.etherType = TYPE_MSLP;
    }

    table tunnelLookup {
        key = {meta.tunnel: exact;}
        actions = {
            addMSLP;
            drop;
        }
        size = 16;
        default_action = drop;
    }
    
    action selectTunnel(bit<16> srcPort, bit<16> dstPort) {
        hash(
            meta.tunnel,
            HashAlgorithm.crc32,
            (bit<2>)0,
            {
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                srcPort,
                dstPort
            },
            (bit<2>)2
        );
    }

    apply {
        // If it is the original packet
        if(standard_metadata.instance_type == 0){
            tunnel_counter.count((bit<32>) standard_metadata.ingress_port); // Count new packet in
        }

        if(hdr.mslp.isValid()) { // If encapsulated
            switch(labelLookup.apply().action_run) {
                // If its the last label, removeMSLP and recirculate the ipv4 packet
                removeMSLP: { 
                    meta.setRecirculate = 1; 
                }
                // If still inside the tunnel, forward in the tunnel
                forwardTunnel: { 
                    internalMacLookup.apply();
                }
            }
            
        } else if(hdr.ipv4.isValid()) { // If unencapsulated
            if(ipv4Lpm.apply().hit) { // Dst it the LAN
                internalMacLookup.apply();

            } else { // Send through a tunnel
                if(hdr.tcp.isValid())       selectTunnel(hdr.tcp.srcPort, hdr.tcp.dstPort);
                else if(hdr.udp.isValid())  selectTunnel(hdr.udp.srcPort, hdr.udp.dstPort);
                else if(hdr.icmp.isValid()) selectTunnel(hdr.icmp.identifier, hdr.icmp.sequence);
                else                        selectTunnel(0x0110, 0x1001); // arbitrary values

                // Create MSLP header and recirculate the packet with MSLP header
                if(tunnelLookup.apply().hit) {
                    meta.setRecirculate = 1;
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

    action popLabel() {
        hdr.labels.pop_front(1);
    }

    apply {
        if(meta.setRecirculate == 1) {
            recirculate_preserving_field_list(0);
        } else if(hdr.mslp.isValid() && hdr.labels[0].isValid()) {
            popLabel();  // Remove a sua label antes de enviar ao seguinte
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
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_opt);
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
