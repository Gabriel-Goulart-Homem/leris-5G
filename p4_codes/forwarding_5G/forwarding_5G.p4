#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<12> vlan_id_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header mac_h {
    bit<1> R1;
    bit<1> R2;
    bit<6> LCID;
    bit<8> eLCID;
}

header rlc_h {
    bit<1> D_C;
    bit<1> P;
    bit<2> SI;
    bit<1> R1;
    bit<1> R2;
    bit<2> SN1;
    bit<8> SN2;
    bit<8> SN3;
    bit<8> SO1;
    bit<8> SO2;
}

header pdcp_h {
    bit<1> R1;
    bit<1> R2;
    bit<1> R3;
    bit<1> R4;
    bit<4> PDCP_SN1;
    bit<8> PDCP_SN2;
}

struct header_t {
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    ipv4_h ipv4;
    tcp_h tcp;
    
    // Add more headers here.
    mac_h mac;
    rlc_h rlc;
    pdcp_h pdcp;
}

struct empty_header_t {}

struct empty_metadata_t {}

struct metadata_t {}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}


parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition accept;
//        transition select (hdr.ethernet.ether_type) {
//            //ETHERTYPE_IPV4 : parse_ipv4;
//            ETHERTYPE_VLAN : parse_vlan_tag;
//            default : accept;
//        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type){
		    ETHERTYPE_VLAN : parse_mac;
		    default: accept;
        }
    }
    state parse_mac {
        pkt.extract(hdr.mac);
        transition parse_rlc;
    }
    
    state parse_rlc {
        pkt.extract(hdr.rlc);
        transition parse_pdcp;
    }
    
    state parse_pdcp {
        pkt.extract(hdr.pdcp);
        transition parse_ipv4;
    }

   state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
	        6:parse_tcp;
	        default: accept;
        }
    }
    
    state parse_tcp{
	    pkt.extract(hdr.tcp);
	    transition accept;
    }
}


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    apply {
        pkt.emit(hdr.ethernet);
	    pkt.emit(hdr.vlan_tag);
	    pkt.emit(hdr.mac);
	    pkt.emit(hdr.rlc);
	    pkt.emit(hdr.pdcp);
	    pkt.emit(hdr.ipv4);
	    pkt.emit(hdr.tcp);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

/*
    action hit(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }

    action miss() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    table forward {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }

        actions = {
            hit;
            miss;
        }

        const default_action = miss;
        size = 1024;
    }
*/

    action new_qid(bit<5> qid){
        ig_intr_tm_md.qid = qid;
    }

    table change_qid {
        key = {
            hdr.vlan_tag.vid : exact;
        }

        actions = {
            new_qid;
        }
        size = 1024;
    }

    apply {
        //forward.apply();
            
        if(ig_intr_md.ingress_port == 132){
            ig_intr_tm_md.ucast_egress_port = 133;
        }else if(ig_intr_md.ingress_port == 133){
            ig_intr_tm_md.ucast_egress_port = 132;
        }
        change_qid.apply();
	

        // No need for egress processing, skip it and use empty controls for egress.
        ig_intr_tm_md.bypass_egress = 1w1;
    }
}

// ---------------------------------------------------------------------------
// Egress
// ---------------------------------------------------------------------------
parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

// Skip egress
control BypassEgress(inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action set_bypass_egress() {
        ig_tm_md.bypass_egress = 1w1;
    }

    table bypass_egress {
        actions = {
            set_bypass_egress();
        }
        const default_action = set_bypass_egress;
    }

    apply {
        bypass_egress.apply();
    }
}

// Empty egress parser/control blocks
parser EmptyEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}

control EmptyEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {}
}

control EmptyEgress(
        inout empty_header_t hdr,
        inout empty_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
