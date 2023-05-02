/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2019-present Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks, Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.  Dissemination of
 * this information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a written
 * agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"


struct metadata_t {}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
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
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan_tag;
            default : reject;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type){
		ETHERTYPE_VLAN : parse_mac;
		default: reject;
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

    Alpm(number_partitions = 1024, subtrees_per_partition = 2) algo_lpm;

    bit<10> vrf;

    action hit(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }

    action miss() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

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

    table forward {
        key = {
            vrf : exact;
            hdr.ipv4.dst_addr : lpm;
        }

        actions = {
            hit;
            miss;
        }

        const default_action = miss;
        size = 1024;
    }

    action route(mac_addr_t srcMac, mac_addr_t dstMac, PortId_t dst_port) {
        ig_intr_tm_md.ucast_egress_port = dst_port;
        hdr.ethernet.dst_addr = dstMac;
        hdr.ethernet.src_addr = srcMac;
        ig_intr_dprsr_md.drop_ctl = 0x0;
    }

    table alpm_forward {
        key = {
            vrf : exact;
            hdr.ipv4.dst_addr : lpm;
        }

        actions = {
            route;
        }

        size = 1024;
        alpm = algo_lpm;
    }

    apply {
        vrf = 10w0;
        forward.apply();
        alpm_forward.apply();
        change_qid.apply();
    }
}

parser EgressParser(
	packet_in pkt,
	out header_t hdr,
	out metadata_t eg_md,
	out egress_intrinsic_metadata_t eg_intr_md) {
	
	TofinoEgressParser() tofino_parser;

	state start{
		tofino_parser.apply(pkt, eg_intr_md);
		transition parse_ethernet;
	}
	

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan_tag;
            default : reject;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type){
		ETHERTYPE_VLAN : parse_mac;
		default: reject;
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

control Egress(
	inout header_t hdr,
	inout metadata_t eg_md,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
	inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
	
	apply {}
}

control EgressDeparser(
	packet_out pkt,
	inout header_t hdr,
	in metadata_t eg_md,
	in egress_intrinsic_metadata_for_deparser_t eg_intr_dors_md) {
	
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

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EgressParser(),
         Egress(),
         EgressDeparser()) pipe;

Switch(pipe) main;
