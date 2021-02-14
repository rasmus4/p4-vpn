/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//#define NO_REMOTE_FLOOD
#define NO_REMOTE_DATA_PLANE_LEARNING
//#define NO_ARP_PROXY

const egressSpec_t PORT_REMOTE = 0x1;
const egressSpec_t PORT_REMOTE_BROADCAST = 240;

struct geneve_digest_t {
    vni_t vni;
    macAddr_t smac;
    ip4Addr_t dstAddr;
}

struct local_digest_t {
    vni_t vni;
    macAddr_t smac;
    egressSpec_t inPort;
}

#ifndef NO_ARP_PROXY
struct arp_digest_t {
    vni_t vni;
    macAddr_t smac;
    egressSpec_t inPort;
    ip4Addr_t sip;
}
#endif


control GeneveVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

control GeneveIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action broadcast() {
        standard_metadata.mcast_grp = (bit<16>)meta.vni + 1;
    }

    action local_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action decapsulate() {
        hdr.ipv4.setInvalid();
        hdr.ethernet.setInvalid();
        hdr.udp.setInvalid();
        hdr.geneve.setInvalid();
    }

    action nve_digest() {
        digest<geneve_digest_t>(1, {hdr.geneve.vni, hdr.inner_ethernet.srcAddr, hdr.ipv4.srcAddr});
    }

    action set_ingress_vni(vni_t vni) {
        meta.vni = vni;
    }

    action set_meta_vni() {
        meta.vni = hdr.geneve.vni;
    }

    action remote_forward(ip4Addr_t srcAddr, ip4Addr_t dstAddr) {
        standard_metadata.egress_spec = PORT_REMOTE;

        hdr.inner_ipv4 = hdr.ipv4;

        hdr.ipv4.setValid();
        hdr.ipv4.version = 4; // IPv4
        hdr.ipv4.ihl = 5;
        hdr.ipv4.diffserv = 0;
        hdr.ipv4.totalLen = HEADER_SIZE_ETH +
                HEADER_SIZE_IPV4 +
                HEADER_SIZE_UDP +
                HEADER_SIZE_GENEVE +
                hdr.inner_ipv4.totalLen;
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 2; // Don't fragment
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.ttl = 0xFF;
        hdr.ipv4.protocol = IP_PROTO_UDP;
        hdr.ipv4.hdrChecksum = 0;
        hdr.ipv4.srcAddr = srcAddr;
        hdr.ipv4.dstAddr = dstAddr;

        hdr.inner_udp = hdr.udp;

        hdr.udp.setValid();
        hdr.udp.srcPort = 31249; // True RNG for each remotely forwarded packet
        hdr.udp.dstPort = UDP_PORT_GENEVE;
        hdr.udp.udpLength = HEADER_SIZE_ETH +
                HEADER_SIZE_UDP +
                HEADER_SIZE_GENEVE +
                hdr.inner_ipv4.totalLen;
        hdr.udp.udpChecksum = 0;

        hdr.geneve.setValid();
        hdr.geneve.version = 0;
        hdr.geneve.optionsLength = 0;
        hdr.geneve.O = 0;
        hdr.geneve.C = 0;
        hdr.geneve.reserved = 0;
        hdr.geneve.protocol = TYPE_TRANS_ETHER_BRIDGING;
        hdr.geneve.vni = meta.vni;
        hdr.geneve.reserved2 = 0;

        hdr.inner_ethernet = hdr.ethernet;

        hdr.ethernet.setValid();
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.ethernet.srcAddr = (macAddr_t) srcAddr;
        hdr.ethernet.dstAddr = (macAddr_t) dstAddr;
    }

    action local_digest() {
        digest<local_digest_t>(1, {meta.vni, hdr.ethernet.srcAddr, standard_metadata.ingress_port});
    }

#ifndef NO_ARP_PROXY
    action arp_digest() {
        digest<arp_digest_t>(2, {meta.vni, hdr.arp.senderHwAddr, standard_metadata.ingress_port, hdr.arp.senderIPAddr});
    }
#endif

#ifndef NO_ARP_PROXY
    action arp_respond(macAddr_t dst) {
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = dst;
        hdr.arp.operation = ARP_REPLY;
        hdr.arp.targetHwAddr = hdr.arp.senderHwAddr;
        hdr.arp.senderHwAddr = dst;
        ip4Addr_t temp_ip = hdr.arp.targetIPAddr;
        hdr.arp.targetIPAddr = hdr.arp.senderIPAddr;
        hdr.arp.senderIPAddr = temp_ip;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        meta.is_reply = 1;
    }
#endif

    table egress_dmac_vni {
        key = {
            hdr.geneve.vni: exact;
            hdr.inner_ethernet.dstAddr: exact;
        }
        actions = {
            broadcast;
            local_forward;
        }
        size = 1024;
        default_action = broadcast();
    }

#ifndef NO_REMOTE_DATA_PLANE_LEARNING
    table egress_smac_vni {
        key = {
            hdr.geneve.vni: exact;
            hdr.inner_ethernet.srcAddr: exact;
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            nve_digest;
            NoAction;
        }
        size = 1024;
        default_action = nve_digest();

    }
#endif

    table ingress_port_to_vni {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_ingress_vni;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table ingress_dmac_vni {
        key = {
            meta.vni: exact;
            hdr.ethernet.dstAddr: lpm;
        }
        actions = {
            remote_forward;
            broadcast; // Broadcast locally and remotely
            local_forward;
            drop;
        }
        size = 1024;
#ifndef NO_REMOTE_DATA_PLANE_LEARNING
        default_action = broadcast();
#else
        default_action = broadcast();
#endif
    }

    table ingress_smac_vni {
        key = {
            meta.vni: exact;
            hdr.ethernet.srcAddr: exact;
            standard_metadata.ingress_port: exact;
        }
        actions = {
            local_digest;
            NoAction;
        }
        size = 1024;
        default_action = local_digest();
    }

#ifndef NO_ARP_PROXY
    table arp_smac_sip {
        key = {
            meta.vni: exact;
            hdr.arp.senderHwAddr: exact;
            hdr.arp.senderIPAddr: exact;
        }
        actions = {
            arp_digest;
            NoAction;
        }
        size = 1024;
        default_action = arp_digest();
    }

    table arp_proxy {
        key = {
            meta.vni: exact;
            hdr.arp.targetIPAddr: exact;
        }
        actions = {
            arp_respond;
            drop();
            NoAction;
        }
        size = 1024;
        //default_action = drop();
        default_action = NoAction;
    }
#endif

    apply {
        /*
            Recirculated ingress packet
        */
        if (hdr.geneve.isValid() &&
            hdr.geneve_opt_header.isValid() &&
            hdr.geneve_opt_header.optionClass == GENEVE_EXPERIMENTAL_OPTS_CLASS &&
            hdr.geneve_opt_header.type == GENEVE_IR_OPT &&
            standard_metadata.instance_type != PKT_INSTANCE_TYPE_NORMAL
        ) {
            standard_metadata.egress_spec = PORT_REMOTE;
        }
        /*
            Egress packet (packet from other NVE)
        */
        else if (hdr.geneve.isValid()) {
            meta.is_egress_packet = 1;
            if (hdr.geneve_opt_header.isValid() &&
                hdr.geneve_opt_header.optionClass == GENEVE_EXPERIMENTAL_OPTS_CLASS &&
                hdr.geneve_opt_header.type == GENEVE_IR_OPT
            ) {
                hdr.geneve_opt_header.setInvalid();
                hdr.geneve.optionsLength = hdr.geneve.optionsLength - (bit<6>) GENEVE_IR_OPT_LEN;
            }
            set_meta_vni();
#ifndef NO_REMOTE_DATA_PLANE_LEARNING
            egress_smac_vni.apply();
            egress_dmac_vni.apply();
            decapsulate();
#else
            /*if (egress_dmac_vni.apply().hit) {
                decapsulate();
            }
            else {
                drop();
            }*/
            egress_dmac_vni.apply();
            decapsulate();
#endif
        }
        /*
            Ingress packet (packet from local CE)
        */
        else {
            /*
                Only process incoming packets which map to a VNI
            */
            if (ingress_port_to_vni.apply().hit) {
                /*
                    Always perform MAC learning
                */
                ingress_smac_vni.apply();
                /*
                    Intercept ARP packets
                */
#ifndef NO_ARP_PROXY
                if (hdr.arp.isValid()) {
                    arp_smac_sip.apply();
                    /*
                        Intercept ARP request and respond to it
                        if entry is present in arp_proxy table;
                        otherwise forward it based on ingress_dmac_vni table
                    */
                    if (hdr.arp.operation == ARP_REQUEST) {
                        if (!arp_proxy.apply().hit) {
                            ingress_dmac_vni.apply();
                        }
                    }
                    /*
                        Forward other ARP operations normally
                    */
                    else {
                        ingress_dmac_vni.apply();
                    }
                }
                else {
                    ingress_dmac_vni.apply();
                }
#else
                ingress_dmac_vni.apply();
#endif
            }
            else {
                drop();
            }
        }
    }
}

control GeneveComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {   hdr.ipv4.version,
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
            HashAlgorithm.csum16);
    }
}

control GeneveEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
#ifndef NO_REMOTE_FLOOD
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action remote_forward(ip4Addr_t dstAddr) {
        hdr.ipv4.dstAddr = dstAddr;
        hdr.ethernet.dstAddr = (macAddr_t) dstAddr;
    }

    action remote_broadcast(ip4Addr_t srcAddr) {
        hdr.inner_ipv4 = hdr.ipv4;

        hdr.ipv4.setValid();
        hdr.ipv4.version = 4; // IPv4
        hdr.ipv4.ihl = 5;
        hdr.ipv4.diffserv = 0;
        hdr.ipv4.totalLen = HEADER_SIZE_ETH +
                HEADER_SIZE_IPV4 +
                HEADER_SIZE_UDP +
                HEADER_SIZE_GENEVE +
                hdr.inner_ipv4.totalLen;
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 2; // Don't fragment
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.ttl = 0xFF;
        hdr.ipv4.protocol = IP_PROTO_UDP;
        hdr.ipv4.hdrChecksum = 0;
        hdr.ipv4.srcAddr = srcAddr;
        hdr.ipv4.dstAddr = (ip4Addr_t) 0;

        hdr.inner_udp = hdr.udp;

        hdr.udp.setValid();
        hdr.udp.srcPort = 31249; // True RNG for each remotely forwarded packet
        hdr.udp.dstPort = UDP_PORT_GENEVE;
        hdr.udp.udpLength = HEADER_SIZE_ETH +
                HEADER_SIZE_UDP +
                HEADER_SIZE_GENEVE +
                hdr.inner_ipv4.totalLen;
        hdr.udp.udpChecksum = 0;

        hdr.geneve.setValid();
        hdr.geneve.version = 0;
        hdr.geneve.optionsLength = 1;
        hdr.geneve.O = 0;
        hdr.geneve.C = 0;
        hdr.geneve.reserved = 0;
        hdr.geneve.protocol = TYPE_TRANS_ETHER_BRIDGING;
        hdr.geneve.vni = meta.vni;
        hdr.geneve.reserved2 = 0;

        hdr.geneve_opt_header.setValid();
        hdr.geneve_opt_header.optionClass = GENEVE_EXPERIMENTAL_OPTS_CLASS;
        hdr.geneve_opt_header.type = GENEVE_IR_OPT;
        hdr.geneve_opt_header.reserved = 0;
        hdr.geneve_opt_header.length = 0;

        hdr.inner_ethernet = hdr.ethernet;

        hdr.ethernet.setValid();
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.ethernet.srcAddr = (macAddr_t) srcAddr;
    }

    table remote_nexthop {
        key = {
            hdr.geneve.vni: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            remote_forward;
            drop();
        }
        size = 1024;
        default_action = drop();
    }

    table nve_broadcast {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            remote_broadcast;
            drop();
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (standard_metadata.egress_port == PORT_REMOTE_BROADCAST) {
            if (meta.is_egress_packet == 1) {
                drop();
            }
            else if (nve_broadcast.apply().hit) {
                recirculate({});
            }
        }
        else if (hdr.geneve_opt_header.isValid() &&
                hdr.geneve_opt_header.optionClass == GENEVE_EXPERIMENTAL_OPTS_CLASS &&
                hdr.geneve_opt_header.type == GENEVE_IR_OPT
        ) {
            if (standard_metadata.egress_port == PORT_REMOTE) {
                if (remote_nexthop.apply().hit) {
                    clone(CloneType.E2E, 1);
                }
                else {
                    drop();
                }
            }
        }
    }
#else
    apply {}
#endif
}
