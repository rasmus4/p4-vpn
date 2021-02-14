/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const mcastGroup_t MCAST_BROADCAST = 0x01;

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

struct L2_digest {
    macAddr_t smac;
    egressSpec_t in_port;
}

control L2Ingress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action l2_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action broadcast() {
        standard_metadata.mcast_grp = MCAST_BROADCAST;
    }

    action l2_digest() {
        digest<L2_digest>(1, {hdr.ethernet.srcAddr, standard_metadata.ingress_port});
    }

    action l2_check_smac(ingressSpec_t port) {
        if (port == standard_metadata.ingress_port) {
            digest<L2_digest>(1, {hdr.ethernet.srcAddr, standard_metadata.ingress_port});
        }
    }

    table smac {
        key = {
            hdr.ethernet.srcAddr: exact;
            standard_metadata.ingress_port: exact;
        }
        actions = {
            l2_digest;
            NoAction;
        }
        size = 1024;
        default_action = l2_digest();
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            broadcast;
            l2_forward;
        }
        size = 1024;
        default_action = broadcast();
    }

    apply {
        if (hdr.ethernet.isValid()) {
            smac.apply();
            dmac.apply();
        }
        else {
            broadcast();
        }
    }
}