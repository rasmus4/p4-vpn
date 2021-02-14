/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/*
    Constants for v1model
*/
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

/*
    EtherTypes
*/
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;
const bit<16> TYPE_TRANS_ETHER_BRIDGING = 0x6558;

const bit<8> IP_PROTO_UDP = 0x11;

const bit<16> UDP_PORT_GENEVE = 6081;

/*
    Geneve
*/
const bit<16> GENEVE_EXPERIMENTAL_OPTS_CLASS = 0xFF00;
const bit<8> GENEVE_IR_OPT = 0x00;
const bit<5> GENEVE_IR_OPT_LEN = 1;

/*
    ARP OPcodes
*/
const bit<16> ARP_REQUEST = 0x1;
const bit<16> ARP_REPLY = 0x2;


/*
    Header sizes
*/
const bit<16> HEADER_SIZE_UDP = 8;
const bit<16> HEADER_SIZE_GENEVE = 8;
const bit<16> HEADER_SIZE_IPV4 = 20;
const bit<16> HEADER_SIZE_ETH = 14;

typedef bit<9>  egressSpec_t;
typedef bit<9>  ingressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGroup_t;
typedef bit<24> vni_t;

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

header udp_t {
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<16>   udpLength;
    bit<16>   udpChecksum;
}

header geneve_t {
    bit<2>    version;
    bit<6>    optionsLength;
    bit<1>    O;
    bit<1>    C;
    bit<6>    reserved;
    bit<16>   protocol;
    vni_t     vni;
    bit<8>    reserved2;
}

header geneve_opt_header_t {
    bit<16>   optionClass;
    bit<8>    type;
    bit<3>    reserved;
    bit<5>    length;
}

header arp_t {
    bit<16>   hardwareType;
    bit<16>   protocolType;
    bit<8>    hardwareLength;
    bit<8>    protocolLength;
    bit<16>   operation;
    macAddr_t senderHwAddr;
    ip4Addr_t senderIPAddr;
    macAddr_t targetHwAddr;
    ip4Addr_t targetIPAddr;
}

struct metadata {
    vni_t     vni;
    bit<4>    is_reply;
    bit<4>    is_egress_packet;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    geneve_t     geneve;
    geneve_opt_header_t geneve_opt_header;
    ethernet_t   inner_ethernet;
    ipv4_t       inner_ipv4;
    udp_t        inner_udp;
    arp_t        arp;
}