#include <netinet/in.h>
#include "ip.h"

struct IpHdr final {
    u_int8_t ip_hl:4, ip_v:4;
    uint8_t dscp_and_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t sip_;
    uint32_t dip_;

    Ip sip() { return Ip(ntohl(sip_)); }
    Ip dip() { return Ip(ntohl(dip_)); }
    uint16_t header_len() { return ip_hl * 4; }

    // Protocol(ip_protocol)
    enum: uint8_t {
        ICMP = 1,
        IGMP = 2,
        TCP = 6,
        IGRP = 9,
        UDP = 17,
        GRE = 47,
        ESP = 50,
        AH = 51,
        SKIP = 57,
        EIGRP = 88,
        OSPF = 89,
        L2TP = 115
    };
};