#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <fstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <cstring>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

char mac[18];

void usage() {
    printf("syntax: tcp-block <interface> <pattern>\n");
    printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool get_s_mac(const char* dev, char* mac) {
    std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
    if (!mac_file.is_open()) return false;
    mac_file >> mac;
    return true;
}

uint16_t checksum(uint16_t* ptr, int len){
    uint32_t sum = 0;
    uint16_t odd = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        *(uint8_t *)(&odd) = (*(uint8_t *)ptr);
        sum += odd;
    }
    if (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

void send_packet(pcap_t* handle, const char* dev, EthHdr* eth, IpHdr* ip, TcpHdr* tcp, const char* payload, int recv_len, bool is_forward) {
    int eth_len = sizeof(EthHdr);
    int ip_len = sizeof(IpHdr);
    int tcp_len = sizeof(TcpHdr);
    int payload_len = strlen(payload);
    int packet_len = eth_len + ip_len + tcp_len + payload_len;

    EthHdr new_eth;
    IpHdr new_ip;
    TcpHdr new_tcp;

    memcpy(&new_eth, eth, eth_len);
    if (!is_forward)
        new_eth.dmac_ = eth->smac_;
    new_eth.smac_ = Mac(mac);

    memcpy(&new_ip, ip, ip_len);
    if (!is_forward) {
        new_ip.sip_ = ip->dip_;
        new_ip.dip_ = ip->sip_;
        new_ip.ttl = 128;
    }
    new_ip.checksum = 0;
    new_ip.total_length = htons(ip_len + tcp_len + payload_len);
    new_ip.checksum = checksum((uint16_t*)&new_ip, ip_len);

    memcpy(&new_tcp, tcp, tcp_len);
    if (is_forward) {
        new_tcp.flags_ = TcpHdr::RST | TcpHdr::ACK;
        new_tcp.seq_ = htonl(ntohl(tcp->seq_) + recv_len);
    } else {
        new_tcp.sport_ = tcp->dport_;
        new_tcp.dport_ = tcp->sport_;
        new_tcp.flags_ = TcpHdr::PSH | TcpHdr::ACK;
        new_tcp.seq_ = tcp->ack_;
        new_tcp.ack_ = htonl(ntohl(tcp->seq_) + recv_len);
    }
    new_tcp.hlen_ = (sizeof(TcpHdr) / 4) << 4;
    new_tcp.win_ = htons(1024);
    new_tcp.urp_ = 0;
    new_tcp.sum_ = 0;

    struct pseudo_header {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } psh;

    psh.source_address = new_ip.sip_;
    psh.dest_address = new_ip.dip_;
    psh.placeholder = 0;
    psh.protocol = IpHdr::TCP;
    psh.tcp_length = htons(tcp_len + payload_len);

    int buffer_len = sizeof(psh) + tcp_len + payload_len;
    char *buffer = (char *)malloc(buffer_len);
    memcpy(buffer, &psh, sizeof(psh));
    memcpy(buffer + sizeof(psh), &new_tcp, tcp_len);
    memcpy(buffer + sizeof(psh) + tcp_len, payload, payload_len);
    new_tcp.sum_ = checksum((uint16_t*)buffer, buffer_len);

    char *packet = (char *)malloc(packet_len);
    memcpy(packet, &new_eth, eth_len);
    memcpy(packet + eth_len, &new_ip, ip_len);
    memcpy(packet + eth_len + ip_len, &new_tcp, tcp_len);
    memcpy(packet + eth_len + ip_len + tcp_len, payload, payload_len);

    if (!is_forward) {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) return;

        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = new_tcp.sport_;
        sin.sin_addr.s_addr = new_ip.sip_;

        char optval = 0x01;
        setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
        sendto(sockfd, packet + eth_len, packet_len - eth_len, 0, (struct sockaddr *)&sin, sizeof(sin));
        close(sockfd);
    } else {
        pcap_sendpacket(handle, (const u_char*)packet, packet_len);
    }
    free(buffer);
    free(packet);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    const char* dev = argv[1];
    const char* pattern = argv[2];

    while (!get_s_mac(dev, mac)) {
        printf("Failed to get source MAC address\n");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Ip4) continue;

        IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));
        if (ip->protocol != IpHdr::TCP) continue;

        TcpHdr* tcp = (TcpHdr*)(packet + sizeof(EthHdr) + ip->header_len());
        int eth_len = sizeof(EthHdr);
        int ip_len = ip->header_len();
        int tcp_len = tcp->header_len();
        int payload_len = ntohs(ip->total_length) - ip_len - tcp_len;
        const char* payload = (const char*)(packet + eth_len + ip_len + tcp_len);

        if (strncmp(payload, "GET", 3) != 0) continue;
        if (memmem(payload, payload_len, pattern, strlen(pattern)) == nullptr) continue;

        printf("Blocking %s\n", pattern);
        send_packet(handle, dev, eth, ip, tcp, "", payload_len, true);
        usleep(50000);
        send_packet(handle, dev, eth, ip, tcp, "HTTP/1.1 302 Found\r\nLocation: http://warning.or.kr\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", payload_len, false);
    }

    pcap_close(handle);
    return 0;
}

