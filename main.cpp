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
#include <cstdio>
#include <cstdlib>
#include <cctype>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

// 전역 변수: 인터페이스의 MAC 주소를 문자열로 저장
char mac[18];

void usage() {
    printf("syntax: tcp-block <interface> <pattern>\n");
    printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

// 인터페이스 이름(dev)에서 MAC 주소를 /sys/class/net/.../address 파일을 읽어 가져옴
bool get_s_mac(const char* dev, char* mac_out) {
    std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
    if (!mac_file.is_open()) {
        return false;
    }
    mac_file >> mac_out;
    return true;
}

// Internet checksum 계산 (RFC 1071)
uint16_t checksum(uint16_t* ptr, int len){
    uint32_t sum = 0;
    uint16_t odd = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        *(uint8_t *)(&odd) = *(uint8_t *)ptr;
        sum += odd;
    }

    // carry 처리
    if (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}

// TCP 체크섬 계산 함수 (pseudo header 없이)
uint16_t tcp_checksum(IpHdr* ip, TcpHdr* tcp, const char* payload, int payload_len) {
    uint32_t sum = 0;

    // IP src/dst 주소를 합산
    sum += (ip->sip_ >> 16) & 0xFFFF;
    sum += ip->sip_ & 0xFFFF;
    sum += (ip->dip_ >> 16) & 0xFFFF;
    sum += ip->dip_ & 0xFFFF;

    // Protocol (TCP)과 TCP 길이를 합산
    sum += htons(IpHdr::TCP);
    sum += htons(sizeof(TcpHdr) + payload_len);

    // TCP 헤더를 합산
    uint16_t* tcp_ptr = (uint16_t*)tcp;
    for (int i = 0; i < sizeof(TcpHdr) / 2; i++) {
        sum += *tcp_ptr++;
    }

    // 페이로드를 합산
    const uint16_t* payload_ptr = (const uint16_t*)payload;
    for (int i = 0; i < payload_len / 2; i++) {
        sum += *payload_ptr++;
    }

    // 페이로드 길이가 홀수일 경우 마지막 바이트 처리
    if (payload_len % 2 == 1) {
        sum += *(const uint8_t*)payload_ptr;
    }

    // Carry 처리
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

// 패킷 전송 함수
// handle: pcap handle
// dev: 송신 인터페이스 이름
// eth, ip, tcp: 캡처된 원본 패킷의 EthHdr, IpHdr, TcpHdr 구조체 포인터
// payload: 보낼 페이로드 문자열 (빈 문자열("")이면 페이로드 없음)
// recv_len: 원본 페이로드 길이 (RST/FIN 시퀀스 계산용)
// is_forward: true면 "클라이언트→서버(RST)", false면 "서버→클라이언트(FIN+Redirect)"
void send_packet(pcap_t* handle, const char* dev,
                 EthHdr* eth, IpHdr* ip, TcpHdr* tcp,
                 const char* payload, int recv_len, bool is_forward) 
{
    int eth_len = sizeof(EthHdr);
    int ip_len = sizeof(IpHdr);
    int tcp_len = sizeof(TcpHdr);
    int payload_len = strlen(payload);
    int packet_len = eth_len + ip_len + tcp_len + payload_len;

    // 새로운 헤더 구조체에 기존 헤더 복사
    EthHdr new_eth;
    IpHdr new_ip;
    TcpHdr new_tcp;

    // Ethernet 헤더 구성
    memcpy(&new_eth, eth, eth_len);
    if (!is_forward) {
        new_eth.dmac_ = eth->smac_;
    }
    new_eth.smac_ = Mac(mac);

    // IP 헤더 구성
    memcpy(&new_ip, ip, ip_len);
    if (!is_forward) {
        new_ip.sip_ = ip->dip_;
        new_ip.dip_ = ip->sip_;
        new_ip.ttl = 64;
    }
    new_ip.total_length = htons(ip_len + tcp_len + payload_len);
    new_ip.checksum = 0;
    new_ip.checksum = checksum((uint16_t*)&new_ip, ip_len);

    // TCP 헤더 구성
    memcpy(&new_tcp, tcp, tcp_len);
    if (is_forward) {
        // 정방향(RST): 클라이언트→서버
        new_tcp.flags_ = TcpHdr::RST | TcpHdr::ACK;
        // RST 시퀀스 = 원본 seq + 원래 페이로드 길이
        new_tcp.seq_ = htonl(ntohl(tcp->seq_) + recv_len);
        // ACK는 0으로 놔도 핸드쉐이크를 끊는 데 무방
        new_tcp.ack_ = 0;
        // 소스/목적지 포트는 그대로
    } else {
        // 역방향(FIN+Redirect): 서버→클라이언트
        new_tcp.sport_ = tcp->dport_;
        new_tcp.dport_ = tcp->sport_;
        new_tcp.flags_ = TcpHdr::FIN | TcpHdr::PSH | TcpHdr::ACK;
        // FIN seq = 원본 ack (클라이언트가 보낸 데이터에 대한 서버의 다음 seq)
        new_tcp.seq_ = tcp->ack_;
        // ACK = 원본 seq + 원래 페이로드 길이
        new_tcp.ack_ = htonl(ntohl(tcp->seq_) + recv_len);
    }
    // TCP 헤더 길이(20바이트) 설정
    new_tcp.hlen_ = (tcp_len / 4) << 4;
    new_tcp.win_ = htons(0);
    new_tcp.urp_ = 0;
    new_tcp.sum_ = 0;

    // TCP 체크섬 계산
    new_tcp.sum_ = tcp_checksum(&new_ip, &new_tcp, payload, payload_len);

    // 최종 패킷 버퍼에 Ethernet, IP, TCP, 페이로드 순으로 복사
    char *packet = (char*)malloc(packet_len);
    memcpy(packet, &new_eth, eth_len);
    memcpy(packet + eth_len, &new_ip, ip_len);
    memcpy(packet + eth_len + ip_len, &new_tcp, tcp_len);
    memcpy(packet + eth_len + ip_len + tcp_len, payload, payload_len);


    if (!is_forward) {
        // 역방향: raw socket으로 IP 헤더 포함 송신 (Ethernet 헤더 제외)
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) {
            fprintf(stderr, "socket error: %s\n", strerror(errno));
            free(packet);
            return;
        }
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = new_tcp.sport_;
        sin.sin_addr.s_addr = new_ip.dip_;

        int hdrincl = 1;
        setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl));

        // Ethernet 헤더 크기만큼 오프셋을 주고 sendto
        if (sendto(sockfd, packet + eth_len, packet_len - eth_len, 0,
                   (struct sockaddr*)&sin, sizeof(sin)) < 0) {
            perror("sendto (raw) failed");
        }
        close(sockfd);
    } else {
        // 정방향: pcap_sendpacket으로 Ethernet 포함 송신
        if (pcap_sendpacket(handle, (const u_char*)packet, packet_len) != 0) {
            fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
        }
    }

    free(packet);
}

// RST 패킷을 서버→클라이언트로 보내는 함수 (ACK 번호를 정확히 맞춤)
void send_rst_to_client(const char* dev, EthHdr* eth, IpHdr* ip, TcpHdr* tcp, int payload_len) {
    int eth_len = sizeof(EthHdr);
    int ip_len = sizeof(IpHdr);
    int tcp_len = sizeof(TcpHdr);
    int packet_len = eth_len + ip_len + tcp_len;

    EthHdr new_eth;
    IpHdr new_ip;
    TcpHdr new_tcp;

    // Ethernet 헤더: src/dst MAC swap
    memcpy(&new_eth, eth, eth_len);
    new_eth.dmac_ = eth->smac_;
    new_eth.smac_ = Mac(mac);

    // IP 헤더: src/dst IP swap
    memcpy(&new_ip, ip, ip_len);
    new_ip.sip_ = ip->dip_;
    new_ip.dip_ = ip->sip_;
    new_ip.ttl = 64;
    new_ip.total_length = htons(ip_len + tcp_len);
    new_ip.checksum = 0;
    new_ip.checksum = checksum((uint16_t*)&new_ip, ip_len);

    // TCP 헤더: src/dst port swap, seq=ack, ack=seq+payload_len, RST+ACK flag
    memcpy(&new_tcp, tcp, tcp_len);
    new_tcp.sport_ = tcp->dport_;
    new_tcp.dport_ = tcp->sport_;
    new_tcp.flags_ = TcpHdr::RST | TcpHdr::ACK;
    new_tcp.seq_ = tcp->ack_; // 서버가 기대하는 seq
    new_tcp.ack_ = htonl(ntohl(tcp->seq_) + payload_len); // 클라이언트가 보낸 데이터 끝
    new_tcp.hlen_ = (tcp_len / 4) << 4;
    new_tcp.win_ = htons(0);
    new_tcp.urp_ = 0;
    new_tcp.sum_ = 0;

    // TCP 체크섬 계산 (pseudo_header 없이)
    new_tcp.sum_ = tcp_checksum(&new_ip, &new_tcp, nullptr, 0);

    // 최종 패킷 버퍼
    char *packet = (char*)malloc(packet_len);
    memcpy(packet, &new_eth, eth_len);
    memcpy(packet + eth_len, &new_ip, ip_len);
    memcpy(packet + eth_len + ip_len, &new_tcp, tcp_len);

    // raw socket으로 IP 헤더 포함 송신 (Ethernet 헤더 제외)
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        fprintf(stderr, "socket error: %s\n", strerror(errno));
        free(packet);
        return;
    }
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = new_tcp.sport_;
    sin.sin_addr.s_addr = new_ip.dip_;

    int hdrincl = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl));

    if (sendto(sockfd, packet + eth_len, packet_len - eth_len, 0,
               (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("sendto (raw) failed");
    }
    close(sockfd);
    free(packet);
}

// 메인
int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    const char* dev = argv[1];
    const char* pattern = argv[2];
    size_t pattern_len = strlen(pattern);

    // 1) 인터페이스의 MAC 주소를 얻어올 때까지 반복
    while (!get_s_mac(dev, mac)) {
        printf("Failed to get source MAC address for %s\n", dev);
        sleep(1);
    }

    // 2) pcap 초기화 (PROMISCUOUS 모드, timeout=1000ms)
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
        return -1;
    }

    printf("[INFO] Listening on interface \"%s\", blocking pattern: \"%s\"\n", dev, pattern);
    printf("[INFO] Press Ctrl+C to quit.\n");

    struct pcap_pkthdr* header;
    const u_char* packet;

    // 역방향(FIN+Redirect)을 보낼 때 사용할 HTTP 302 payload (HTTP/1.1 표준 형태)
    const char* http_redirect =
        "HTTP/1.1 302 Found\r\n"
        "Location: http://warning.or.kr\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n";

    // 3) 무한 루프: 패킷 캡처 & 처리
    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d: %s\n", res, pcap_geterr(handle));
            break;
        }

        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Ip4) continue;

        IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));
        if (ip->protocol != IpHdr::TCP) continue;

        TcpHdr* tcp = (TcpHdr*)(packet + sizeof(EthHdr) + ip->header_len());
        int eth_len = sizeof(EthHdr);
        int ip_len = ip->header_len();
        int tcp_len = tcp->header_len();
        int payload_len = ntohs(ip->total_length) - ip_len - tcp_len;
        if (payload_len <= 0) continue;

        const char* payload = (const char*)(packet + eth_len + ip_len + tcp_len);

        // 4) “GET” 요청인지 확인 (클라이언트→서버 HTTP 요청만 차단)
        if (strncmp(payload, "GET", 3) != 0) continue;

        // 5) 패턴이 payload 전체에 포함되어 있는지 검사
        bool matched = false;
        for (int i = 0; i + (int)pattern_len <= payload_len; i++) {
            if (memcmp(payload + i, pattern, pattern_len) == 0) {
                matched = true;
                break;
            }
        }
        if (!matched) continue;

        // 디버그 출력
        char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->sip_, sip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->dip_, dip, INET_ADDRSTRLEN);
        printf("[DEBUG] Block pattern \"%s\" in payload: %s:%u → %s:%u | payload_len=%d\n",
               pattern,
               sip, ntohs(tcp->sport_),
               dip, ntohs(tcp->dport_),
               payload_len);

        // 6) 1차: 정방향(RST) 패킷 전송 → 클라이언트→서버 연결 강제 종료
        send_packet(handle, dev, eth, ip, tcp, "", payload_len, true);

        // 7) 짧은 딜레이(5ms) 후 역방향(FIN+Redirect) 전송
        usleep(5000);
        send_packet(handle, dev, eth, ip, tcp, http_redirect, payload_len, false);

        // 8) 추가: 서버→클라이언트로 RST 패킷도 전송 (브라우저가 302를 확실히 처리하게 함)
        usleep(1000);
        send_rst_to_client(dev, eth, ip, tcp, payload_len);
    }

    pcap_close(handle);
    return 0;
}
