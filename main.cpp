#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <fstream>
#include <sys/socket.h>
#include <cstring>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

// 인터페이스 MAC 문자열을 저장할 버퍼
static char mac[18];

// 302 Redirect 페이로드
static constexpr char REDIRECT_PAYLOAD[] =
    "HTTP/1.1 302 Found\r\n"
    "Location: http://warning.or.kr\r\n"
    "Content-Length: 0\r\n"
    "Connection: close\r\n"
    "\r\n";

// pseudo-header 구조체 (TCP 체크섬 계산용)
struct PseudoHeader {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

// 사용법 출력
void usage() {
    std::cout << "syntax: tcp-block <interface> <pattern>\n";
    std::cout << "sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n";
}

// "/sys/class/net/<dev>/address" 파일에서 MAC 문자열을 읽어오는 함수
bool get_interface_mac(const char* dev, char* mac_buf) {
    std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
    if (!mac_file.is_open()) {
        return false;
    }
    mac_file >> mac_buf;
    return true;
}

// 단순 16비트 체크섬 계산 (IP 헤더 등에서 사용)
static uint16_t checksum16(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
    while (len > 1) {
        sum += ntohs(*ptr++);
        if (sum & 0x10000) {
            sum = (sum & 0xFFFF) + 1;
        }
        len -= 2;
    }
    if (len == 1) {
        uint16_t last = static_cast<uint16_t>(data[len - 1] << 8);
        sum += ntohs(last);
        if (sum & 0x10000) {
            sum = (sum & 0xFFFF) + 1;
        }
    }
    return htons(static_cast<uint16_t>(~sum & 0xFFFF));
}

// TCP 체크섬 계산: pseudo-header + TCP 헤더 + 페이로드
static uint16_t compute_tcp_checksum(const IpHdr* ip, const TcpHdr* tcp, const char* payload, int payload_len) {
    // pseudo-header 생성
    PseudoHeader psh;
    psh.source_address = ip->sip_;
    psh.dest_address   = ip->dip_;
    psh.placeholder    = 0;
    psh.protocol       = IPPROTO_TCP;
    psh.tcp_length     = htons(static_cast<uint16_t>(sizeof(TcpHdr) + payload_len));

    // 버퍼 길이: pseudo-header + TCP 헤더 + 페이로드
    int psize = sizeof(PseudoHeader) + sizeof(TcpHdr) + payload_len;
    uint8_t* buf = static_cast<uint8_t*>(malloc(psize));
    memset(buf, 0, psize);

    // 1) pseudo-header 복사
    memcpy(buf, &psh, sizeof(PseudoHeader));

    // 2) TCP 헤더 복사
    memcpy(buf + sizeof(PseudoHeader), tcp, sizeof(TcpHdr));

    // 3) Payload 복사
    if (payload_len > 0) {
        memcpy(buf + sizeof(PseudoHeader) + sizeof(TcpHdr), payload, payload_len);
    }

    // 4) 체크섬 계산
    uint16_t chk = checksum16(buf, psize);
    free(buf);
    return chk;
}

// 패킷 조립 및 전송
//   is_forward == true  : 클라이언트→서버 (RST+ACK)
//   is_forward == false : 서버→클라이언트 (PSH+ACK + 302 Redirect 페이로드)
static void send_packet(pcap_t* handle,
                        const EthHdr* orig_eth,
                        const IpHdr* orig_ip,
                        const TcpHdr* orig_tcp,
                        const char* payload,
                        int recv_len,
                        bool is_forward)
{
    const int ETH_LEN     = sizeof(EthHdr);
    const int IP_LEN      = sizeof(IpHdr);
    const int TCP_LEN     = sizeof(TcpHdr);
    const int PAYLOAD_LEN = static_cast<int>(strlen(payload));
    const int PACKET_LEN  = ETH_LEN + IP_LEN + TCP_LEN + PAYLOAD_LEN;

    // 새로운 이더넷 / IP / TCP 헤더
    EthHdr new_eth = *orig_eth;
    IpHdr  new_ip  = *orig_ip;
    TcpHdr new_tcp = *orig_tcp;

    // 1) 이더넷 헤더 설정
    if (!is_forward) {
        // 서버→클라이언트: 원래의 클라이언트 MAC(=orig_eth->smac_)을 dst로 설정
        new_eth.dmac_ = orig_eth->smac_;
    }
    // src MAC은 항상 우리 인터페이스 MAC
    new_eth.smac_ = Mac(mac);

    // 2) IP 헤더 설정
    if (!is_forward) {
        // 서버→클라이언트: IP src/dst 뒤집기 + TTL 높이기
        new_ip.sip_ = orig_ip->dip_;
        new_ip.dip_ = orig_ip->sip_;
        new_ip.ttl  = 128;
    }
    new_ip.checksum = 0;
    new_ip.total_length = htons(static_cast<uint16_t>(IP_LEN + TCP_LEN + PAYLOAD_LEN));
    new_ip.checksum = checksum16(reinterpret_cast<const uint8_t*>(&new_ip), IP_LEN);

    // 3) TCP 헤더 설정
    if (is_forward) {
        // 클라이언트→서버: RST+ACK
        new_tcp.flags_ = TcpHdr::RST | TcpHdr::ACK;
        new_tcp.seq_   = htonl(ntohl(orig_tcp->seq_) + recv_len);
        // new_tcp.ack_는 orig_tcp->ack_를 유지
    } else {
        // 서버→클라이언트: PSH+ACK + 302 Redirect 페이로드
        new_tcp.sport_ = orig_tcp->dport_;
        new_tcp.dport_ = orig_tcp->sport_;
        new_tcp.flags_ = TcpHdr::PSH | TcpHdr::ACK;
        new_tcp.seq_   = orig_tcp->ack_;
        new_tcp.ack_   = htonl(ntohl(orig_tcp->seq_) + recv_len);
    }
    new_tcp.hlen_ = static_cast<uint8_t>((TCP_LEN / 4) << 4);
    new_tcp.win_  = htons(1024);
    new_tcp.urp_  = 0;
    new_tcp.sum_  = 0;
    // pseudo-header 포함 TCP 체크섬 계산
    new_tcp.sum_ = compute_tcp_checksum(&new_ip, &new_tcp, payload, PAYLOAD_LEN);

    // 4) 전체 패킷 메모리 할당 및 복사
    uint8_t* packet = static_cast<uint8_t*>(malloc(PACKET_LEN));
    memcpy(packet,                       &new_eth, ETH_LEN);
    memcpy(packet + ETH_LEN,             &new_ip,  IP_LEN);
    memcpy(packet + ETH_LEN + IP_LEN,    &new_tcp, TCP_LEN);
    if (PAYLOAD_LEN > 0) {
        memcpy(packet + ETH_LEN + IP_LEN + TCP_LEN, payload, PAYLOAD_LEN);
    }

    // 5) 실제 전송
    if (!is_forward) {
        // 서버→클라이언트: raw 소켓(IP_HDRINCL)
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd >= 0) {
            struct sockaddr_in sin{};
            sin.sin_family      = AF_INET;
            sin.sin_port        = new_tcp.sport_;
            sin.sin_addr.s_addr = new_ip.sip_;

            int optval = 1;
            setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
            sendto(sockfd,
                   packet + ETH_LEN,
                   PACKET_LEN - ETH_LEN,
                   0,
                   reinterpret_cast<struct sockaddr*>(&sin),
                   sizeof(sin));
            close(sockfd);
        }
    } else {
        // 클라이언트→서버: pcap_sendpacket
        if (pcap_sendpacket(handle, packet, PACKET_LEN) != 0) {
            fprintf(stderr, "pcap_sendpacket() failed: %s\n", pcap_geterr(handle));
        }
    }

    free(packet);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return EXIT_FAILURE;
    }

    const char* dev     = argv[1];
    const char* pattern = argv[2];

    // 인터페이스 MAC 읽기
    while (!get_interface_mac(dev, mac)) {
        fprintf(stderr, "Failed to read MAC from %s\n", dev);
        sleep(1);
    }

    // pcap 핸들 열기
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    struct pcap_pkthdr* header;
    const u_char* packet_data;

    // 패킷 캡처 루프
    while (true) {
        int res = pcap_next_ex(handle, &header, &packet_data);
        if (res == 0) continue;
        if (res < 0) {
            fprintf(stderr, "pcap_next_ex() error: %s\n", pcap_geterr(handle));
            break;
        }

        // 이더넷 헤더
        const EthHdr* eth = reinterpret_cast<const EthHdr*>(packet_data);
        if (eth->type() != EthHdr::Ip4) continue;

        // IP 헤더
        const IpHdr* ip = reinterpret_cast<const IpHdr*>(packet_data + sizeof(EthHdr));
        if (ip->protocol != IpHdr::TCP) continue;

        // TCP 헤더 + 페이로드
        const TcpHdr* tcp = reinterpret_cast<const TcpHdr*>(packet_data + sizeof(EthHdr) + ip->header_len());
        int eth_len     = sizeof(EthHdr);
        int ip_len      = ip->header_len();
        int tcp_len     = tcp->header_len();
        int payload_len = ntohs(ip->total_length) - ip_len - tcp_len;
        if (payload_len <= 0) continue;

        const char* payload = reinterpret_cast<const char*>(packet_data + eth_len + ip_len + tcp_len);
        // GET 요청인지 확인
        if (strncmp(payload, "GET", 3) != 0) continue;
        // Host 헤더에 패턴이 포함되어 있는지 검사
        if (memmem(payload, payload_len, pattern, strlen(pattern)) == nullptr) continue;

        printf("=== 사이트 차단: %s ===\n", pattern);

        // (A) 서버→클라이언트: PSH+ACK + 302 Redirect
        send_packet(handle,
                    eth,
                    ip,
                    tcp,
                    REDIRECT_PAYLOAD,
                    payload_len,
                    /*is_forward=*/ false);

        // (B) 클라이언트→서버: RST+ACK
        send_packet(handle,
                    eth,
                    ip,
                    tcp,
                    /*payload=*/ "",
                    payload_len,
                    /*is_forward=*/ true);
    }

    pcap_close(handle);
    return EXIT_SUCCESS;
}
