#pragma once
#include <cstdint>
#include <arpa/inet.h>

struct TcpHdr final {
    uint16_t sport_;   // Source port
    uint16_t dport_;   // Destination port
    uint32_t seq_;     // Sequence number
    uint32_t ack_;     // Acknowledgment number
    uint8_t  hlen_;    // Data offset (upper 4 bits), Reserved (lower 4 bits)
    uint8_t  flags_;   // Flags
    uint16_t win_;     // Window size
    uint16_t sum_;     // Checksum
    uint16_t urp_;     // Urgent pointer

    enum : uint8_t {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PSH = 0x08,
        ACK = 0x10,
        URG = 0x20,
        ECE = 0x40,
        CWR = 0x80
    };

    uint8_t header_len() const { return (hlen_ >> 4) * 4; }
};
