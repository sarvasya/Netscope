#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace netscope {

constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_ARP  = 0x0806;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;  // 802.1Q
constexpr uint16_t ETHERTYPE_QINQ = 0x88A8;  // 802.1ad
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;

constexpr uint8_t IPPROTO_ICMP_ = 1;
constexpr uint8_t IPPROTO_TCP_  = 6;
constexpr uint8_t IPPROTO_UDP_  = 17;

struct MacAddress {
    std::array<uint8_t, 6> b{};
    std::string str() const;
    bool isBroadcast() const;
    bool operator==(const MacAddress& o) const { return b == o.b; }
    bool operator<(const MacAddress& o) const { return b < o.b; }
};

struct EthernetHeader {
    MacAddress dst, src;
    uint16_t ethertype = 0;               // after any VLAN tag
    std::optional<uint16_t> vlan_id;
};

struct IPv4Header {
    uint8_t version = 0, ihl = 0;         // ihl in 32-bit words
    uint8_t dscp = 0, ecn = 0;
    uint16_t total_length = 0, identification = 0;
    bool flag_df = false, flag_mf = false;
    uint16_t frag_offset = 0;             // in 8-byte units
    uint8_t ttl = 0, protocol = 0;
    uint16_t checksum = 0;
    bool checksum_ok = false;
    uint32_t src = 0, dst = 0;
    size_t header_len() const { return size_t(ihl) * 4; }
};

struct TransportInfo {
    enum class Kind { TCP, UDP, ICMP } kind = Kind::TCP;
    uint16_t src_port = 0, dst_port = 0;  // TCP / UDP
    uint32_t seq = 0, ack = 0;            // TCP
    std::string tcp_flags;                // e.g. "SYN,ACK"
    uint8_t icmp_type = 0, icmp_code = 0; // ICMP
};

struct ArpPacket {
    uint16_t hw_type = 0, proto_type = 0;
    uint8_t hw_len = 0, proto_len = 0;
    uint16_t opcode = 0;                  // 1 request, 2 reply
    MacAddress sender_mac, target_mac;
    uint32_t sender_ip = 0, target_ip = 0;
    bool isGratuitous() const { return sender_ip == target_ip; }
};

struct ParsedPacket {
    size_t captured_len = 0;
    EthernetHeader eth;
    std::optional<IPv4Header> ip;
    std::optional<TransportInfo> transport;
    std::optional<ArpPacket> arp;
    std::string error;                    // non-empty => truncated / malformed
    bool ok() const { return error.empty(); }
};

// Decodes Ethernet -> (IPv4 -> TCP/UDP/ICMP) | ARP. Bounds-checked: never reads
// past `len`. Returns false only if not even an Ethernet header could be read;
// otherwise returns true and sets `out.error` for later-layer problems.
bool parsePacket(const uint8_t* data, size_t len, ParsedPacket& out);

// Internet checksum over `len` bytes (result 0 => valid when checksum included).
uint16_t internetChecksum(const uint8_t* data, size_t len);

std::string arpOpName(uint16_t op);
std::string protocolName(uint8_t proto);
std::string formatSummary(const ParsedPacket& p);   // one line
std::string formatVerbose(const ParsedPacket& p);   // multi-line field dump

}  // namespace netscope
