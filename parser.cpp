#include "netscope/packet.hpp"
#include "netscope/subnet.hpp"

#include <cstdio>
#include <sstream>

namespace netscope {

static inline uint16_t rd16(const uint8_t* p) { return uint16_t((p[0] << 8) | p[1]); }
static inline uint32_t rd32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
static MacAddress rdMac(const uint8_t* p) {
    MacAddress m;
    for (int i = 0; i < 6; ++i) m.b[i] = p[i];
    return m;
}

std::string MacAddress::str() const {
    char buf[18];
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4],
                  b[5]);
    return buf;
}
bool MacAddress::isBroadcast() const {
    for (auto x : b)
        if (x != 0xFF) return false;
    return true;
}

uint16_t internetChecksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) sum += rd16(data + i);
    if (len & 1) sum += uint32_t(data[len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return uint16_t(~sum & 0xFFFF);
}

// ---------------------------------------------------------------------------
static void parseTransport(const uint8_t* p, size_t len, uint8_t proto, ParsedPacket& out) {
    TransportInfo t;
    if (proto == IPPROTO_TCP_) {
        if (len < 14) { out.error = "truncated TCP header"; return; }
        t.kind = TransportInfo::Kind::TCP;
        t.src_port = rd16(p);
        t.dst_port = rd16(p + 2);
        t.seq = rd32(p + 4);
        t.ack = rd32(p + 8);
        uint8_t f = p[13];
        static const struct { uint8_t bit; const char* name; } names[] = {
            {0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"}, {0x08, "PSH"}, {0x20, "URG"}};
        for (auto& n : names)
            if (f & n.bit) t.tcp_flags += (t.tcp_flags.empty() ? "" : ",") + std::string(n.name);
        if (t.tcp_flags.empty()) t.tcp_flags = "none";
    } else if (proto == IPPROTO_UDP_) {
        if (len < 8) { out.error = "truncated UDP header"; return; }
        t.kind = TransportInfo::Kind::UDP;
        t.src_port = rd16(p);
        t.dst_port = rd16(p + 2);
    } else if (proto == IPPROTO_ICMP_) {
        if (len < 2) { out.error = "truncated ICMP header"; return; }
        t.kind = TransportInfo::Kind::ICMP;
        t.icmp_type = p[0];
        t.icmp_code = p[1];
    } else {
        return;  // other protocols: IPv4 info only
    }
    out.transport = t;
}

static void parseIPv4Packet(const uint8_t* p, size_t len, ParsedPacket& out) {
    if (len < 20) { out.error = "truncated IPv4 header"; return; }
    IPv4Header h;
    h.version = p[0] >> 4;
    h.ihl = p[0] & 0x0F;
    if (h.version != 4) { out.error = "IPv4 ethertype but version=" + std::to_string(h.version); return; }
    if (h.ihl < 5) { out.error = "invalid IPv4 IHL=" + std::to_string(h.ihl); return; }
    if (len < h.header_len()) { out.error = "truncated IPv4 options"; return; }

    h.dscp = p[1] >> 2;
    h.ecn = p[1] & 0x03;
    h.total_length = rd16(p + 2);
    h.identification = rd16(p + 4);
    uint16_t ff = rd16(p + 6);
    h.flag_df = ff & 0x4000;
    h.flag_mf = ff & 0x2000;
    h.frag_offset = ff & 0x1FFF;
    h.ttl = p[8];
    h.protocol = p[9];
    h.checksum = rd16(p + 10);
    h.src = rd32(p + 12);
    h.dst = rd32(p + 16);
    h.checksum_ok = internetChecksum(p, h.header_len()) == 0;
    out.ip = h;

    if (h.total_length < h.header_len()) { out.error = "IPv4 total length < header length"; return; }
    // Clamp to total_length to ignore Ethernet padding; tolerate snaplen truncation.
    size_t end = h.total_length < len ? h.total_length : len;
    if (h.frag_offset != 0) return;  // non-first fragment: no transport header
    parseTransport(p + h.header_len(), end - h.header_len(), h.protocol, out);
}

static void parseArpPacket(const uint8_t* p, size_t len, ParsedPacket& out) {
    if (len < 28) { out.error = "truncated ARP packet"; return; }
    ArpPacket a;
    a.hw_type = rd16(p);
    a.proto_type = rd16(p + 2);
    a.hw_len = p[4];
    a.proto_len = p[5];
    a.opcode = rd16(p + 6);
    if (a.hw_len != 6 || a.proto_len != 4 || a.proto_type != ETHERTYPE_IPV4) {
        out.error = "unsupported ARP (only Ethernet/IPv4 handled)";
        return;
    }
    a.sender_mac = rdMac(p + 8);
    a.sender_ip = rd32(p + 14);
    a.target_mac = rdMac(p + 18);
    a.target_ip = rd32(p + 24);
    out.arp = a;
}

bool parsePacket(const uint8_t* data, size_t len, ParsedPacket& out) {
    out = ParsedPacket{};
    out.captured_len = len;
    if (!data || len < 14) return false;

    out.eth.dst = rdMac(data);
    out.eth.src = rdMac(data + 6);
    uint16_t et = rd16(data + 12);
    size_t off = 14;
    while ((et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ)) {
        if (len < off + 4) { out.eth.ethertype = et; out.error = "truncated VLAN tag"; return true; }
        if (!out.eth.vlan_id) out.eth.vlan_id = rd16(data + off) & 0x0FFF;
        et = rd16(data + off + 2);
        off += 4;
    }
    out.eth.ethertype = et;

    if (et == ETHERTYPE_IPV4) parseIPv4Packet(data + off, len - off, out);
    else if (et == ETHERTYPE_ARP) parseArpPacket(data + off, len - off, out);
    return true;
}

// ---------------------------------------------------------------------------
std::string arpOpName(uint16_t op) {
    switch (op) {
        case 1: return "Request";
        case 2: return "Reply";
        case 3: return "RARP Request";
        case 4: return "RARP Reply";
        default: return "Op" + std::to_string(op);
    }
}

std::string protocolName(uint8_t p) {
    switch (p) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 47: return "GRE";
        case 50: return "ESP";
        default: return "proto " + std::to_string(p);
    }
}

static std::string icmpName(uint8_t t) {
    switch (t) {
        case 0: return "Echo Reply";
        case 3: return "Destination Unreachable";
        case 5: return "Redirect";
        case 8: return "Echo Request";
        case 11: return "Time Exceeded";
        default: return "Type " + std::to_string(t);
    }
}

std::string formatSummary(const ParsedPacket& p) {
    std::ostringstream o;
    if (p.arp) {
        const auto& a = *p.arp;
        o << "ARP " << arpOpName(a.opcode) << ": ";
        if (a.opcode == 1) {
            if (a.isGratuitous()) o << "gratuitous, " << ipToString(a.sender_ip) << " is " << a.sender_mac.str();
            else o << "who has " << ipToString(a.target_ip) << "? tell " << ipToString(a.sender_ip)
                   << " (" << a.sender_mac.str() << ")";
        } else if (a.opcode == 2) {
            o << ipToString(a.sender_ip) << " is at " << a.sender_mac.str() << " -> "
              << ipToString(a.target_ip) << " (" << a.target_mac.str() << ")";
            if (a.isGratuitous()) o << " [gratuitous]";
        }
    } else if (p.ip) {
        const auto& h = *p.ip;
        o << "IPv4 " << ipToString(h.src) << " -> " << ipToString(h.dst) << " " << protocolName(h.protocol);
        if (p.transport) {
            const auto& t = *p.transport;
            if (t.kind == TransportInfo::Kind::TCP)
                o << " " << t.src_port << " -> " << t.dst_port << " [" << t.tcp_flags << "]";
            else if (t.kind == TransportInfo::Kind::UDP)
                o << " " << t.src_port << " -> " << t.dst_port;
            else
                o << " " << icmpName(t.icmp_type);
        }
        o << " ttl=" << int(h.ttl) << " len=" << h.total_length;
        if (!h.checksum_ok) o << " [BAD IP CHECKSUM]";
    } else {
        char buf[16];
        std::snprintf(buf, sizeof buf, "0x%04x", p.eth.ethertype);
        o << (p.eth.ethertype == ETHERTYPE_IPV6 ? "IPv6" : "Ethernet") << " ethertype " << buf << " "
          << p.eth.src.str() << " -> " << p.eth.dst.str();
    }
    if (!p.error.empty()) o << " [MALFORMED: " << p.error << "]";
    return o.str();
}

std::string formatVerbose(const ParsedPacket& p) {
    std::ostringstream o;
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%04x", p.eth.ethertype);
    o << "    Ethernet: " << p.eth.src.str() << " -> " << p.eth.dst.str()
      << (p.eth.dst.isBroadcast() ? " (broadcast)" : "") << "  type=" << buf;
    if (p.eth.vlan_id) o << "  vlan=" << *p.eth.vlan_id;
    o << '\n';
    if (p.arp) {
        const auto& a = *p.arp;
        o << "    ARP: op=" << a.opcode << " (" << arpOpName(a.opcode) << ")  hw=" << a.hw_type
          << "/" << int(a.hw_len) << "  proto=0x" << std::hex << a.proto_type << std::dec << "/"
          << int(a.proto_len) << '\n'
          << "         sender " << a.sender_mac.str() << " / " << ipToString(a.sender_ip) << '\n'
          << "         target " << a.target_mac.str() << " / " << ipToString(a.target_ip) << '\n';
    }
    if (p.ip) {
        const auto& h = *p.ip;
        std::snprintf(buf, sizeof buf, "0x%04x", h.checksum);
        o << "    IPv4: " << ipToString(h.src) << " -> " << ipToString(h.dst) << "  ihl=" << int(h.ihl)
          << "  dscp=" << int(h.dscp) << "  ecn=" << int(h.ecn) << "  total_len=" << h.total_length
          << "  id=" << h.identification << '\n'
          << "          flags=" << (h.flag_df ? "DF " : "") << (h.flag_mf ? "MF " : "")
          << " frag_off=" << h.frag_offset * 8 << "  ttl=" << int(h.ttl)
          << "  proto=" << int(h.protocol) << " (" << protocolName(h.protocol) << ")  checksum=" << buf
          << (h.checksum_ok ? " (ok)" : " (BAD)") << '\n';
    }
    if (p.transport) {
        const auto& t = *p.transport;
        if (t.kind == TransportInfo::Kind::TCP)
            o << "    TCP: " << t.src_port << " -> " << t.dst_port << "  seq=" << t.seq << "  ack=" << t.ack
              << "  flags=" << t.tcp_flags << '\n';
        else if (t.kind == TransportInfo::Kind::UDP)
            o << "    UDP: " << t.src_port << " -> " << t.dst_port << '\n';
        else
            o << "    ICMP: type=" << int(t.icmp_type) << " (" << icmpName(t.icmp_type)
              << ") code=" << int(t.icmp_code) << '\n';
    }
    return o.str();
}

}  // namespace netscope
