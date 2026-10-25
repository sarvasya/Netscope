#include <cstdio>
#include <vector>
#include "netscope/analyzer.hpp"
#include "netscope/packet.hpp"
#include "netscope/subnet.hpp"
using namespace netscope;

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

using Bytes = std::vector<uint8_t>;

static Bytes arpFrame(uint16_t op, const char* smac_dst_hint, const uint8_t smac[6], uint32_t sip,
                      const uint8_t tmac[6], uint32_t tip) {
    (void)smac_dst_hint;
    Bytes f;
    for (int i = 0; i < 6; ++i) f.push_back(op == 1 ? 0xFF : tmac[i]);   // eth dst
    for (int i = 0; i < 6; ++i) f.push_back(smac[i]);                      // eth src
    f.insert(f.end(), {0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, uint8_t(op)});
    for (int i = 0; i < 6; ++i) f.push_back(smac[i]);
    for (int s = 24; s >= 0; s -= 8) f.push_back(uint8_t(sip >> s));
    for (int i = 0; i < 6; ++i) f.push_back(tmac[i]);
    for (int s = 24; s >= 0; s -= 8) f.push_back(uint8_t(tip >> s));
    return f;
}

// Ethernet + IPv4(UDP 1234->53, 4 byte payload) with correct checksum
static Bytes udpFrame(uint32_t src, uint32_t dst, bool corrupt = false) {
    Bytes f(12, 0x11);
    f.insert(f.end(), {0x08, 0x00});
    Bytes ip = {0x45, 0, 0, 32, 0x12, 0x34, 0x40, 0, 64, 17, 0, 0};
    for (int s = 24; s >= 0; s -= 8) ip.push_back(uint8_t(src >> s));
    for (int s = 24; s >= 0; s -= 8) ip.push_back(uint8_t(dst >> s));
    uint16_t c = internetChecksum(ip.data(), ip.size());
    ip[10] = c >> 8; ip[11] = c & 0xFF;
    if (corrupt) ip[8] ^= 0xFF;   // change TTL after checksum computed
    Bytes udp = {0x04, 0xD2, 0x00, 0x35, 0, 12, 0, 0, 'd', 'a', 't', 'a'};
    f.insert(f.end(), ip.begin(), ip.end());
    f.insert(f.end(), udp.begin(), udp.end());
    return f;
}

int main() {
    const uint8_t macA[6] = {0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01};
    const uint8_t macB[6] = {0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02};
    const uint8_t zero[6] = {0};
    uint32_t ipA = *parseIPv4("192.168.1.10"), ipB = *parseIPv4("192.168.1.1");

    // ARP request
    ParsedPacket p;
    Bytes req = arpFrame(1, "", macA, ipA, zero, ipB);
    CHECK(parsePacket(req.data(), req.size(), p) && p.ok() && p.arp);
    CHECK(p.arp->opcode == 1 && p.arp->sender_ip == ipA && p.arp->target_ip == ipB);
    CHECK(p.arp->sender_mac.str() == "aa:bb:cc:00:00:01");
    CHECK(p.eth.dst.isBroadcast() && p.eth.ethertype == ETHERTYPE_ARP);
    CHECK(formatSummary(p).find("who has 192.168.1.1? tell 192.168.1.10") != std::string::npos);

    // ARP reply
    Bytes rep = arpFrame(2, "", macB, ipB, macA, ipA);
    CHECK(parsePacket(rep.data(), rep.size(), p) && p.arp && p.arp->opcode == 2);
    CHECK(formatSummary(p).find("192.168.1.1 is at aa:bb:cc:00:00:02") != std::string::npos);

    // Gratuitous ARP
    Bytes grat = arpFrame(1, "", macA, ipA, zero, ipA);
    CHECK(parsePacket(grat.data(), grat.size(), p) && p.arp && p.arp->isGratuitous());

    // Truncated ARP
    CHECK(parsePacket(req.data(), 30, p) && !p.ok() && !p.arp);

    // UDP over IPv4
    Bytes u = udpFrame(ipA, *parseIPv4("8.8.8.8"));
    CHECK(parsePacket(u.data(), u.size(), p) && p.ok() && p.ip && p.transport);
    CHECK(p.ip->checksum_ok && p.ip->ttl == 64 && p.ip->protocol == 17 && p.ip->flag_df);
    CHECK(p.ip->src == ipA && ipToString(p.ip->dst) == "8.8.8.8");
    CHECK(p.transport->kind == TransportInfo::Kind::UDP && p.transport->src_port == 1234 && p.transport->dst_port == 53);

    // Bad checksum detected
    Bytes bad = udpFrame(ipA, ipB, true);
    CHECK(parsePacket(bad.data(), bad.size(), p) && p.ip && !p.ip->checksum_ok);

    // Ethernet padding is ignored (frame longer than IP total_length)
    Bytes padded = u;
    padded.insert(padded.end(), 10, 0);
    CHECK(parsePacket(padded.data(), padded.size(), p) && p.ok() && p.transport);

    // Truncated IPv4 / runt frames / garbage must not crash
    CHECK(parsePacket(u.data(), 20, p) && !p.ok());
    CHECK(!parsePacket(u.data(), 10, p));
    CHECK(!parsePacket(nullptr, 0, p));
    Bytes wrongver = u; wrongver[14] = 0x65;
    CHECK(parsePacket(wrongver.data(), wrongver.size(), p) && !p.ok());
    Bytes badihl = u; badihl[14] = 0x43;
    CHECK(parsePacket(badihl.data(), badihl.size(), p) && !p.ok());
    for (size_t n = 0; n <= u.size(); ++n) parsePacket(u.data(), n, p);   // every prefix length

    // VLAN-tagged ARP
    Bytes vl(req.begin(), req.begin() + 12);
    vl.insert(vl.end(), {0x81, 0x00, 0x00, 0x2A});
    vl.insert(vl.end(), req.begin() + 12, req.end());
    CHECK(parsePacket(vl.data(), vl.size(), p) && p.arp && p.eth.vlan_id == 42);

    // Analyzer: counts + conflict detection
    Analyzer an;
    Bytes spoof = arpFrame(2, "", macB, ipA, macA, ipB);   // macB claims ipA (macA already did)
    for (auto* f : {&req, &rep, &grat, &u, &spoof}) {
        parsePacket(f->data(), f->size(), p);
        an.record(p, f->size());
    }
    CHECK(an.total == 5 && an.arp_requests == 2 && an.arp_replies == 2 && an.arp_gratuitous == 1);
    CHECK(an.ipv4 == 1 && an.udp == 1);
    auto conf = an.arpConflicts();
    CHECK(conf.size() == 1 && conf[0].ip == ipA && conf[0].macs.size() == 2);

    if (failures == 0) std::puts("test_parser: all passed");
    return failures ? 1 : 0;
}
