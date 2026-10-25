#include "netscope/analyzer.hpp"
#include "netscope/subnet.hpp"

#include <sstream>

namespace netscope {

void Analyzer::record(const ParsedPacket& p, size_t wire_len) {
    ++total;
    bytes += wire_len;
    if (!p.ok()) ++malformed;

    if (p.arp) {
        const auto& a = *p.arp;
        if (a.opcode == 1) ++arp_requests;
        else if (a.opcode == 2) ++arp_replies;
        if (a.isGratuitous()) ++arp_gratuitous;
        if (a.sender_ip != 0)   // 0.0.0.0 = ARP probe, not a binding
            arp_table[a.sender_ip].insert(a.sender_mac);
    } else if (p.ip) {
        ++ipv4;
        if (!p.ip->checksum_ok) ++bad_checksum;
        if (p.ip->protocol == IPPROTO_TCP_) ++tcp;
        else if (p.ip->protocol == IPPROTO_UDP_) ++udp;
        else if (p.ip->protocol == IPPROTO_ICMP_) ++icmp;
        else ++other_ip;
    } else {
        ++other_l2;
    }
}

std::vector<ArpConflict> Analyzer::arpConflicts() const {
    std::vector<ArpConflict> out;
    for (const auto& [ip, macs] : arp_table)
        if (macs.size() > 1) out.push_back({ip, macs});
    return out;
}

std::string Analyzer::summary() const {
    std::ostringstream o;
    o << "\n--- NetScope summary ---\n"
      << "  packets: " << total << "  bytes: " << bytes << "  malformed: " << malformed << '\n'
      << "  ARP:  " << (arp_requests + arp_replies) << " (requests " << arp_requests << ", replies "
      << arp_replies << ", gratuitous " << arp_gratuitous << ")\n"
      << "  IPv4: " << ipv4 << " (TCP " << tcp << ", UDP " << udp << ", ICMP " << icmp << ", other "
      << other_ip << ", bad checksum " << bad_checksum << ")\n"
      << "  other L2/L3: " << other_l2 << '\n';

    if (!arp_table.empty()) {
        o << "\n  Observed ARP bindings:\n";
        for (const auto& [ip, macs] : arp_table) {
            o << "    " << ipToString(ip) << "  ->";
            for (const auto& m : macs) o << ' ' << m.str();
            o << '\n';
        }
    }
    auto conflicts = arpConflicts();
    if (!conflicts.empty()) {
        o << "\n  [!] ARP conflicts (same IP, multiple MACs - duplicate IP or possible spoofing):\n";
        for (const auto& c : conflicts) {
            o << "    " << ipToString(c.ip) << " claimed by";
            for (const auto& m : c.macs) o << ' ' << m.str();
            o << '\n';
        }
    }
    return o.str();
}

}  // namespace netscope 
