#pragma once
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "netscope/packet.hpp"

namespace netscope {

struct ArpConflict {
    uint32_t ip;
    std::set<MacAddress> macs;   // >1 MAC claiming the same IP (possible spoofing / duplicate IP)
};

// Accumulates statistics and an observed IP->MAC table across packets.
class Analyzer {
public:
    void record(const ParsedPacket& p, size_t wire_len);

    std::vector<ArpConflict> arpConflicts() const;
    std::string summary() const;

    uint64_t total = 0, bytes = 0, malformed = 0, non_ethernet = 0;
    uint64_t arp_requests = 0, arp_replies = 0, arp_gratuitous = 0;
    uint64_t ipv4 = 0, tcp = 0, udp = 0, icmp = 0, other_ip = 0, other_l2 = 0, bad_checksum = 0;
    std::map<uint32_t, std::set<MacAddress>> arp_table;   // IP -> MACs seen as sender
};

}  // namespace netscope
