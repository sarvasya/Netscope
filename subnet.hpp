#pragma once
#include <cstdint>
#include <optional>
#include <string>

namespace netscope {

// ---- IPv4 address helpers -------------------------------------------------
// Parses strict dotted-quad ("192.168.1.10"). Rejects leading zeros and
// out-of-range octets.
std::optional<uint32_t> parseIPv4(const std::string& s);
std::string ipToString(uint32_t ip);

uint32_t maskFromPrefix(int prefix);                 // 0..32
std::optional<int> prefixFromMask(uint32_t mask);    // nullopt if non-contiguous
std::string toBinary(uint32_t v);                    // "11000000.10101000...."

// ---- Subnet calculation ---------------------------------------------------
struct SubnetInfo {
    uint32_t ip = 0;
    uint32_t mask = 0;
    uint32_t wildcard = 0;
    uint32_t network = 0;
    uint32_t broadcast = 0;
    uint32_t first_host = 0;
    uint32_t last_host = 0;
    int prefix = 0;
    uint64_t total_addresses = 0;
    uint64_t usable_hosts = 0;
    std::string ip_class;   // A, B, C, D (multicast), E (reserved)
    std::string scope;      // Private (RFC 1918), Loopback, Link-local, ...
};

// Accepts "192.168.1.10/24", "192.168.1.10/255.255.255.0" or
// "192.168.1.10 255.255.255.0". On failure returns nullopt and fills `error`.
std::optional<SubnetInfo> calculateSubnet(const std::string& input, std::string* error = nullptr);

std::string formatSubnet(const SubnetInfo& s);

// True if `ip` lies inside `s`'s network.
bool contains(const SubnetInfo& s, uint32_t ip);

}  // namespace netscope
