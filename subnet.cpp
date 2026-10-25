#include "netscope/subnet.hpp"

#include <cctype>
#include <sstream>
//subnet part
namespace netscope {

std::optional<uint32_t> parseIPv4(const std::string& s) {
    uint32_t result = 0;
    int octets = 0;
    size_t i = 0;
    while (true) {
        if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) return std::nullopt;
        size_t start = i;
        unsigned val = 0;
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
            val = val * 10 + static_cast<unsigned>(s[i] - '0');
            if (val > 255) return std::nullopt;
            ++i;
        }
        if (i - start > 1 && s[start] == '0') return std::nullopt;  // no leading zeros
        result = (result << 8) | val;
        if (++octets > 4) return std::nullopt;
        if (i == s.size()) break;
        if (s[i] != '.') return std::nullopt;
        ++i;
    }
    if (octets != 4) return std::nullopt;
    return result;
}

std::string ipToString(uint32_t ip) {
    std::ostringstream o;
    o << ((ip >> 24) & 0xFF) << '.' << ((ip >> 16) & 0xFF) << '.' << ((ip >> 8) & 0xFF) << '.'
      << (ip & 0xFF);
    return o.str();
}

uint32_t maskFromPrefix(int prefix) {
    if (prefix <= 0) return 0;
    if (prefix >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - prefix);
}

std::optional<int> prefixFromMask(uint32_t mask) {
    int ones = 0;
    while (ones < 32 && (mask & (0x80000000u >> ones))) ++ones;
    if (mask != maskFromPrefix(ones)) return std::nullopt;  // holes in the mask
    return ones;
}

std::string toBinary(uint32_t v) {
    std::string out;
    for (int i = 31; i >= 0; --i) {
        out += ((v >> i) & 1) ? '1' : '0';
        if (i % 8 == 0 && i != 0) out += '.';
    }
    return out;
}

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string classify(uint32_t ip, std::string& scope) {
    uint8_t a = ip >> 24, b = (ip >> 16) & 0xFF;
    if (a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168))
        scope = "Private (RFC 1918)";
    else if (a == 127) scope = "Loopback";
    else if (a == 169 && b == 254) scope = "Link-local (APIPA)";
    else if (a >= 224 && a <= 239) scope = "Multicast";
    else if (a >= 240) scope = "Reserved";
    else if (a == 0) scope = "This network";
    else scope = "Public";

    if (a < 128) return "A";
    if (a < 192) return "B";
    if (a < 224) return "C";
    if (a < 240) return "D (multicast)";
    return "E (reserved)";
}

std::optional<SubnetInfo> calculateSubnet(const std::string& input, std::string* error) {
    auto fail = [&](const std::string& m) -> std::optional<SubnetInfo> {
        if (error) *error = m;
        return std::nullopt;
    };

    std::string in = trim(input);
    std::string ip_str, mask_str;
    size_t slash = in.find('/');
    if (slash != std::string::npos) {
        ip_str = trim(in.substr(0, slash));
        mask_str = trim(in.substr(slash + 1));
    } else {
        size_t sp = in.find_first_of(" \t");
        if (sp == std::string::npos)
            return fail("expected CIDR (a.b.c.d/n) or 'a.b.c.d mask'");
        ip_str = in.substr(0, sp);
        mask_str = trim(in.substr(sp + 1));
    }

    auto ip = parseIPv4(ip_str);
    if (!ip) return fail("invalid IPv4 address: '" + ip_str + "'");
    if (mask_str.empty()) return fail("missing prefix length / mask");

    SubnetInfo s;
    s.ip = *ip;
    if (mask_str.find('.') != std::string::npos) {
        auto m = parseIPv4(mask_str);
        if (!m) return fail("invalid subnet mask: '" + mask_str + "'");
        auto p = prefixFromMask(*m);
        if (!p) return fail("subnet mask is not contiguous: '" + mask_str + "'");
        s.mask = *m;
        s.prefix = *p;
    } else {
        for (char c : mask_str)
            if (!std::isdigit(static_cast<unsigned char>(c)))
                return fail("invalid prefix length: '" + mask_str + "'");
        if (mask_str.size() > 2) return fail("prefix length must be 0-32");
        int p = std::stoi(mask_str);
        if (p < 0 || p > 32) return fail("prefix length must be 0-32");
        s.prefix = p;
        s.mask = maskFromPrefix(p);
    }

    s.wildcard = ~s.mask;
    s.network = s.ip & s.mask;
    s.broadcast = s.network | s.wildcard;
    s.total_addresses = 1ULL << (32 - s.prefix);

    if (s.prefix <= 30) {                 // normal subnet
        s.first_host = s.network + 1;
        s.last_host = s.broadcast - 1;
        s.usable_hosts = s.total_addresses - 2;
    } else if (s.prefix == 31) {          // RFC 3021 point-to-point
        s.first_host = s.network;
        s.last_host = s.broadcast;
        s.usable_hosts = 2;
    } else {                              // /32 host route
        s.first_host = s.last_host = s.ip;
        s.usable_hosts = 1;
    }
    s.ip_class = classify(s.ip, s.scope);
    return s;
}

bool contains(const SubnetInfo& s, uint32_t ip) { return (ip & s.mask) == s.network; }

std::string formatSubnet(const SubnetInfo& s) {
    std::ostringstream o;
    auto row = [&](const char* label, const std::string& v) {
        o << "  " << label;
        for (size_t i = std::string(label).size(); i < 18; ++i) o << ' ';
        o << v << '\n';
    };
    o << "Subnet calculation\n";
    row("Address:", ipToString(s.ip));
    row("Netmask:", ipToString(s.mask) + " = /" + std::to_string(s.prefix));
    row("Wildcard:", ipToString(s.wildcard));
    row("Network:", ipToString(s.network) + "/" + std::to_string(s.prefix));
    row("Broadcast:", s.prefix >= 31 ? ipToString(s.broadcast) + " (n/a for /31, /32)"
                                      : ipToString(s.broadcast));
    row("Host range:", ipToString(s.first_host) + " - " + ipToString(s.last_host));
    row("Total addresses:", std::to_string(s.total_addresses));
    row("Usable hosts:", std::to_string(s.usable_hosts));
    row("Class:", s.ip_class);
    row("Scope:", s.scope);
    row("Address (bin):", toBinary(s.ip));
    row("Netmask (bin):", toBinary(s.mask));
    return o.str();
}

}  // namespace netscope
