#include <cstdio>
#include "netscope/subnet.hpp"
using namespace netscope;

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

int main() {
    // parse / print
    CHECK(parseIPv4("192.168.1.10") == 0xC0A8010Au);
    CHECK(!parseIPv4("256.1.1.1"));
    CHECK(!parseIPv4("1.2.3"));
    CHECK(!parseIPv4("1.2.3.4.5"));
    CHECK(!parseIPv4("01.2.3.4"));
    CHECK(!parseIPv4("1.2.3.4 "));
    CHECK(!parseIPv4(""));
    CHECK(ipToString(0x0A000001u) == "10.0.0.1");

    // masks
    CHECK(maskFromPrefix(0) == 0u);
    CHECK(maskFromPrefix(24) == 0xFFFFFF00u);
    CHECK(maskFromPrefix(32) == 0xFFFFFFFFu);
    CHECK(prefixFromMask(0xFFFFFF00u) == 24);
    CHECK(!prefixFromMask(0xFF00FF00u));
    CHECK(prefixFromMask(0) == 0);

    // /24
    auto s = calculateSubnet("192.168.1.10/24");
    CHECK(s && ipToString(s->network) == "192.168.1.0");
    CHECK(s && ipToString(s->broadcast) == "192.168.1.255");
    CHECK(s && ipToString(s->first_host) == "192.168.1.1");
    CHECK(s && ipToString(s->last_host) == "192.168.1.254");
    CHECK(s && s->usable_hosts == 254 && s->total_addresses == 256);
    CHECK(s && s->ip_class == "C" && s->scope == "Private (RFC 1918)");

    // non-octet boundary: 192.168.10.77/26 -> .64 - .127 
    s = calculateSubnet("192.168.10.77/26");
    CHECK(s && ipToString(s->network) == "192.168.10.64");
    CHECK(s && ipToString(s->broadcast) == "192.168.10.127");
    CHECK(s && ipToString(s->first_host) == "192.168.10.65");
    CHECK(s && ipToString(s->last_host) == "192.168.10.126");
    CHECK(s && s->usable_hosts == 62);
    CHECK(s && ipToString(s->wildcard) == "0.0.0.63");

    // dotted mask forms
    s = calculateSubnet("172.16.5.9 255.255.0.0");
    CHECK(s && s->prefix == 16 && ipToString(s->broadcast) == "172.16.255.255");
    s = calculateSubnet("10.1.2.3/255.255.255.252");
    CHECK(s && s->prefix == 30 && s->usable_hosts == 2);

    // edge prefixes
    s = calculateSubnet("10.0.0.0/8");
    CHECK(s && s->usable_hosts == 16777214ULL);
    s = calculateSubnet("1.2.3.4/0");
    CHECK(s && s->total_addresses == 4294967296ULL && s->usable_hosts == 4294967294ULL);
    s = calculateSubnet("10.0.0.4/31");
    CHECK(s && s->usable_hosts == 2 && ipToString(s->first_host) == "10.0.0.4" && ipToString(s->last_host) == "10.0.0.5");
    s = calculateSubnet("10.0.0.9/32");
    CHECK(s && s->usable_hosts == 1 && ipToString(s->first_host) == "10.0.0.9");

    // classification
    s = calculateSubnet("8.8.8.8/24");   CHECK(s && s->scope == "Public" && s->ip_class == "A");
    s = calculateSubnet("172.20.0.1/12"); CHECK(s && s->scope == "Private (RFC 1918)" && s->ip_class == "B");
    s = calculateSubnet("172.32.0.1/12"); CHECK(s && s->scope == "Public");
    s = calculateSubnet("224.0.0.5/4");  CHECK(s && s->scope == "Multicast");
    s = calculateSubnet("127.0.0.1/8");  CHECK(s && s->scope == "Loopback");

    // contains
    s = calculateSubnet("192.168.1.10/24");
    CHECK(s && contains(*s, *parseIPv4("192.168.1.200")) && !contains(*s, *parseIPv4("192.168.2.1")));

    // errors
    std::string err;
    CHECK(!calculateSubnet("192.168.1.10", &err) && !err.empty());
    CHECK(!calculateSubnet("192.168.1.10/33", &err));
    CHECK(!calculateSubnet("192.168.1.10/abc", &err));
    CHECK(!calculateSubnet("192.168.1.10/255.0.255.0", &err));
    CHECK(!calculateSubnet("999.1.1.1/24", &err));
    CHECK(!calculateSubnet("1.2.3.4/", &err));

    if (failures == 0) std::puts("test_subnet: all passed");
    return failures ? 1 : 0;
}
