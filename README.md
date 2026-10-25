# NetScope — IPv4 and ARP Network Analyzer

C++17 · TCP/IP · libpcap

NetScope is a command-line tool that (1) calculates IPv4 subnet details and (2) captures or
reads packet traces and decodes **Ethernet, IPv4 (TCP/UDP/ICMP) and ARP** headers by hand —
no protocol structs cast onto raw memory, every read is bounds-checked.

## Features
- **Subnet calculator**: network, broadcast, wildcard, first/last host, usable host count,
  class, scope (RFC 1918, loopback, link-local…), binary view. Handles `/0`–`/32`, including
  RFC 3021 `/31` point-to-point links and `/32` host routes. Accepts `ip/prefix`, `ip/mask`, `ip mask`.
- **Packet parsing**: Ethernet (incl. 802.1Q/QinQ VLAN), IPv4 (all header fields, flags, fragment
  offset, header-checksum verification), TCP flags/ports/seq/ack, UDP ports, ICMP type/code,
  ARP request/reply/gratuitous with sender/target MAC + IP.
- **Live capture & pcap files** via libpcap, with BPF filters (`-f "arp or tcp port 443"`).
- **ARP analysis**: builds an observed IP→MAC table and flags IPs claimed by multiple MACs
  (duplicate IP / possible ARP spoofing).
- Robust against truncated/malformed frames (tested against every truncation length).

## Build
```bash
sudo apt install build-essential cmake libpcap-dev     # Debian/Ubuntu
# brew install cmake libpcap                           # macOS
cmake -S . -B build && cmake --build build
cd build && ctest --output-on-failure                  # run unit tests
```

## Usage
```text
netscope subnet <ip/prefix | ip/mask | "ip mask">
netscope devices
netscope read <file.pcap> [-f bpf] [-c n] [-v] [-q]
netscope capture -i <iface> [-f bpf] [-c n] [-v] [-q] [-p] [-s snaplen]   # needs root / CAP_NET_RAW
```

```bash
./build/netscope subnet 192.168.10.77/26
python3 tools/gen_sample_pcap.py                       # creates samples/sample.pcap
./build/netscope read samples/sample.pcap              # decode + summary + spoof detection
./build/netscope read samples/sample.pcap -f arp -v    # ARP only, every field
sudo ./build/netscope capture -i eth0 -f "arp or icmp" -c 50
```

Example subnet output:
```text
  Network:          192.168.10.64/26
  Broadcast:        192.168.10.127
  Host range:       192.168.10.65 - 192.168.10.126
  Usable hosts:     62
```

## Layout
```text
include/netscope/  subnet.hpp  packet.hpp  analyzer.hpp  capture.hpp
src/               subnet.cpp  parser.cpp  analyzer.cpp  capture.cpp  main.cpp
tests/             test_subnet.cpp  test_parser.cpp
tools/             gen_sample_pcap.py
```
`netscope_core` (subnet, parser, analyzer) has no libpcap dependency; only `capture.cpp`/`main.cpp` do.

## Notes
- Only Ethernet (DLT_EN10MB) captures are decoded. IPv6 frames are reported by ethertype only.
- Live captures on hosts with checksum offload may show "BAD IP CHECKSUM" for outgoing packets;
  the checksum is filled in by the NIC after libpcap sees the frame.
