#!/usr/bin/env python3
"""Generate samples/sample.pcap: ARP request/reply/gratuitous/spoof, TCP, UDP, ICMP, a bad-checksum
packet and a VLAN frame. Standard library only. Usage: python3 tools/gen_sample_pcap.py [out.pcap]"""
import socket, struct, sys, os
## samples
def mac(s): return bytes(int(x, 16) for x in s.split(":"))
def ip(s): return socket.inet_aton(s)

def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def eth(dst, src, et, payload, vlan=None):
    if vlan is not None:
        return mac(dst) + mac(src) + struct.pack("!HHH", 0x8100, vlan, et) + payload
    return mac(dst) + mac(src) + struct.pack("!H", et) + payload

def arp(op, smac, sip, tmac, tip):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac(smac) + ip(sip) + mac(tmac) + ip(tip)

def ipv4(src, dst, proto, payload, ttl=64, ident=1, bad=False):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, ttl, proto, 0, ip(src), ip(dst))
    c = csum(hdr)
    if bad: c ^= 0xFFFF
    return hdr[:10] + struct.pack("!H", c) + hdr[12:] + payload

def tcp(sp, dp, seq, ack, flags):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 64240, 0, 0)

def udp(sp, dp, data):
    return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data

def icmp_echo(t, ident, seq):
    body = struct.pack("!BBHHH", t, 0, 0, ident, seq) + b"abcdefgh"
    return body[:2] + struct.pack("!H", csum(body)) + body[4:]

A, B, GW, ATT = "aa:bb:cc:00:00:0a", "aa:bb:cc:00:00:0b", "aa:bb:cc:00:00:01", "de:ad:be:ef:00:66"
BC, Z = "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"
ETH_IP, ETH_ARP = 0x0800, 0x0806

frames = [
    eth(BC, A, ETH_ARP, arp(1, A, "192.168.1.10", Z, "192.168.1.1")),
    eth(A, GW, ETH_ARP, arp(2, GW, "192.168.1.1", A, "192.168.1.10")),
    eth(GW, A, ETH_IP, ipv4("192.168.1.10", "93.184.216.34", 6, tcp(51514, 443, 1000, 0, 0x02))),
    eth(A, GW, ETH_IP, ipv4("93.184.216.34", "192.168.1.10", 6, tcp(443, 51514, 5000, 1001, 0x12), ttl=56)),
    eth(GW, A, ETH_IP, ipv4("192.168.1.10", "93.184.216.34", 6, tcp(51514, 443, 1001, 5001, 0x10))),
    eth(GW, A, ETH_IP, ipv4("192.168.1.10", "8.8.8.8", 17, udp(40000, 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"))),
    eth(GW, A, ETH_IP, ipv4("192.168.1.10", "1.1.1.1", 1, icmp_echo(8, 7, 1))),
    eth(A, GW, ETH_IP, ipv4("1.1.1.1", "192.168.1.10", 1, icmp_echo(0, 7, 1), ttl=58)),
    eth(BC, B, ETH_ARP, arp(1, B, "192.168.1.20", Z, "192.168.1.20")),        # gratuitous
    eth(BC, A, ETH_ARP, arp(1, A, "192.168.1.10", Z, "192.168.1.55")),
    eth(A, ATT, ETH_ARP, arp(2, ATT, "192.168.1.1", A, "192.168.1.10")),      # spoofed gateway!
    eth(GW, A, ETH_IP, ipv4("192.168.1.10", "10.9.9.9", 17, udp(5000, 5001, b"bad"), bad=True)),
    eth(BC, B, ETH_ARP, arp(1, B, "192.168.1.20", Z, "192.168.1.1"), vlan=100), # VLAN-tagged
]

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join("samples", "sample.pcap")
os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    t = 1_700_000_000
    for i, fr in enumerate(frames):
        f.write(struct.pack("<IIII", t + i, i * 1000 + 123, len(fr), len(fr)) + fr)
print(f"wrote {out} ({len(frames)} packets)")
