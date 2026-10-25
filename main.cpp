// NetScope - IPv4 and ARP network analyzer
#include <csignal>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include "netscope/analyzer.hpp"
#include "netscope/capture.hpp"
#include "netscope/packet.hpp"
#include "netscope/subnet.hpp"

using namespace netscope;

namespace {

Capture* g_active = nullptr;
void onSigint(int) {
    if (g_active) g_active->stop();
}

void usage() {
    std::puts(
        "NetScope 1.0 - IPv4 and ARP network analyzer\n"
        "\n"
        "Usage:\n"
        "  netscope subnet <ip/prefix | ip/mask | \"ip mask\">\n"
        "  netscope devices\n"
        "  netscope read <file.pcap> [options]\n"
        "  netscope capture -i <iface> [options]     (usually needs root/CAP_NET_RAW)\n"
        "\n"
        "Options for read/capture:\n"
        "  -f <bpf>     BPF filter expression, e.g. \"arp\" or \"host 10.0.0.5 and tcp\"\n"
        "  -c <n>       stop after n packets (default: unlimited)\n"
        "  -v           verbose: dump every decoded header field\n"
        "  -q           quiet: only print the final summary\n"
        "  -p           (capture) do NOT enable promiscuous mode\n"
        "  -s <bytes>   (capture) snap length, default 65535\n"
        "\n"
        "Examples:\n"
        "  netscope subnet 192.168.10.77/26\n"
        "  netscope read samples/sample.pcap -f arp -v\n"
        "  sudo netscope capture -i eth0 -f \"arp or icmp\" -c 100");
}

struct Options {
    std::string source, filter;
    int count = 0, snaplen = 65535;
    bool verbose = false, quiet = false, promisc = true;
};

bool parseOptions(int argc, char** argv, int start, Options& o, bool live) {
    for (int i = start; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name) -> const char* {
            if (i + 1 >= argc) { std::fprintf(stderr, "error: %s needs a value\n", name); return nullptr; }
            return argv[++i];
        };
        if (a == "-f") { auto v = need("-f"); if (!v) return false; o.filter = v; }
        else if (a == "-c") { auto v = need("-c"); if (!v) return false; o.count = std::atoi(v); if (o.count < 0) o.count = 0; }
        else if (a == "-s") { auto v = need("-s"); if (!v) return false; o.snaplen = std::atoi(v); }
        else if (a == "-i" && live) { auto v = need("-i"); if (!v) return false; o.source = v; }
        else if (a == "-v") o.verbose = true;
        else if (a == "-q") o.quiet = true;
        else if (a == "-p") o.promisc = false;
        else if (!live && o.source.empty() && a[0] != '-') o.source = a;
        else { std::fprintf(stderr, "error: unknown argument '%s'\n", a.c_str()); return false; }
    }
    if (o.source.empty()) {
        std::fprintf(stderr, live ? "error: -i <iface> required\n" : "error: pcap file required\n");
        return false;
    }
    return true;
}

int runAnalysis(Capture& cap, const Options& o) {
    if (!o.filter.empty() && !cap.setFilter(o.filter)) {
        std::fprintf(stderr, "error: %s\n", cap.error().c_str());
        return 1;
    }
    Analyzer analyzer;
    unsigned long n = 0;
    g_active = &cap;
    std::signal(SIGINT, onSigint);

    int rc = cap.run(o.count, [&](const RawPacket& rp) {
        ++n;
        ParsedPacket pp;
        if (!parsePacket(rp.data, rp.caplen, pp)) {
            ++analyzer.total;
            ++analyzer.malformed;
            if (!o.quiet) std::printf("#%-5lu  [runt frame, %u bytes]\n", n, rp.caplen);
            return;
        }
        analyzer.record(pp, rp.len);
        if (o.quiet) return;

        char tbuf[32];
        time_t secs = rp.ts.tv_sec;
        std::tm tmv{};
        localtime_r(&secs, &tmv);
        std::strftime(tbuf, sizeof tbuf, "%H:%M:%S", &tmv);
        std::printf("#%-5lu %s.%06ld  %5u B  %s\n", n, tbuf, static_cast<long>(rp.ts.tv_usec), rp.len,
                    formatSummary(pp).c_str());
        if (o.verbose) std::fputs(formatVerbose(pp).c_str(), stdout);
    });
    g_active = nullptr;

    if (rc < 0) {
        std::fprintf(stderr, "error: %s\n", cap.error().c_str());
        return 1;
    }
    std::fputs(analyzer.summary().c_str(), stdout);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2 || !std::strcmp(argv[1], "-h") || !std::strcmp(argv[1], "--help")) {
        usage();
        return argc < 2 ? 1 : 0;
    }
    std::string cmd = argv[1];

    if (cmd == "subnet") {
        if (argc < 3) { usage(); return 1; }
        std::string input = argv[2];
        for (int i = 3; i < argc; ++i) input += std::string(" ") + argv[i];   // allow unquoted "ip mask"
        std::string err;
        auto s = calculateSubnet(input, &err);
        if (!s) { std::fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
        std::fputs(formatSubnet(*s).c_str(), stdout);
        return 0;
    }

    if (cmd == "devices") {
        std::string err;
        auto devs = Capture::listDevices(err);
        if (!err.empty()) { std::fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
        for (auto& [name, desc] : devs)
            std::printf("%-16s %s\n", name.c_str(), desc.c_str());
        return 0;
    }

    if (cmd == "read" || cmd == "capture") {
        bool live = cmd == "capture";
        Options o;
        if (!parseOptions(argc, argv, 2, o, live)) return 1;
        Capture cap;
        bool ok = live ? cap.openLive(o.source, o.snaplen, o.promisc, 1000) : cap.openOffline(o.source);
        if (!ok) { std::fprintf(stderr, "error: %s\n", cap.error().c_str()); return 1; }
        return runAnalysis(cap, o);
    }

    std::fprintf(stderr, "error: unknown command '%s'\n\n", cmd.c_str());
    usage();
    return 1;
}
