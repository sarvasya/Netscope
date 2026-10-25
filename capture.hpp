#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <sys/time.h>
#include <utility>
#include <vector>
// capturing
struct pcap;  // forward decl (pcap_t is `struct pcap`)

namespace netscope {

struct RawPacket {
    timeval ts;
    const uint8_t* data;
    uint32_t caplen;
    uint32_t len;     // original length on the wire
};

// Thin RAII wrapper over libpcap (live capture or offline .pcap files).
class Capture {
public:
    Capture() = default;
    ~Capture();
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;

    static std::vector<std::pair<std::string, std::string>> listDevices(std::string& error);

    bool openLive(const std::string& iface, int snaplen, bool promisc, int timeout_ms);
    bool openOffline(const std::string& path);
    bool setFilter(const std::string& bpf);   // BPF expression, e.g. "arp or tcp port 80"

    // Runs until `count` packets (0 = unlimited), EOF, error or stop().
    // Returns number of packets processed, or -1 on error.
    int run(int count, const std::function<void(const RawPacket&)>& cb);
    void stop();                               // async-signal-safe enough for SIGINT

    const std::string& error() const { return error_; }

private:
    bool checkLinkType();
    struct pcap* handle_ = nullptr;
    std::string error_;
};

}  // namespace netscope
