#include "netscope/capture.hpp"

#include <pcap/pcap.h>

namespace netscope {

Capture::~Capture() {
    if (handle_) pcap_close(handle_);
}

std::vector<std::pair<std::string, std::string>> Capture::listDevices(std::string& error) {
    std::vector<std::pair<std::string, std::string>> out;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* devs = nullptr;
    if (pcap_findalldevs(&devs, errbuf) != 0) {
        error = errbuf;
        return out;
    }
    for (pcap_if_t* d = devs; d; d = d->next)
        out.emplace_back(d->name, d->description ? d->description : "");
    pcap_freealldevs(devs);
    return out;
}

bool Capture::checkLinkType() {
    int dlt = pcap_datalink(handle_);
    if (dlt != DLT_EN10MB) {
        error_ = std::string("unsupported link type '") + (pcap_datalink_val_to_name(dlt) ? pcap_datalink_val_to_name(dlt) : "?") +
                 "' (NetScope decodes Ethernet only)";
        return false;
    }
    return true;
}

bool Capture::openLive(const std::string& iface, int snaplen, bool promisc, int timeout_ms) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_live(iface.c_str(), snaplen, promisc ? 1 : 0, timeout_ms, errbuf);
    if (!handle_) {
        error_ = errbuf;
        return false;
    }
    return checkLinkType();
}

bool Capture::openOffline(const std::string& path) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_offline(path.c_str(), errbuf);
    if (!handle_) {
        error_ = errbuf;
        return false;
    }
    return checkLinkType();
}

bool Capture::setFilter(const std::string& bpf) {
    if (!handle_) { error_ = "capture not open"; return false; }
    bpf_program prog;
    if (pcap_compile(handle_, &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        error_ = std::string("bad filter: ") + pcap_geterr(handle_);
        return false;
    }
    bool ok = pcap_setfilter(handle_, &prog) == 0;
    if (!ok) error_ = std::string("cannot set filter: ") + pcap_geterr(handle_);
    pcap_freecode(&prog);
    return ok;
}

namespace {
struct Ctx {
    const std::function<void(const RawPacket&)>* cb;
    int n;
};
void trampoline(u_char* user, const pcap_pkthdr* h, const u_char* bytes) {
    auto* c = reinterpret_cast<Ctx*>(user);
    RawPacket p{h->ts, bytes, h->caplen, h->len};
    (*c->cb)(p);
    ++c->n;
}
}  // namespace

int Capture::run(int count, const std::function<void(const RawPacket&)>& cb) {
    if (!handle_) { error_ = "capture not open"; return -1; }
    Ctx ctx{&cb, 0};
    int rc = pcap_loop(handle_, count, trampoline, reinterpret_cast<u_char*>(&ctx));
    if (rc == PCAP_ERROR) {
        error_ = pcap_geterr(handle_);
        return -1;
    }
    return ctx.n;   // rc == 0 (count reached / EOF) or PCAP_ERROR_BREAK (stopped)
}

void Capture::stop() {
    if (handle_) pcap_breakloop(handle_);
}

}  // namespace netscope
