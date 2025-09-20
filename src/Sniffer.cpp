#include "Sniffer.h"
#include "PacketParser.h"
#include <stdexcept>
#include <signal.h>
#include <cstring>
#include <iostream>

static volatile bool keep_running = true;

static void intHandler(int) {
    keep_running = false;
}

Sniffer::Sniffer(const std::string &iface, Logger* logger) : iface_(iface), logger_(logger) {
    std::memset(errbuf_, 0, sizeof(errbuf_));
    openDevice();
    signal(SIGINT, intHandler);
}

Sniffer::~Sniffer() {
    closeDevice();
}

void Sniffer::openDevice() {
    std::string dev = iface_.empty() ? "any" : iface_;
    handle_ = pcap_open_live(dev.c_str(), 65536, 1, 1000, errbuf_);
    if (!handle_) {
        throw std::runtime_error(std::string("pcap_open_live failed: ") + errbuf_);
    }
    // Try to set immediate mode if supported
    #if PCAP_VERSION_MAJOR >= 1
    if (pcap_setnonblock(handle_, 0, errbuf_) == -1) {
        // non-fatal
    }
    #endif
}

void Sniffer::closeDevice() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void Sniffer::startCapture() {
    if (!handle_) throw std::runtime_error("device not open");
    // Capture loop; use pcap_dispatch to allow break via keep_running
    while (keep_running) {
        int ret = pcap_dispatch(handle_, 10, Sniffer::packetHandler, reinterpret_cast<u_char*>(this));
        if (ret == -1) {
            std::cerr << "pcap_dispatch error: " << pcap_geterr(handle_) << std::endl;
            break;
        }
    }
    std::cout << "Stopping capture..." << std::endl;
}

void Sniffer::packetHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    Sniffer *self = reinterpret_cast<Sniffer*>(user);
    if (!self || !self->logger_) return;
    // Parse packet minimally and log summary
    PacketParser parser(bytes, h->len);
    auto info = parser.parseSummary();
    self->logger_->log(info);
}
