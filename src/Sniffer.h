#pragma once
#include <string>
#include <pcap/pcap.h>
#include "Logger.h"

class Sniffer {
public:
    Sniffer(const std::string &iface, Logger* logger);
    ~Sniffer();

    void startCapture();
    std::string getInterface() const { return iface_.empty() ? "any" : iface_; }

private:
    static void packetHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
    void openDevice();
    void closeDevice();

    std::string iface_;
    pcap_t *handle_{nullptr};
    char errbuf_[PCAP_ERRBUF_SIZE];
    Logger* logger_;
};
