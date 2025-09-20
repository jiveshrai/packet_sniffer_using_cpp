#include "PacketParser.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>

PacketParser::PacketParser(const uint8_t* data, size_t len) : data_(data), len_(len) {}

std::string PacketParser::parseSummary() {
    // Minimal parsing: Ethernet -> IPv4 -> TCP/UDP
    std::ostringstream os;
    os << "len=" << len_;
    try {
        os << " " << parseEthernet();
    } catch (...) {
        os << " parse_error";
    }
    return os.str();
}

std::string PacketParser::parseEthernet() {
    if (len_ < 14) return "eth:truncated";
    const uint8_t* d = data_;
    uint16_t ethertype = (d[12] << 8) | d[13];
    std::ostringstream os;
    os << "ethertype=0x" << std::hex << ethertype << std::dec;
    if (ethertype == 0x0800) { // IPv4
        const uint8_t* ip_payload = d + 14;
        size_t ip_len = len_ - 14;
        os << " ipv4=" << parseIP(ip_payload, ip_len);
    }
    return os.str();
}

std::string PacketParser::parseIP(const uint8_t* payload, size_t payload_len) {
    if (payload_len < 20) return "ip:truncated";
    uint8_t ver_ihl = payload[0];
    uint8_t ihl = (ver_ihl & 0x0F) * 4;
    if (payload_len < ihl) return "ip:truncated";
    uint8_t proto = payload[9];
    uint32_t src, dst;
    memcpy(&src, payload + 12, 4);
    memcpy(&dst, payload + 16, 4);
    char ssrc[INET_ADDRSTRLEN], sdst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src, ssrc, sizeof(ssrc));
    inet_ntop(AF_INET, &dst, sdst, sizeof(sdst));
    std::ostringstream os;
    os << ssrc << ":";
    if (payload_len >= ihl + 2) {
        uint16_t sport = (payload[ihl] << 8) | payload[ihl+1];
        os << sport;
    } else os << "?";
    os << "->" << sdst << ":";
    if (payload_len >= ihl + 4) {
        uint16_t dport = (payload[ihl+2] << 8) | payload[ihl+3];
        os << dport;
    } else os << "?";
    os << " proto=" << int(proto);
    // transport parsing could be added
    return os.str();
}

std::string PacketParser::parseTransport(uint8_t proto, const uint8_t* payload, size_t payload_len) {
    // Not used in minimal summary
    return std::string();
}

std::string PacketParser::toHex(const uint8_t* d, size_t n) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (size_t i=0;i<n;i++) os << std::setw(2) << int(d[i]);
    os << std::dec;
    return os.str();
}
