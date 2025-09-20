#pragma once
#include <string>
#include <cstdint>

class PacketParser {
public:
    PacketParser(const uint8_t* data, size_t len);
    ~PacketParser() = default;

    // Return a one-line summary for logging
    std::string parseSummary();

private:
    const uint8_t* data_;
    size_t len_;

    std::string parseEthernet();
    std::string parseIP(const uint8_t* payload, size_t payload_len);
    std::string parseTransport(uint8_t proto, const uint8_t* payload, size_t payload_len);
    static std::string toHex(const uint8_t* d, size_t n);
};
