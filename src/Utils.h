#pragma once
#include <string>

namespace Utils {
    std::string hexDump(const uint8_t* data, size_t len, size_t maxBytes = 32);
}
