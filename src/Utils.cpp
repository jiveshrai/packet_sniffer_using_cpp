#include "Utils.h"
#include <sstream>
#include <iomanip>

namespace Utils {
    std::string hexDump(const uint8_t* data, size_t len, size_t maxBytes) {
        std::ostringstream os;
        size_t n = std::min(len, maxBytes);
        os << std::hex << std::setfill('0');
        for (size_t i = 0; i < n; ++i) {
            os << std::setw(2) << int(data[i]) ;
            if (i+1 < n) os << ' ';
        }
        os << std::dec;
        return os.str();
    }
}
