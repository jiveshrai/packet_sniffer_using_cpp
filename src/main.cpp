#include "Sniffer.h"
#include "Logger.h"
#include <iostream>

int main(int argc, char** argv) {
    std::string iface = (argc > 1) ? argv[1] : "";
    std::string logfile = "packets.log";
    Logger logger(logfile);

    try {
        Sniffer sniffer(iface, &logger);
        std::cout << "Starting packet capture on interface: " << sniffer.getInterface() << std::endl;
        sniffer.startCapture(); // runs until interrupted (Ctrl+C)
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
