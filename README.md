
# Packet Sniffer (C++)

This is a modular packet sniffer implemented in **C++17** using **libpcap**.  
It is a conversion of the original Python-based project.

## Features
- Captures packets from any network interface using libpcap.
- Parses Ethernet and IPv4 headers.
- Extracts source/destination IPs and ports.
- Logs summaries with timestamps to `packets.log`.
- Modular design:
  - `Sniffer` – manages packet capture.
  - `PacketParser` – decodes packets.
  - `Logger` – writes packet info to log file.
  - `Utils` – helper functions.

## Build Instructions
1. Install dependencies:
   ```bash
   sudo apt update
   sudo apt install libpcap-dev cmake g++
