cmake_minimum_required(VERSION 3.5)
project(packet_sniffer)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/src)
link_directories(${PCAP_LIBRARY_DIRS})

add_executable(packet_sniffer
    src/main.cpp
    src/Sniffer.cpp
    src/PacketParser.cpp
    src/Logger.cpp
    src/Utils.cpp
)

target_link_libraries(packet_sniffer ${PCAP_LIBRARIES})
