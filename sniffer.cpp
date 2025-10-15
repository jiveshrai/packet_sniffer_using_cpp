#include <pcap.h>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <netinet/if_ether.h> // For Ethernet header
#include <netinet/ip.h>       // For IP header
#include <netinet/ip_icmp.h>  // For ICMP
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>

using namespace std;

// Global variables
string proto_filter = "0";
ofstream log_file;

// Function to get timestamp as string
string current_time() {
    time_t now = time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buf);
}

// Packet callback function
void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ether_header* eth = (struct ether_header*) packet;

    string protocol;
    if (ntohs(eth->ether_type) == ETHERTYPE_ARP) protocol = "ARP";
    else if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
        if (ip_hdr->ip_p == IPPROTO_ICMP) protocol = "ICMP";
        else protocol = "IP";
    } else protocol = "OTHER";

    // Apply protocol filter
    if (proto_filter != "0" && protocol != proto_filter) return;

    // Log MAC addresses
    char src_mac[18], dst_mac[18];
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
             eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
             eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    log_file << "Time: " << current_time() << " Protocol: " << protocol
             << " SMAC: " << src_mac << " DMAC: " << dst_mac << endl;
}

int main() {
    string interface;
    int pkt_count;
    int timeout_sec;
    char errbuf[PCAP_ERRBUF_SIZE];

    cout << "* Enter the interface on which to run the sniffer (e.g. eth0): ";
    cin >> interface;

    cout << "* Enter the number of packets to capture (0 for infinity): ";
    cin >> pkt_count;

    cout << "* Enter the number of seconds to run the capture: ";
    cin >> timeout_sec;

    cout << "* Enter the protocol to filter by (arp|icmp|bootp|0 for all): ";
    cin >> proto_filter;
    if (proto_filter == "bootp") proto_filter = "udp port 67 or udp port 68"; // BOOTP filter

    string filename;
    cout << "* Please give a name to the log file: ";
    cin >> filename;

    log_file.open(filename, ios::app);
    if (!log_file.is_open()) {
        cerr << "Error opening log file!" << endl;
        return 1;
    }

    cout << "\n* Starting the capture...\n";

    // Build the BPF filter string
    string filter_exp = (proto_filter == "0") ? "" : proto_filter;

    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Couldn't open device " << interface << ": " << errbuf << endl;
        return 1;
    }

    // Compile and apply filter
    struct bpf_program fp;
    if (!filter_exp.empty()) {
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
            return 1;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
            return 1;
        }
    }

    if (pkt_count == 0) {
        // Capture until timeout
        time_t start_time = time(nullptr);
        while (difftime(time(nullptr), start_time) < timeout_sec) {
            pcap_dispatch(handle, -1, packet_handler, nullptr);
        }
    } else {
        pcap_loop(handle, pkt_count, packet_handler, nullptr);
    }

    cout << "\n* Capture finished. Check " << filename << " for captured packets.\n";

    pcap_close(handle);
    log_file.close();
    return 0;
}
