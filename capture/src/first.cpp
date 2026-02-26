#include <iostream>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

struct counter_t {
    uint64_t pckts;
    uint64_t bytes;
};

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) 
{
    // std::cout << header->ts.tv_sec << "." << header->ts.tv_usec << " Captured a packet with length: " << header->len << " bytes" << std::endl;
    counter_t *ctr = reinterpret_cast<counter_t*>(user);
    ctr->pckts += 1;
    ctr->bytes += header->len;
//    struct ether_header *eth_hdr = (struct ether_header*) packet;
    const struct ether_header *eth_hdr = reinterpret_cast<const ether_header*>(packet);
//    std::cout << "Ethernet Type: " << std::hex << ntohs(eth_hdr->ether_type) << std::dec << std::endl;
    if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
        // const struct ip *ip_hdr = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
        const struct ip *ip_hdr = reinterpret_cast<const struct ip*>(eth_hdr + 1);
        std::cout << "Captured an IP packet from " << inet_ntoa(ip_hdr->ip_src) 
                  << " to " << inet_ntoa(ip_hdr->ip_dst) 
                  << " with length: " << header->len << " bytes" << std::endl;
    }

};

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " -[i|f] <interface|pcap_file> <filter>" << std::endl;
        return 1;
    }

//     handle = pcap_open_offline("smallFlows.pcap", errbuf);

    if (argv[1][0] == '-' && argv[1][1] == 'i') {
        handle = pcap_open_live(argv[2], 64, 1, 500, errbuf);
    } else if (argv[1][0] == '-' && argv[1][1] == 'f') {
        handle = pcap_open_offline(argv[2], errbuf);
    } else {
        std::cerr << "Invalid option: " << argv[1] << std::endl;
        return 1;
    }

    if (handle == nullptr) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        return 1;
    }    
   
//    for (int i = 0; i < 20; ++i) {
//        struct pcap_pkthdr hdr;
//        const u_char *packet;
//
//        // Capture a packet
//        packet = pcap_next(handle, &hdr);
//
//        if (packet == nullptr) {
//            std::cerr << "No packet captured." << std::endl;
//            continue;
//        }
//
//        // Print the length of the captured packet
//    std::cout << hdr.ts.tv_sec << "." << hdr.ts.tv_usec << " Captured a packet with length: " << hdr.len << " bytes" << std::endl;
//    }

    auto filter =argv[3];
    struct bpf_program filter_prog;
    pcap_compile(handle, &filter_prog, filter, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &filter_prog);

    struct counter_t ctr = {0, 0};

    pcap_loop(handle, 20, packet_handler, reinterpret_cast<u_char*>(&ctr));
//    pcap_loop(handle, 20, packet_handler, (u_char*)(&ctr));

    // Close the handle after use
    pcap_close(handle);

    std::cout << "Total packets captured: " << ctr.pckts << std::endl;
    std::cout << "Total bytes captured: " << ctr.bytes << std::endl;


    return 0;
}