#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <map_id>" << std::endl;
        return 1;
    }
    __u32 map_id = std::stoi(argv[1]);

    // Open the BPF map using its ID
    int map_fd = bpf_map_get_fd_by_id(map_id);
    if (map_fd < 0) {
        std::cerr << "Failed to get BPF map file descriptor" << std::endl;
        return 1;
    }
    
    // Read and print the counters for IP and non-IP packets

    for(;;) {
        __u32 key = 0; // Key for IP packets
        __u64 value;
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            std::cout << "IP Packet Count: " << value << std::endl;
        } else {
            std::cerr << "Failed to read IP packet count" << std::endl;
        }

        key = 1; // Key for non-IP packets
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            std::cout << "Non-IP Packet Count: " << value << std::endl;
        } else {
            std::cerr << "Failed to read non-IP packet count" << std::endl; 
        }
        std::cout << "-----------------------------" << std::endl;
        sleep(1); // Sleep for a while before the next read
    }
}