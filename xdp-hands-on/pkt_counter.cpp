#include <iostream>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <xdp_kern_prog.o> <iface>" << std::endl;
        return 1;
    }

   auto xdp_prog = xdp_program__open_file(argv[1], "xdp", nullptr);
    if (!xdp_prog) {
        std::cerr << "Failed to open BPF object file" << std::endl;
        return 1;
    }

    auto ret = xdp_program__attach(xdp_prog, if_nametoindex(argv[2]), XDP_MODE_NATIVE, 0);

    if (ret < 0) {
        std::cerr << "Failed to attach XDP program" << std::endl;
        return 1;
    }   
    // Read and print the counters for IP and non-IP packets

    auto obj = xdp_program__bpf_obj(xdp_prog);
    auto map_fd = bpf_object__find_map_fd_by_name(obj, "rxcnt");
    if (!map_fd) {
        std::cerr << "Failed to find BPF map" << std::endl;
        return 1;
    }

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