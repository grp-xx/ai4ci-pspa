#include <arpa/inet.h>
#include <cerrno>
#include <net/if.h>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <bpf/libbpf.h>

static volatile sig_atomic_t stop_flag = 0;
static void on_sig(int) { stop_flag = 1; }

// must match eBPF struct layout exactly
// Note: in a real application, you might want to use a more robust serialization method
struct ip_pair {
    uint32_t src; // network order
    uint32_t dst; // network order
};

static int handle_event(void*, void* data, size_t size)
{
    if (size < sizeof(ip_pair))
        return 0;

    const auto* e = static_cast<const ip_pair*>(data);

    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];

    in_addr src_addr{ .s_addr = e->src };
    in_addr dst_addr{ .s_addr = e->dst };

    if (!inet_ntop(AF_INET, &src_addr, src_str, sizeof(src_str)))
        std::snprintf(src_str, sizeof(src_str), "<?>");
    if (!inet_ntop(AF_INET, &dst_addr, dst_str, sizeof(dst_str)))
        std::snprintf(dst_str, sizeof(dst_str), "<?>");

    std::printf("%s -> %s\n", src_str, dst_str);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc != 3) {
        std::fprintf(stderr, "Usage: %s <iface> <bpf_obj>\n", argv[0]);
        std::fprintf(stderr, "Example: %s eth0 iplogger_kern.o\n", argv[0]);
        return 1;
    }

    const char* iface = argv[1];
    const char* obj_path = argv[2];

    std::signal(SIGINT, on_sig);
    std::signal(SIGTERM, on_sig);
 
//    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        std::perror("if_nametoindex");
        return 1;
    }

    bpf_object* obj = bpf_object__open_file(obj_path, nullptr);
    if (!obj) {
        std::fprintf(stderr, "Failed to open BPF object: %s\n", obj_path);
        return 1;
    }

    if (bpf_object__load(obj)) {
        std::fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    bpf_program* prog = bpf_object__find_program_by_name(obj, "xdp_ip_pairs");
    if (!prog) {
        std::fprintf(stderr, "Failed to find bpf program xdp_ip_pairs\n");
        bpf_object__close(obj);
        return 1;
    }

    bpf_link* link = bpf_program__attach_xdp(prog, ifindex);
    if (!link) {
        std::fprintf(stderr, "Failed to attach XDP to %s\n", iface);
        bpf_object__close(obj);
        return 1;
    }

    bpf_map* rb_map = bpf_object__find_map_by_name(obj, "rb");
    if (!rb_map) {
        std::fprintf(stderr, "Failed to find ringbuf map 'rb'\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    int rb_fd = bpf_map__fd(rb_map);
    ring_buffer* rb = ring_buffer__new(rb_fd, handle_event, nullptr, nullptr);
    if (!rb) {
        std::fprintf(stderr, "Failed to create ring buffer\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    std::printf("Listening on %s... Ctrl+C to stop.\n", iface);

    while (!stop_flag) {
        int err = ring_buffer__poll(rb, 250);
        if (err < 0 && err != -EINTR) {
            std::fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}