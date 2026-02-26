#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct ip_pair {
    __u32 src;  // network byte order
    __u32 dst;  // network byte order
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB ringbuf (tune as needed)
} rb SEC(".maps");

SEC("xdp")
int xdp_ip_pairs(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // IPv4
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Validate IHL (header length)
    __u32 ihl_bytes = ip->ihl * 4;
    if (ihl_bytes < sizeof(*ip))
        return XDP_PASS;
    if ((void *)ip + ihl_bytes > data_end)
        return XDP_PASS;

    // Reserve event
    struct ip_pair *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return XDP_PASS; // drop event if buffer full

    e->src = ip->saddr;
    e->dst = ip->daddr;

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}