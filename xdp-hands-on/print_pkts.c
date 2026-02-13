#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

SEC("xdp")
int print_all(struct xdp_md* ctx) 
{
	bpf_printk("Hello World! Packet received");
	return XDP_PASS;
}

SEC("xdp")
int print_ip(struct xdp_md* ctx) 
{
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr* eth = data;

	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_ABORTED;  // Packet is too short, abort processing
	}

//	if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
//		bpf_printk("Hello! Welcome IP Packet!");
//	}
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		bpf_printk("Hello! Welcome IP Packet from interface %d!", ctx->ingress_ifindex);
	}
	return XDP_PASS;  // For all other packets, pass them to the next layer

}

char _license[] SEC("license") = "GPL";


	
