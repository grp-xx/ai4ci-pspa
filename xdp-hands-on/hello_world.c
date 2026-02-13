#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")

int print_all(struct xdp_md* ctx) 
{
	bpf_printk("Hello World! Packet received");
	return XDP_PASS;
}
char _license[] SEC("license") = "GPL";


	
