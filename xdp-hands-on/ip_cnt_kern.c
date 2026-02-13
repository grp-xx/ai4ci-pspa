#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);  // IP address as key
	__type(value, __u64); // Counter as value
} rxcnt SEC(".maps");

SEC("xdp")
int count_ip(struct xdp_md* ctx) 
{
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr* eth = data;

	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_ABORTED;  // Packet is too short, abort processing
	}

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		// update a counter for IP packets (this is just a placeholder, you can implement your own logic herie)
		__u32 key = 0; // You can use the source IP address as the key
		__u64* value = bpf_map_lookup_elem(&rxcnt, &key);
		if (value) { 
			__sync_fetch_and_add(value, 1); // Increment the counter atomically
		}
	} else {
		// count non IP packets by incrementin the counter at index 1
		__u32 key = 1; // Use index 1 for non-IP packets	
		__u64* value = bpf_map_lookup_elem(&rxcnt, &key);  // helper function to lookup the value in the map
		if (value) { 
			__sync_fetch_and_add(value, 1); // Increment the counter atomically of non IP packets
		}
	}
	return XDP_PASS;  // For all other packets, pass them to the next layer
}

char _license[] SEC("license") = "GPL";


	
