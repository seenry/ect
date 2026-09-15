/*
 * ex/ebpf-se/map_access.c writing 2 instead of 1.  Both return XDP_DROP on
 * every path, so the two differ ONLY in what bpf_map_update_elem leaves in the
 * map region.
 */
#include "ebpf_se_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct dummy_key);
	__type(value, long);
	__uint(max_entries, 256);
} rxcnt SEC(".maps");


SEC("xdp_map_acces")
int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct dummy_key key = {0};
	int rc = XDP_DROP;
	long *value;
	u16 h_proto;
	u64 nh_off;
	long dummy_value = 2;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

//	swap_src_dst_mac(data);
//	rc = XDP_TX;

	h_proto = eth->h_proto;
	key.key = 23;
	
	value = bpf_map_lookup_elem(&rxcnt, &key);
	if (value){
		*value += 1;
	}else{
		bpf_map_update_elem(&rxcnt, &key, &dummy_value, BPF_ANY);
	}
	return rc;
}

char _license[] SEC("license") = "GPL";
