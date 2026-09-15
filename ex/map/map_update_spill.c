/*
 * ex/map/map_update.c with the stored value computed through a volatile
 * temporary: different bytecode, same 7 written to the same slot.
 */
#include "map_common.h"

SEC("xdp") int prog(struct xdp_md *ctx)
{
    __u32 key = ctx->ingress_ifindex;
    __u64 *v = bpf_map_lookup_elem(&counters, &key);
    if (v)
        return 0;
    volatile __u64 half = 3;
    __u64 fresh = half + 4;
    bpf_map_update_elem(&counters, &key, &fresh, BPF_ANY);
    return 0;
}
