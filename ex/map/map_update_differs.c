/*
 * ex/map/map_update.c writing 9 instead of 7.  Both return 0 on every path, so
 * the two differ ONLY in what the update leaves in the map region.  The checker
 * separating them is what shows it compares final region contents.
 */
#include "map_common.h"

SEC("xdp") int prog(struct xdp_md *ctx)
{
    __u32 key = ctx->ingress_ifindex;
    __u64 *v = bpf_map_lookup_elem(&counters, &key);
    if (v)
        return 0;
    __u64 fresh = 9;
    bpf_map_update_elem(&counters, &key, &fresh, BPF_ANY);
    return 0;
}
