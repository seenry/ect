/*
 * A lookup followed, on a miss, by an update: the shape almost every real map
 * program has.  The RETURN value is the same on both arms, so the only thing
 * that distinguishes this from ex/map/map_update_differs.c is the final
 * contents of the map region -- which is what makes it a test that the checker
 * compares regions, not just output.
 */
#include "map_common.h"

SEC("xdp") int prog(struct xdp_md *ctx)
{
    __u32 key = ctx->ingress_ifindex;
    __u64 *v = bpf_map_lookup_elem(&counters, &key);
    if (v)
        return 0;
    __u64 fresh = 7;
    bpf_map_update_elem(&counters, &key, &fresh, BPF_ANY);
    return 0;
}
