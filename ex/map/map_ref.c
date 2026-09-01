/* The reference map program.  ex/map_spill.c is equivalent to it;
   ex/map_miss_differs.c and ex/map_hit_differs.c are not. */
#include "map_common.h"

SEC("xdp") int prog(struct xdp_md *ctx)
{
    __u32 key = ctx->ingress_ifindex;
    __u64 *v = bpf_map_lookup_elem(&counters, &key);
    if (!v)
        return 1;
    if (*v > 100)
        return 2;
    return 0;
}
