/* map_ref, except that a lookup miss returns 3 rather than 1.  Distinguishing
   this from map_ref is what shows the NULL arm of a lookup is reachable. */
#include "map_common.h"

SEC("xdp") int prog(struct xdp_md *ctx)
{
    __u32 key = ctx->ingress_ifindex;
    __u64 *v = bpf_map_lookup_elem(&counters, &key);
    if (!v)
        return 3;
    if (*v > 100)
        return 2;
    return 0;
}
