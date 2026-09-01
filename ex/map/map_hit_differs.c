/* map_ref, except that the threshold on the looked-up value is 101 rather than
   100.  Distinguishing this from map_ref is what shows the hit arm is
   reachable and that the value really comes out of the map region. */
#include "map_common.h"

SEC("xdp") int prog(struct xdp_md *ctx)
{
    __u32 key = ctx->ingress_ifindex;
    __u64 *v = bpf_map_lookup_elem(&counters, &key);
    if (!v)
        return 1;
    if (*v > 101)
        return 2;
    return 0;
}
