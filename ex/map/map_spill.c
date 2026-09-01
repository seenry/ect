/* map_ref with the value round-tripped through a volatile stack slot: two more
   instructions and a different block structure, same meaning. */
#include "map_common.h"

SEC("xdp") int prog(struct xdp_md *ctx)
{
    __u32 key = ctx->ingress_ifindex;
    __u64 *v = bpf_map_lookup_elem(&counters, &key);
    if (!v)
        return 1;
    volatile __u64 tmp = *v;
    if (tmp > 100)
        return 2;
    return 0;
}
