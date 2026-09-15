/* Compile-time check that ebpf_se_common.h reproduces the kernel's layout.  A
   negative array size is a compile error, so a wrong offset breaks `make`
   rather than silently changing what these programs mean. */
#include "ebpf_se_common.h"
char _eth_proto[__builtin_offsetof(struct ethhdr,    h_proto)  == 12 ? 1 : -1];
char _xdp_data [__builtin_offsetof(struct xdp_md,    data)     ==  0 ? 1 : -1];
char _xdp_dend [__builtin_offsetof(struct xdp_md,    data_end) ==  4 ? 1 : -1];
char _xdp_ifidx[__builtin_offsetof(struct xdp_md, ingress_ifindex) == 12 ? 1 : -1];
char _skb_data [__builtin_offsetof(struct __sk_buff, data)     == 76 ? 1 : -1];
char _skb_dend [__builtin_offsetof(struct __sk_buff, data_end) == 80 ? 1 : -1];
char _skb_cb   [__builtin_offsetof(struct __sk_buff, cb)       == 48 ? 1 : -1];
char _dummy_key[sizeof(struct dummy_key) == 1 ? 1 : -1];

/* Map type constants -- see the note in ex/suricata/offsets.c. */
char _t_array       [BPF_MAP_TYPE_ARRAY        == 2 ? 1 : -1];
char _t_percpu_hash [BPF_MAP_TYPE_PERCPU_HASH  == 5 ? 1 : -1];
char _t_percpu_array[BPF_MAP_TYPE_PERCPU_ARRAY == 6 ? 1 : -1];
