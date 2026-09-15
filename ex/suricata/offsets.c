/* Compile-time check that sur_common.h reproduces the kernel's layout.  A
   negative array size is a compile error, so a wrong offset breaks `make`
   rather than silently changing what these programs mean -- bpf_to_ir turns
   each field access into a load at that offset into the ctx or packet region,
   so a wrong one still translates, still runs and still discriminates, just
   against a different field.

   Every field any program in this directory reads needs a line here.  The
   struct is a truncated PREFIX of the kernel's (88 bytes against the 192
   bpf_to_ir models), which is fine because only the offsets are used, but it
   does mean sizeof() is not the thing to check. */
#include "sur_common.h"

/* Packet headers, read via LD_ABS/LD_IND. */
char _eth_proto[__builtin_offsetof(struct ethhdr,   h_proto) == 12 ? 1 : -1];
char _ip_saddr [__builtin_offsetof(struct iphdr,    saddr)   == 12 ? 1 : -1];
char _ip_daddr [__builtin_offsetof(struct iphdr,    daddr)   == 16 ? 1 : -1];
char _v6_saddr [__builtin_offsetof(struct ipv6hdr,  saddr)   ==  8 ? 1 : -1];
char _v6_daddr [__builtin_offsetof(struct ipv6hdr,  daddr)   == 24 ? 1 : -1];

/* Context fields.  These are the ones bpf_to_ir's ctx_sk_buff layout has to
   agree with; vlan_tci is the only field vlan_filter.c reads at all, and was
   the one field this check used to miss. */
char _skb_mark [__builtin_offsetof(struct __sk_buff, mark)     ==  8 ? 1 : -1];
char _skb_proto[__builtin_offsetof(struct __sk_buff, protocol) == 16 ? 1 : -1];
char _skb_vtci [__builtin_offsetof(struct __sk_buff, vlan_tci) == 24 ? 1 : -1];
char _skb_cb   [__builtin_offsetof(struct __sk_buff, cb)       == 48 ? 1 : -1];
char _skb_hash [__builtin_offsetof(struct __sk_buff, hash)     == 68 ? 1 : -1];
char _skb_data [__builtin_offsetof(struct __sk_buff, data)     == 76 ? 1 : -1];
char _skb_dend [__builtin_offsetof(struct __sk_buff, data_end) == 80 ? 1 : -1];

/* Map type constants.  These decide which FAMILY the translator models a map
   as, and the families disagree about what a key means -- an array's in-range
   lookup can never miss, a hash's can.  A wrong value here silently changes
   what the program means, exactly like a wrong field offset. */
char _t_percpu_hash[BPF_MAP_TYPE_PERCPU_HASH == 5 ? 1 : -1];
