/*
 * The classic-BPF packet loads and BPF_END, one per arm so each can be
 * checked on its own.  Every arm's value is fixed by the seeded ctx and
 * packet, so the expect tests in TestModuleSemantics are hand-computed:
 * load_* convert from network byte order, and BPF_END is a plain byte swap.
 */
#include "sur_common.h"

SEC("filter") int p(struct __sk_buff *skb)
{
    switch (skb->mark) {
        case 0:  return load_word(skb, 4);              /* LD_ABS, 32 bits */
        case 1:  return load_half(skb, 2);              /* LD_ABS, 16 bits */
        case 2:  return load_byte(skb, 1);              /* LD_ABS,  8 bits */
        case 3:  return load_word(skb, skb->cb[0] + 8); /* LD_IND, 32 bits */
        default: return __builtin_bswap32(skb->hash);   /* BPF_END, 32 bits */
    }
}
