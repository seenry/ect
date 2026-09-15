/*
 * Not a meaningful program: a fixture that makes clang emit every
 * instruction form bpf_to_ir synthesizes rather than maps one-to-one --
 * 32-bit ALU (narrow, operate, widen), ARSH, DIV/MOD, NEG, BPF_END, JSET,
 * JMP32, and the signed and "or equal" jump forms that are compiled by
 * testing the complementary condition and swapping the arms.
 *
 * Those paths have no natural coverage in the real programs in ex/, so
 * without this a change to emit_condition or the ALU narrowing could be
 * wrong in a way nothing here would notice.  Straight-line and
 * forward-branching only, so it translates.
 */
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;

#define SEC(N) __attribute__((section(N), used))
struct xdp_md { __u32 data, data_end, data_meta, ingress_ifindex, rx_queue_index; };

SEC("xdp") int prog(struct xdp_md *ctx)
{
    __u64 a = ctx->ingress_ifindex;
    __u64 b = ctx->rx_queue_index;
    __u32 x = (__u32)a;
    __u32 y = (__u32)b;

    switch (ctx->data_meta) {
        /* 32-bit ALU: narrow, operate at W32, widen back. */
        case 0:  return x + y;
        case 1:  return x - y;
        case 2:  return x & y;
        case 3:  return x | y;
        case 4:  return x ^ y;
        case 5:  return x * y;
        case 6:  return x + 12345;
        case 7:  return (__u32)(-(__s32)x);
        /* shifts: constant only, lowered to multiply/divide */
        case 8:  return (__u32)(x << 3);
        case 9:  return (__u32)(x >> 3);
        case 10: return (__u32)(((__s32)x) >> 3);        /* ARSH at 32 */
        case 11: return (__u32)(((__s64)a) >> 5);        /* ARSH at 64 */
        /* division and remainder */
        case 12: return (__u32)(a / 7);
        case 13: return (__u32)(a % 7);
        case 14: return (__u32)(a * b);
        case 15: return (__u32)(-a);                     /* NEG at 64 */
        /* byte swaps -> BPF_END at three widths */
        case 16: return __builtin_bswap16((unsigned short)a);
        case 17: return __builtin_bswap32(x);
        case 18: return (__u32)__builtin_bswap64(a);
        /* JSET: a bit test, which has no comparison form */
        case 19: if (a & 0x40) return 1; return 2;
        case 20: if (a & b)    return 3; return 4;
        /* JMP32: 32-bit compares */
        case 21: if (x == 9)   return 5; return 6;
        case 22: if (x >  9)   return 7; return 8;
        case 23: if (x <  9)   return 9; return 10;
        /* unsigned "or equal" and less-than forms */
        case 24: if (a >= 100) return 11; return 12;
        case 25: if (a <= 100) return 13; return 14;
        case 26: if (a <  100) return 15; return 16;
        /* signed compares, biased into unsigned by flipping the sign bit */
        case 27: if ((__s64)a >  (__s64)b) return 17; return 18;
        case 28: if ((__s64)a >= (__s64)b) return 19; return 20;
        case 29: if ((__s64)a <  (__s64)b) return 21; return 22;
        case 30: if ((__s64)a <= (__s64)b) return 23; return 24;
        /* a wide immediate that is not a map address */
        case 31: return (__u32)(a + 0x1234567890abcdefULL);
        default: return 0;
    }
}
