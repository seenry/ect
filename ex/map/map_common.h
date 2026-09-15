/*
 * Shared declarations for the ex/map_*.c family: one legacy-style BPF map and
 * the lookup helper.  The four programs differ only in what they do with the
 * result, which is what makes them a discrimination test for the map model.
 */
#ifndef MAP_COMMON_H
#define MAP_COMMON_H

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(N) __attribute__((section(N), used))

struct bpf_map_def {
    __u32 type, key_size, value_size, max_entries, map_flags;
};

struct bpf_map_def SEC("maps") counters = {
    .type = 1 /* BPF_MAP_TYPE_HASH -- see the note above on families */,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 64,
    .map_flags = 0,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *) 2;

#define BPF_ANY 0

struct xdp_md {
    __u32 data, data_end, data_meta, ingress_ifindex, rx_queue_index;
};

#endif
