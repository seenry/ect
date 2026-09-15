/*
 * ex/ebpf-se/xdp_pktcntr.c incrementing the counter by 2 instead of 1.
 *
 * Both return XDP_PASS on every path and both touch exactly the same map cells,
 * so the emitted packet and every access extent are identical.  The two differ
 * only in the value left in the map region, which is what shows the checker
 * compares final region contents.
 */
#include "ebpf_se_common.h"

#define CTRL_ARRAY_SIZE 2
#define CNTRS_ARRAY_SIZE 512




struct bpf_map_def SEC("maps") ctl_array = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = CTRL_ARRAY_SIZE,
};

struct bpf_map_def SEC("maps") cntrs_array = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u64),
  .max_entries = CNTRS_ARRAY_SIZE,
};

SEC("xdp-pktcntr")
int pktcntr(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  __u32 ctl_flag_pos = 0;
  __u32 cntr_pos = 0;
  __u32* flag = bpf_map_lookup_elem(&ctl_array, &ctl_flag_pos);

  if (!flag || (*flag == 0)) {
    return XDP_PASS;
  };


  __u64* cntr_val = bpf_map_lookup_elem(&cntrs_array, &cntr_pos);
  if (cntr_val) {
    *cntr_val += 2;
  };
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
