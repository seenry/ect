/*
 * ex/ebpf-se/cls_pktcntr.c returning TC_ACT_SHOT where the control flag is
 * unset, instead of TC_ACT_OK.  This program never writes to a map, so a
 * difference in the emitted return value is what shows the ctl_array lookup
 * reaches the output at all.
 *
 * Needs --ctx=__sk_buff, like the program it derives from.
 */
#include "ebpf_se_common.h"

#define CTRL_ARRAY_SIZE 2
#define CNTRS_ARRAY_SIZE 512



/*
 * map_fd #0
 */

struct bpf_map_def SEC("maps") ctl_array = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = CTRL_ARRAY_SIZE,
};


/*
 * map_fd #1
 */
struct bpf_map_def SEC("maps") cntrs_array = {
 // @lint-ignore TXT2 T25377293 Grandfathered in
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u64),
  .max_entries = CNTRS_ARRAY_SIZE,
};

SEC("cls-pktcntr")
int pktcntr(struct __sk_buff *skb) {
  __u32 ctl_flag_pos = 0;
  __u32 cntr_pos = 0;
  __u32* flag = bpf_map_lookup_elem(&ctl_array, &ctl_flag_pos);

  if (!flag || (*flag == 0)) {
    return TC_ACT_SHOT;
  };


  __u64* cntr_val = bpf_map_lookup_elem(&cntrs_array, &cntr_pos);
  if (cntr_val) {
    *cntr_val += 1;
  };
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
