/*
 * ex/vlan_filter.c accepting VLAN 3 and 5 instead of 2 and 4.  Its only job is
 * to be DIFFERENT: the checker reporting these two inequivalent is what shows
 * vlan_filter is really being run rather than rejected out of hand, which is
 * what happened while the ctx region was modelled as struct xdp_md's 20 bytes
 * and every __sk_buff field access overran it.
 *
 * Upstream: https://github.com/OISF/suricata (GPL-2.0-only)
 * Copyright (C) 2018 Open Information Security Foundation
 */
#include "sur_common.h"

int SEC("filter") hashfilter(struct __sk_buff *skb) {
    __u16 vlan_id = skb->vlan_tci & 0x0fff;
    /* accept VLAN 3 and 5 and drop the rest */
    switch (vlan_id) {
        case 3:
        case 5:
            return -1;
        default:
            return 0;
    }
    return 0;
}
