// +build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>


struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 3);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &jmp_table, 0);
	return 1;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &jmp_table, 0);
	return 1;
}
