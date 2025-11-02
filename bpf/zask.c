// SPDX-License-Identifier: GPL-2.0-only
// ZASK - Zero-trust AI-Secured Kernel
//
// Placeholder eBPF program for Phase 0 toolchain validation.
// This will be replaced with the full LSM gatekeeper in Phase 1.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// inode_key uniquely identifies a file across filesystems.
struct inode_key
{
  __u64 inode_number;
  __u32 device_id;
};

// verdict_map stores per-inode enforcement decisions.
// Key: inode_key, Value: u32 (0 = ALLOW, 1 = BLOCK).
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct inode_key);
  __type(value, __u32);
} verdict_map SEC(".maps");

// placeholder_prog is a minimal LSM hook that always allows execution.
// Phase 1 will replace this with the full bprm_check_security enforcement.
SEC("lsm/bprm_check_security")
int BPF_PROG(zask_bprm_check, struct linux_binprm *bprm)
{
  return 0; // Allow all — placeholder only
}
