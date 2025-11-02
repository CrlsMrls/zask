/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * vmlinux.h — Minimal kernel type definitions for ZASK eBPF programs.
 *
 * This is a minimal vmlinux.h containing only the types needed for the
 * current eBPF programs. For Phase 1+, regenerate the full vmlinux.h from
 * a running kernel with BTF support:
 *
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
 *
 * CO-RE (Compile Once – Run Everywhere) uses these type definitions at
 * compile time to generate relocation records. The kernel's BTF at load
 * time provides the actual field offsets, so a single vmlinux.h works
 * across kernel versions.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* Prevent libbpf/standard headers from being included alongside vmlinux.h */
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

/*
 * Primitive types
 */
typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef int __s32;
typedef __s32 s32;
typedef __s64 s64;

typedef _Bool bool;

/*
 * Network and checksum types (required by bpf_helper_defs.h)
 */
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

/*
 * Filesystem types used for inode-based identification
 */
struct inode
{
  unsigned long i_ino;
  /* dev_t i_rdev is not directly accessible; use CO-RE helpers */
};

struct file
{
  struct inode *f_inode;
};

struct path
{
  void *mnt;
  void *dentry;
};

/*
 * linux_binprm — passed to lsm/bprm_check_security
 *
 * This struct represents a binary being prepared for execution.
 * The LSM hook receives a pointer to this before the process memory
 * space is mapped.
 */
struct linux_binprm
{
  struct file *file;
  int argc;
  int envc;
  const char *filename;
};

/*
 * Task and credential types for process context
 */
struct task_struct
{
  int pid;
  int tgid;
  unsigned int flags;
  struct task_struct *parent;
  const struct cred *real_cred;
  char comm[16];
};

struct cred
{
  unsigned int uid;
  unsigned int gid;
  unsigned int euid;
  unsigned int egid;
};

/*
 * Signal types for lsm/task_kill (self-protection)
 */
struct kernel_siginfo
{
  int si_signo;
};

#pragma clang attribute pop

/*
 * BPF map types (subset used by ZASK)
 */
enum bpf_map_type
{
  BPF_MAP_TYPE_HASH = 1,
  BPF_MAP_TYPE_ARRAY = 2,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
  BPF_MAP_TYPE_RINGBUF = 27,
};

#endif /* __VMLINUX_H__ */
