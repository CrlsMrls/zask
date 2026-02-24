/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * vmlinux.h — Minimal kernel type definitions for ZASK eBPF programs.
 *
 * This is a hand-maintained subset of the kernel's vmlinux.h containing
 * only the types and fields accessed by ZASK eBPF programs. Adding a field
 * here is safe — CO-RE relocations ensure the loader resolves actual
 * offsets from the running kernel's BTF at load time.
 *
 * To regenerate the complete vmlinux.h from the running kernel:
 *
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
 *
 * The minimal approach is preferred for readability and maintainability.
 * Only add types/fields that are directly accessed via BPF_CORE_READ().
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
 * Filesystem types used for inode-based identification.
 * Fields accessed: inode->i_ino, inode->i_sb->s_dev.
 */
struct super_block
{
  unsigned int s_dev; /* dev_t — encodes major/minor device number */
};

struct inode
{
  unsigned long i_ino;
  struct super_block *i_sb;
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
  struct task_struct *real_parent; /* biological parent (not changed by ptrace) */
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
  BPF_MAP_TYPE_PERCPU_ARRAY = 6,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
  BPF_MAP_TYPE_RINGBUF = 27,
};

/*
 * Errno constants returned by LSM hooks.
 */
#define EPERM 1

#endif /* __VMLINUX_H__ */
