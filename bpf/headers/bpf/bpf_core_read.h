/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * bpf_core_read.h — CO-RE (Compile Once, Run Everywhere) read helpers.
 *
 * Provides BPF_CORE_READ() macro for type-safe, relocatable field access
 * from kernel data structures. Uses __builtin_preserve_access_index()
 * to emit BTF-based field offset relocations, enabling the eBPF loader
 * to adjust offsets at load time for the running kernel.
 */

#ifndef __BPF_CORE_READ_H__
#define __BPF_CORE_READ_H__

/*
 * bpf_core_read() — Read sz bytes from src into dst with CO-RE relocation.
 *
 * Wraps bpf_probe_read_kernel() with __builtin_preserve_access_index()
 * so that the compiler emits BTF relocations for the source address.
 */
#define bpf_core_read(dst, sz, src) \
  bpf_probe_read_kernel(dst, sz,    \
                        (const void *)__builtin_preserve_access_index(src))

/*
 * bpf_core_read_str() — Read a NUL-terminated string with CO-RE relocation.
 */
#define bpf_core_read_str(dst, sz, src) \
  bpf_probe_read_kernel_str(dst, sz,    \
                            (const void *)__builtin_preserve_access_index(src))

/*
 * BPF_CORE_READ() — Read a single field from a struct pointer.
 *
 * Usage:
 *     struct inode *inode = BPF_CORE_READ(file, f_inode);
 *     __u64 ino = BPF_CORE_READ(inode, i_ino);
 *
 * For chained reads (e.g., file->f_inode->i_ino), break them into
 * individual BPF_CORE_READ() calls for clarity and verifier safety.
 */
#define BPF_CORE_READ(src, field)                    \
  ({                                                 \
    typeof((src)->field) __r;                        \
    bpf_core_read(&__r, sizeof(__r), &(src)->field); \
    __r;                                             \
  })

#endif /* __BPF_CORE_READ_H__ */
