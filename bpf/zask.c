// SPDX-License-Identifier: GPL-2.0-only
//
// ZASK — Zero-trust AI-Secured Kernel
//
// eBPF LSM programs for kernel-native binary execution control.
//
// Programs:
//   zask_bprm_check  — LSM gatekeeper on bprm_check_security (Tier 1).
//   zask_task_kill    — Self-protection hook preventing unauthorized
//                       signals to the ZASK daemon.
//
// Maps:
//   verdict_map     — Hash map: inode_key → verdict (ALLOW/BLOCK).
//   events          — Ring buffer exporting telemetry to user-space.
//   protected_pids  — Hash map of PIDs shielded from SIGKILL/SIGTERM.
//   drop_counter    — Per-CPU counter tracking ring buffer overflows.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Maximum buffer size for argv/filename extraction (§1.2.3).
// Strings exceeding this limit are silently truncated. The Go consumer
// must be aware that the field may not be NUL-terminated when the
// source string exceeds ARGV_MAX - 1 bytes.
#define ARGV_MAX 256

// Verdict constants for verdict_map values.
#define VERDICT_ALLOW 0
#define VERDICT_BLOCK 1

// Signal numbers for self-protection hook.
#define SIG_KILL 9
#define SIG_TERM 15

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

// inode_key uniquely identifies a file across filesystems.
// Used as the key for verdict_map lookups.
struct inode_key
{
  __u64 inode_number;
  __u32 device_id;
};

// event is the telemetry record exported to user-space via the ring buffer.
// The Go struct in internal/ebpf must mirror this layout exactly —
// bpf2go generates it from BTF metadata, so keeping this struct in the
// -type flag of the go:generate directive ensures alignment.
//
// Field order is chosen to minimise padding: u64 fields first, then u32,
// then u8 and the trailing char array.
struct event
{
  __u64 inode_number;
  __u64 cgroup_id;
  __u32 pid;
  __u32 ppid;
  __u32 uid;
  __u32 device_id;
  __u8 is_map_hit;            // 1 if verdict_map contained an entry
  char argv[ARGV_MAX];        // executable filename (truncated to ARGV_MAX)
  char script_argv[ARGV_MAX]; // raw argv[1] — may be a flag; Go engine resolves via procfs
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// verdict_map stores per-inode enforcement decisions (§1.3).
//
// Key:   inode_key {inode_number, device_id}
// Value: __u32 — VERDICT_ALLOW (0) or VERDICT_BLOCK (1)
//
// Capacity: 10 000 entries. Each entry is ~20 bytes (16-byte key + 4-byte
// value), so full occupancy uses ~200 KB of kernel memory. Increase
// max_entries for environments monitoring more than 10 000 unique binaries,
// but note that hash-map lookup remains O(1) regardless of size.
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, struct inode_key);
  __type(value, __u32);
} verdict_map SEC(".maps");

// events is the ring buffer for exporting telemetry to user-space (§1.4).
//
// Size: 256 KB (must be a power of 2 and a multiple of the page size).
// At ~300 bytes per event, this holds ~850 events before overflowing.
// Overflow is non-fatal — the per-CPU drop_counter is incremented.
//
// The __type(value, ...) annotation is not required by ring buffers at
// runtime, but ensures bpf2go includes 'struct event' in its BTF output
// so the Go binding struct is auto-generated.
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
  __type(value, struct event);
} events SEC(".maps");

// protected_pids stores PIDs shielded from unauthorized kill signals
// (§1.5). Populated by the Go orchestrator at startup with the daemon's
// own PID (and, optionally, child worker PIDs).
//
// Key:   __u32 PID
// Value: __u32 (non-zero → protected)
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16);
  __type(key, __u32);
  __type(value, __u32);
} protected_pids SEC(".maps");

// drop_counter tracks the number of ring buffer overflow events per CPU
// (§1.4.6). Exposed to user-space as a Prometheus metric in Phase 4.
//
// Key:   __u32 (always 0 — single logical counter)
// Value: __u64 count of dropped events
struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} drop_counter SEC(".maps");

// baseline_allow_counter tracks the number of kernel ALLOW fast-path hits
// per CPU (§3b.1.2). Binaries with a VERDICT_ALLOW entry skip the ring
// buffer entirely; this counter is the only visibility into that volume.
// Phase 4 exposes it as the zask_baseline_allow_total Prometheus metric.
//
// Key:   __u32 (always 0 — single logical counter)
// Value: __u64 count of fast-path ALLOW hits
struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} baseline_allow_counter SEC(".maps");

// ---------------------------------------------------------------------------
// Programs
// ---------------------------------------------------------------------------

// zask_bprm_check is the Tier 1 LSM gatekeeper (§1.1, §1.3).
//
// Intercepts every execve-family syscall via the bprm_check_security hook.
// Decision flow:
//   1. Extract inode_key from the binary being loaded.
//   2. Look up verdict_map for a pre-existing verdict.
//   3. Emit a telemetry event to the ring buffer (regardless of verdict).
//   4. Return -EPERM for BLOCK, 0 for ALLOW or unknown binaries.
//
// Default policy is fail-open (ALLOW) to avoid breaking normal operations.
// The Go control plane and AI layer populate verdict_map entries over time.
SEC("lsm/bprm_check_security")
int BPF_PROG(zask_bprm_check, struct linux_binprm *bprm)
{
  // --- 1. Identity extraction (§1.2) ---

  // Walk bprm->file->f_inode to get the binary's inode and device.
  // Each BPF_CORE_READ emits a BTF relocation so offsets are resolved
  // at load time, making this portable across kernel versions.
  struct file *f = BPF_CORE_READ(bprm, file);
  struct inode *inode = BPF_CORE_READ(f, f_inode);

  struct inode_key key = {};
  key.inode_number = BPF_CORE_READ(inode, i_ino);

  // s_dev encodes the major/minor device number of the filesystem.
  struct super_block *sb = BPF_CORE_READ(inode, i_sb);
  key.device_id = BPF_CORE_READ(sb, s_dev);

  // --- 2. Verdict map lookup (§1.3.2) ---

  int verdict = VERDICT_ALLOW;
  __u8 is_map_hit = 0;

  __u32 *value = bpf_map_lookup_elem(&verdict_map, &key);
  if (value)
  {
    is_map_hit = 1;
    verdict = *value;
    if (verdict == VERDICT_ALLOW)
    {
      // Fast-path: known-good binary. Skip the ring buffer entirely —
      // no userspace involvement needed. Increment the per-CPU counter
      // so Phase 4 can expose this volume as a Prometheus metric.
      __u32 idx = 0;
      __u64 *cnt = bpf_map_lookup_elem(&baseline_allow_counter, &idx);
      if (cnt)
        __sync_fetch_and_add(cnt, 1);
      return 0;
    }
  }

  // --- 3. Telemetry export (§1.4) ---
  // Reached only for BLOCK hits (is_map_hit=1, verdict=BLOCK) and
  // unknown binaries (is_map_hit=0). ALLOW fast-path exits above.

  // Reserve space directly in the ring buffer to avoid stack allocation
  // of the ~300-byte event struct (BPF stack limit is 512 bytes).
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e)
  {
    // Process metadata (§1.2.4).
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (__u32)(pid_tgid >> 32);
    e->uid = (__u32)bpf_get_current_uid_gid();

    // PPID: walk current task_struct → real_parent → tgid.
    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    // Inode metadata.
    e->inode_number = key.inode_number;
    e->device_id = key.device_id;

    // Cgroup ID for container-aware policy differentiation
    // (§1.5.4). Allows the Go orchestrator to distinguish
    // host-level vs. containerised workloads.
    e->cgroup_id = bpf_get_current_cgroup_id();

    // Source flag (§1.4.4).
    e->is_map_hit = is_map_hit;

    // Argument extraction (§1.2.3, §2b.1).
    // Read the executable filename from linux_binprm.
    const char *filename = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(e->argv, sizeof(e->argv),
                              filename);

    // Extract raw argv[1] (§2b.1.2) — for interpreters this is often
    // the script path, but may be a flag (e.g., "-u"). The Go engine
    // falls back to /proc/[pid]/cmdline when this value is not a path.
    // Walk current task's mm->arg_start, skip argv[0], and read argv[1].
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    unsigned long arg_start = 0;
    unsigned long arg_end = 0;
    if (mm)
    {
      arg_start = BPF_CORE_READ(mm, arg_start);
      arg_end = BPF_CORE_READ(mm, arg_end);
    }
    if (arg_start && arg_end > arg_start)
    {
      // Skip argv[0] by scanning for the first NUL byte.
      // Limit scan to 128 bytes (sufficient for most binary paths).
      char ch;
      unsigned long pos = arg_start;
      unsigned long limit = arg_start + 128;
      if (limit > arg_end)
        limit = arg_end;

      // Walk past argv[0] to find the NUL terminator.
      // Bounded loop — kernel ≥ 5.3 verifier accepts this without unrolling.
      for (int i = 0; i < 128; i++)
      {
        if (pos >= limit)
          break;
        if (bpf_probe_read_user(&ch, 1, (void *)pos) != 0)
          break;
        pos++;
        if (ch == '\0')
        {
          // pos now points to the start of argv[1].
          // Only read if there is data remaining.
          if (pos < arg_end)
            bpf_probe_read_user_str(e->script_argv,
                                    sizeof(e->script_argv),
                                    (void *)pos);
          break;
        }
      }
    }

    bpf_ringbuf_submit(e, 0);
  }
  else
  {
    // Ring buffer is full — increment the per-CPU drop counter
    // (§1.4.6). This is non-fatal; events resume after the
    // user-space consumer drains the buffer.
    __u32 idx = 0;
    __u64 *cnt = bpf_map_lookup_elem(&drop_counter, &idx);
    if (cnt)
      __sync_fetch_and_add(cnt, 1);
  }

  // --- 4. Enforcement (§1.3.3) ---

  if (verdict == VERDICT_BLOCK)
    return -EPERM;

  return 0;
}

// zask_task_kill protects the ZASK daemon from unauthorized termination
// (§1.5).
//
// Policy:
//   - If the target PID is in protected_pids and the signal is SIGKILL
//     or SIGTERM, deny unless the sender is the protected process itself
//     (allowing graceful self-shutdown).
//   - All other signals and non-protected targets pass through.
SEC("lsm/task_kill")
int BPF_PROG(zask_task_kill, struct task_struct *target,
             struct kernel_siginfo *info, int sig, const struct cred *cred)
{
  // Only guard against SIGKILL and SIGTERM — allow all other signals
  // (e.g. SIGCHLD, SIGUSR1) so normal process management works.
  if (sig != SIG_KILL && sig != SIG_TERM)
    return 0;

  // Check if the target is a protected PID.
  __u32 target_pid = BPF_CORE_READ(target, tgid);
  __u32 *prot = bpf_map_lookup_elem(&protected_pids, &target_pid);
  if (!prot)
    return 0; // Not protected — allow.

  // Target is protected. Allow only self-signals so the daemon can
  // shut itself down gracefully (e.g. via os.Exit or context cancel).
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 sender_pid = (__u32)(pid_tgid >> 32);
  if (sender_pid == target_pid)
    return 0; // Self-signal — allow.

  // Unauthorized signal to a protected process — deny.
  return -EPERM;
}
