// SPDX-License-Identifier: GPL-2.0-only
//
// ZASK — Zero-trust AI-Secured Kernel
//
// eBPF LSM programs for kernel-native binary execution control.
//
// Programs:
//   zask_bprm_check   — LSM gatekeeper on bprm_check_security (Tier 1).
//   zask_task_kill    — Self-protection hook preventing unauthorized
//                       signals to the ZASK daemon.
//   zask_process_exit — Tracepoint to evict dead PIDs from pid_hash_map.
//
// Maps:
//   verdict_map     — Hash map: exec_key → verdict (ALLOW/BLOCK).
//   pid_hash_map    — LRU hash: pid → hash[32] (exec-chain identity).
//   events          — Ring buffer exporting telemetry to user-space.
//   protected_pids  — Hash map of PIDs shielded from SIGKILL/SIGTERM.
//   drop_counter    — Per-CPU counter tracking ring buffer overflows.
//
// Kernel prerequisites (Phase 3c/ADR):
//   - Kernel ≥ 5.18 for bpf_ima_file_hash() support.
//   - CONFIG_IMA=y with measurement policy covering exec (ima_policy=tcb).

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

// SHA-256 produces a 32-byte digest used as content-derived binary identity.
#define HASH_SIZE 32

// Verdict constants for verdict_map values.
#define VERDICT_ALLOW 0
#define VERDICT_BLOCK 1

// Signal numbers for self-protection hook.
#define SIG_KILL 9
#define SIG_TERM 15

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

// exec_key is the verdict map key — a content-derived exec-chain pair.
// Identity: (parent_binary_hash, child_binary_hash) → verdict.
//
// This is intentionally content-addressed: the same binary pair executes
// identically regardless of path, inode, or mount namespace. IMA tamper
// detection is free: bpf_ima_file_hash() re-computes when i_version changes.
//
// Example enforcement:
//   (hash(nginx), hash(bash)) → BLOCK  (web server must not spawn a shell)
//   (hash(sshd),  hash(bash)) → ALLOW  (SSH daemon may open an interactive shell)
//
// When the parent hash is unavailable (process started before ZASK, or PID 1),
// parent_hash is all-zeros (sentinel). The sentinel key correctly mismatches
// any verdict stored with a known parent hash, forcing userspace evaluation.
struct exec_key
{
  __u8 parent_hash[HASH_SIZE]; // SHA-256 of the parent binary (zero = unknown)
  __u8 child_hash[HASH_SIZE];  // SHA-256 of the child binary (exec target)
};

// event is the telemetry record exported to user-space via the ring buffer.
// The Go struct in internal/ebpf must mirror this layout exactly —
// bpf2go generates it from BTF metadata, so keeping this struct in the
// -type flag of the go:generate directive ensures alignment.
//
// Field order is chosen to minimise padding: u64 fields first, then u32,
// then u8 fields grouped together, then the trailing char arrays.
struct event
{
  __u64 inode_number; // informational — not used as identity
  __u64 cgroup_id;
  __u32 pid;
  __u32 ppid;
  __u32 uid;
  __u32 device_id;             // informational
  __u8 is_map_hit;             // 1 if verdict_map contained an entry
  __u8 hash_available;         // 1 if IMA hash was obtained for child, 0 if not
  __u8 hash[HASH_SIZE];        // SHA-256 of child binary (zero if unavailable)
  __u8 parent_hash_available;  // 1 if parent hash resolved from pid_hash_map
  __u8 parent_hash[HASH_SIZE]; // SHA-256 of parent binary (zero if unavailable)
  char argv[ARGV_MAX];         // executable filename (truncated to ARGV_MAX)
  char script_argv[ARGV_MAX];  // raw argv[1] — may be a flag; Go engine resolves via procfs
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// verdict_map stores exec-chain enforcement decisions (§ADR-exec-chain).
//
// Key:   exec_key {parent_hash[32], child_hash[32]} — compound content identity
// Value: __u32 — VERDICT_ALLOW (0) or VERDICT_BLOCK (1)
//
// The compound key encodes WHO invokes WHAT, enabling context-aware enforcement:
// the same child binary can be ALLOWed when invoked by sshd but BLOCKed by nginx.
// Content-addressing means: copies of a binary share one verdict entry regardless
// of path, inode, or container. IMA tamper detection is free: overwriting a binary
// changes its hash, invalidating the prior verdict automatically.
//
// Capacity: 10 000 entries. Each entry is ~68 bytes (64-byte key + 4-byte value).
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, struct exec_key);
  __type(value, __u32);
} verdict_map SEC(".maps");

// pid_hash_map tracks the SHA-256 hash of the last exec'd binary for each PID.
// Used to construct the compound exec_key: when a new exec occurs, the parent's
// hash is looked up here so that (parent_hash, child_hash) → verdict lookups work.
//
// Key:   __u32 pid — host PID namespace (LSM hooks always see host PIDs)
// Value: __u8 hash[HASH_SIZE] — SHA-256 from bpf_ima_file_hash() at execve time
//
// LRU eviction handles capacity overflow. The sched_process_exit tracepoint
// provides explicit cleanup to prevent stale entries from PID reuse.
//
// Capacity: 65536 — covers typical Linux systems (default PID max is ~32768).
struct
{
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, __u8[HASH_SIZE]);
} pid_hash_map SEC(".maps");

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

// zask_bprm_check is the Tier 1 LSM gatekeeper (§1.1, §1.3, §3c.2.3, §ADR).
//
// Intercepts every execve-family syscall via the bprm_check_security hook.
// Decision flow:
//   1. Read inode metadata (informational — for logging only).
//   2. Call bpf_ima_file_hash() to get the child binary's SHA-256 hash.
//      If IMA is unavailable, hash_available=0 and the event falls through
//      to userspace without a kernel fast-path verdict.
//   3. Look up the parent process's hash from pid_hash_map (exec-chain identity).
//   4. Store the child hash in pid_hash_map for future children of this PID.
//   5. If hash available, look up verdict_map[(parent_hash, child_hash)].
//   6. Emit a telemetry event to the ring buffer (for BLOCK hits and unknowns).
//   7. Return -EPERM for BLOCK, 0 for ALLOW or unknown binaries.
//
// Default policy is fail-open (ALLOW) to avoid breaking normal operations.
// The Go control plane and AI layer populate verdict_map entries over time.
SEC("lsm.s/bprm_check_security")
int BPF_PROG(zask_bprm_check, struct linux_binprm *bprm)
{
  // --- 1. Identity extraction — inode metadata for logging (§1.2) ---

  // Use direct field access (not BPF_CORE_READ) for the file pointer.
  // BPF_CORE_READ routes through bpf_probe_read_kernel which writes raw bytes
  // to a stack buffer; loading from that buffer gives the verifier a scalar,
  // losing the ptr_to_btf_id type required by bpf_ima_file_hash().
  // Direct access generates a typed ldx instruction that preserves the type.
  struct file *f = bprm->file;
  struct inode *inode = BPF_CORE_READ(f, f_inode);

  __u64 inode_number = BPF_CORE_READ(inode, i_ino);
  struct super_block *sb = BPF_CORE_READ(inode, i_sb);
  __u32 device_id = BPF_CORE_READ(sb, s_dev);

  // --- 2. Process context — PID/PPID needed for exec-chain key ---
  //
  // Extract these before the ring buffer reservation so they are available
  // for pid_hash_map operations and event population.
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 cur_pid = (__u32)(pid_tgid >> 32);

  struct task_struct *task =
      (struct task_struct *)bpf_get_current_task();
  struct task_struct *par = BPF_CORE_READ(task, real_parent);
  __u32 par_pid = BPF_CORE_READ(par, tgid);

  // --- 3. Child hash via IMA (§3c.2.3) ---
  //
  // bpf_ima_file_hash() reads the IMA-computed SHA-256 hash from the
  // inode security blob. IMA hashes executed files lazily on first exec
  // (with ima_policy=tcb) and caches the result; subsequent execs of the
  // same unmodified file get a cached lookup at O(1) cost.
  //
  // If IMA is not configured or hasn't measured this file yet,
  // bpf_ima_file_hash() returns a negative errno. In that case we set
  // hash_available=0 and proceed without a map lookup — the event still
  // reaches userspace so rules and AI can evaluate behavioral signals.

  struct exec_key key = {};
  __u8 hash_available = 0;
  __u8 parent_hash_available = 0;

  int ima_ret = bpf_ima_file_hash(f, key.child_hash, HASH_SIZE);
  if (ima_ret >= 0)
    hash_available = 1;

  // --- 4. Exec-chain key: look up parent hash from pid_hash_map (§ADR) ---
  //
  // The pid_hash_map stores each process's content hash at exec time.
  // Look up the parent's hash BEFORE updating our own entry so we see
  // the parent's value, not a stale entry from a PID-reuse scenario.
  //
  // If the parent has no entry (started before ZASK, or PID 1), the
  // parent_hash field stays all-zeros — the "unknown parent" sentinel.
  // Store our own hash for future children of this process.
  if (hash_available)
  {
    __u8 *phash = bpf_map_lookup_elem(&pid_hash_map, &par_pid);
    if (phash)
    {
      __builtin_memcpy(key.parent_hash, phash, HASH_SIZE);
      parent_hash_available = 1;
    }
    // Store child hash keyed by our PID for future children.
    bpf_map_update_elem(&pid_hash_map, &cur_pid, key.child_hash, BPF_ANY);
  }

  // --- 5. Verdict map lookup (§1.3.2) ---
  //
  // Look up the compound (parent_hash, child_hash) key. When parent_hash
  // is all-zeros (unknown-parent sentinel), this correctly mismatches any
  // verdict stored with a real parent hash, so unknown-parent events always
  // fall through to userspace on first encounter.

  int verdict = VERDICT_ALLOW;
  __u8 is_map_hit = 0;

  if (hash_available)
  {
    __u32 *value = bpf_map_lookup_elem(&verdict_map, &key);
    if (value)
    {
      is_map_hit = 1;
      verdict = *value;
      if (verdict == VERDICT_ALLOW)
      {
        // Fast-path: known-good exec chain. Skip the ring buffer entirely —
        // no userspace involvement needed. Increment the per-CPU counter
        // so Phase 4 can expose this volume as a Prometheus metric.
        __u32 idx = 0;
        __u64 *cnt = bpf_map_lookup_elem(&baseline_allow_counter, &idx);
        if (cnt)
          __sync_fetch_and_add(cnt, 1);
        return 0;
      }
    }
  }

  // --- 6. Telemetry export (§1.4) ---
  // Reached only for BLOCK hits (is_map_hit=1, verdict=BLOCK) and
  // unknown binaries (is_map_hit=0). ALLOW fast-path exits above.

  // Reserve space directly in the ring buffer to avoid stack allocation
  // of the large event struct (BPF stack limit is 512 bytes).
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e)
  {
    // Process metadata (§1.2.4).
    e->pid = cur_pid;
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->ppid = par_pid;

    // Inode metadata (informational — not used as identity).
    e->inode_number = inode_number;
    e->device_id = device_id;

    // Cgroup ID for container-aware policy differentiation
    // (§1.5.4). Allows the Go orchestrator to distinguish
    // host-level vs. containerised workloads.
    e->cgroup_id = bpf_get_current_cgroup_id();

    // Source flag (§1.4.4).
    e->is_map_hit = is_map_hit;

    // Exec-chain hash fields (§ADR-exec-chain).
    e->hash_available = hash_available;
    __builtin_memcpy(e->hash, key.child_hash, HASH_SIZE);
    e->parent_hash_available = parent_hash_available;
    __builtin_memcpy(e->parent_hash, key.parent_hash, HASH_SIZE);

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

  // --- 7. Enforcement (§1.3.3) ---

  if (verdict == VERDICT_BLOCK)
    return -EPERM;

  return 0;
}

// zask_process_exit evicts a PID's hash entry from pid_hash_map when the
// process terminates (§ADR-exec-chain). Without explicit cleanup, dead PID
// slots remain until LRU eviction — fine for correctness, but leaves stale
// entries that could be inherited by a new process reusing the same PID.
//
// This tracepoint fires on every thread exit. We use the tgid (process PID)
// as the key, matching what zask_bprm_check stores, so the entry is removed
// when the thread group leader exits.
SEC("tp/sched/sched_process_exit")
int zask_process_exit(void *ctx)
{
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = (__u32)(pid_tgid >> 32);
  bpf_map_delete_elem(&pid_hash_map, &pid);
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
