# bpf/ — ZASK eBPF Programs

This directory contains the C source for ZASK's kernel-space eBPF programs,
compiled via `bpf2go` into Go-loadable bytecode.

## Programs

| Program | Hook | Purpose |
|---------|------|---------|
| `zask_bprm_check` | `lsm/bprm_check_security` | Tier 1 Gatekeeper — intercepts every `execve`-family syscall. Resolves the exec-chain identity `(parent_hash, child_hash)`, looks up the verdict map, and returns `-EPERM` for blocked pairs. Emits a telemetry event to the ring buffer for every execution not on the kernel fast-path. |
| `zask_process_exit` | `tp/sched/sched_process_exit` | PID cleanup — evicts the terminated process's hash entry from `pid_hash_map`, preventing stale entries from being inherited by a new process that reuses the same PID. |
| `zask_task_kill` | `lsm/task_kill` | Self-protection — prevents unauthorized `SIGKILL` / `SIGTERM` delivery to the ZASK daemon. Only the daemon itself may send termination signals to its own PID. |

## Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `verdict_map` | `BPF_MAP_TYPE_HASH` | `struct exec_key` (parent_hash[32] + child_hash[32]) | `__u32` (0=ALLOW, 1=BLOCK) | Stores exec-chain enforcement decisions. The compound key encodes WHO invokes WHAT: `(hash(sshd), hash(bash)) → ALLOW` while `(hash(nginx), hash(bash)) → BLOCK`. Max 10 000 entries. |
| `pid_hash_map` | `BPF_MAP_TYPE_LRU_HASH` | `__u32` (PID) | `__u8[32]` (SHA-256) | Tracks the content hash of the last exec'd binary for each PID. Used to build the parent hash component of the exec-chain key at execve time. Max 65 536 entries (LRU-evicted). |
| `events` | `BPF_MAP_TYPE_RINGBUF` | — | `struct event` | Exports telemetry events (PID, PPID, UID, exec-chain hashes, argv, etc.) to user-space. 256 KB capacity. |
| `protected_pids` | `BPF_MAP_TYPE_HASH` | `__u32` (PID) | `__u32` (non-zero) | PIDs shielded from external kill signals. Populated by the Go daemon at startup. Max 16 entries. |
| `drop_counter` | `BPF_MAP_TYPE_PERCPU_ARRAY` | `__u32` (always 0) | `__u64` (count) | Per-CPU counter tracking ring buffer overflow events. Exposed as a Prometheus metric in Phase 4. |
| `baseline_allow_counter` | `BPF_MAP_TYPE_PERCPU_ARRAY` | `__u32` (always 0) | `__u64` (count) | Per-CPU counter for kernel ALLOW fast-path hits. Binaries with a `VERDICT_ALLOW` entry skip the ring buffer entirely; this is the only visibility into that volume. Phase 4 exposes it as a Prometheus metric. |

## Structs

### `struct exec_key`

Verdict map key — a content-derived exec-chain pair. Encodes WHO invokes WHAT.

```c
struct exec_key {
    __u8 parent_hash[32];  // SHA-256 of parent binary (all-zeros = unknown parent)
    __u8 child_hash[32];   // SHA-256 of child binary (exec target)
};
```

When the parent process started before ZASK (or is PID 1), `parent_hash` is all-zeros — the *unknown-parent sentinel*. This correctly mismatches any verdict stored with a real parent hash, so unknown-parent events fall through to userspace on first encounter.

### `struct event`

Telemetry record sent to user-space via the ring buffer. The Go struct
`ZaskEvent` in `internal/ebpf/` is auto-generated from this via `bpf2go`
and must stay in sync.

```c
struct event {
    __u64 inode_number;           // File inode (informational)
    __u64 cgroup_id;              // Cgroup ID for container-aware policy
    __u32 pid;                    // Process ID
    __u32 ppid;                   // Parent process ID
    __u32 uid;                    // User ID
    __u32 device_id;              // Filesystem device ID (informational)
    __u8  is_map_hit;             // 1 if verdict_map had an entry
    __u8  hash_available;         // 1 if IMA hash was obtained for child
    __u8  hash[32];               // SHA-256 of child binary (exec target)
    __u8  parent_hash_available;  // 1 if parent hash resolved from pid_hash_map
    __u8  parent_hash[32];        // SHA-256 of parent binary (all-zeros if unavailable)
    char  argv[256];              // Executable filename (truncated to 256 bytes)
    char  script_argv[256];       // Raw argv[1] (may be a flag; Go engine resolves via procfs)
};
```

## Decision Flow

```
execve() called

lsm/bprm_check_security
 │
 ├─ 1. bpf_ima_file_hash() → child_hash[32]  (hash_available = 0 if IMA not configured)
 │
 ├─ 2. pid_hash_map[par_pid] → parent_hash[32]  (zeros if parent started before ZASK)
 │
 ├─ 3. pid_hash_map[cur_pid] = child_hash  (store for future children)
 │
 ├─ 4. verdict_map[(parent_hash, child_hash)]
 │      ├─ ALLOW (0)  → increment baseline_allow_counter, return 0   [kernel fast-path]
 │      ├─ BLOCK (1)  → emit event (is_map_hit=1), return -EPERM
 │      └─ NULL       → emit event (is_map_hit=0), return 0
 │
 └─ Ring buffer full? → increment drop_counter (non-fatal)

tp/sched/sched_process_exit
 └─ pid_hash_map[pid].delete()  (PID eviction on process exit)
```

## Build

eBPF programs are compiled via `make generate`, which invokes `bpf2go`:

Compiles the C source `bpf/zask.c` into architecture-specific bytecode and generates Go bindings. The resulting `.o` files are loaded by the Go daemon at runtime.

> **Never modify the generated `.go` or `.o` files directly.**
> Always edit `bpf/zask.c` and re-run `make generate`.
