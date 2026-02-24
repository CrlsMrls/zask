# bpf/ — ZASK eBPF Programs

This directory contains the C source for ZASK's kernel-space eBPF programs,
compiled via `bpf2go` into Go-loadable bytecode.

## Programs

| Program | Hook | Purpose |
|---------|------|---------|
| `zask_bprm_check` | `lsm/bprm_check_security` | Tier 1 Gatekeeper — intercepts every `execve`-family syscall. Looks up the binary's inode in the verdict map and returns `-EPERM` for blocked binaries. Emits a telemetry event to the ring buffer for every execution. |
| `zask_task_kill` | `lsm/task_kill` | Self-protection — prevents unauthorized `SIGKILL` / `SIGTERM` delivery to the ZASK daemon. Only the daemon itself may send termination signals to its own PID. |

## Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `verdict_map` | `BPF_MAP_TYPE_HASH` | `struct inode_key` (inode + device) | `__u32` (0=ALLOW, 1=BLOCK) | Stores per-binary enforcement decisions. Populated by the Go control plane and AI feedback loop. Max 10 000 entries. |
| `events` | `BPF_MAP_TYPE_RINGBUF` | — | `struct event` | Exports telemetry events (PID, PPID, UID, inode, argv, etc.) to user-space. 256 KB capacity. |
| `protected_pids` | `BPF_MAP_TYPE_HASH` | `__u32` (PID) | `__u32` (non-zero) | PIDs shielded from external kill signals. Populated by the Go daemon at startup. Max 16 entries. |
| `drop_counter` | `BPF_MAP_TYPE_PERCPU_ARRAY` | `__u32` (always 0) | `__u64` (count) | Per-CPU counter tracking ring buffer overflow events. Exposed as a Prometheus metric in Phase 4. |

## Structs

### `struct inode_key`

Uniquely identifies a file across filesystems. Used as the verdict map key.

```c
struct inode_key {
    __u64 inode_number;  // Inode number from the filesystem
    __u32 device_id;     // Superblock device ID (major/minor)
};
```

### `struct event`

Telemetry record sent to user-space via the ring buffer. The Go struct
`ZaskEvent` in `internal/ebpf/` is auto-generated from this via `bpf2go`
and must stay in sync.

```c
struct event {
    __u64 inode_number;     // File inode
    __u64 cgroup_id;        // Cgroup ID for container-aware policy
    __u32 pid;              // Process ID
    __u32 ppid;             // Parent process ID
    __u32 uid;              // User ID
    __u32 device_id;        // Filesystem device ID
    __u8  is_map_hit;       // 1 if verdict_map had an entry
    char  argv[256];        // Executable filename (truncated to 256 bytes)
};
```

## Decision Flow

1. execve() called

2. lsm/bprm_check_security
    │
    ├─ Extract inode_key from bprm->file->f_inode
    │
    ├─ Lookup verdict_map[inode_key]
    │   ├─ BLOCK (1)  → return -EPERM (execution denied)
    │   ├─ ALLOW (0)  → continue
    │   └─ NULL       → continue (default-allow)
    │
    ├─ Emit event to ring buffer
    │   └─ If buffer full → increment drop_counter
    │
    └─ return 0 (allow) or -EPERM (block)


## Build

eBPF programs are compiled via `make generate`, which invokes `bpf2go`:

Compiles the C source `bpf/zask.c` into architecture-specific bytecode and generates Go bindings. The resulting `.o` files are loaded by the Go daemon at runtime.

> **Never modify the generated `.go` or `.o` files directly.**
> Always edit `bpf/zask.c` and re-run `make generate`.
