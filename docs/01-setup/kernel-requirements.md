# Kernel Requirements

ZASK requires a Linux kernel with eBPF LSM support and IMA (Integrity Measurement Architecture). These are **hard prerequisites** — the daemon cannot start without them.

---

## Summary

| Requirement | Value |
|---|---|
| Kernel version | **≥ 5.18** |
| `CONFIG_BPF_LSM` | `=y` |
| `CONFIG_DEBUG_INFO_BTF` | `=y` |
| `CONFIG_BPF_SYSCALL` | `=y` |
| `CONFIG_IMA` | `=y` |
| Boot parameters | `lsm=...,bpf,...` and `ima_policy=tcb` |
| BPF filesystem | mounted at `/sys/fs/bpf` |
| Runtime capabilities | `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_KILL` |

---

## Kernel Version ≥ 5.18

5.18 is the minimum for two reasons:

- **`bpf_ima_file_hash()`** — introduced in kernel 5.18. ZASK calls this helper from its eBPF LSM hook to read the IMA-measured SHA-256 hash of each executed binary in O(1) time (the hash is already cached in the inode security blob by IMA). This is the foundation of ZASK's content-derived binary identity.
- Earlier requirements still apply: **`BPF_MAP_TYPE_RINGBUF`** (5.8) and **eBPF LSM hooks** (stabilised in 5.8).

Reference: [BPF ring buffer — kernel docs](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html)

---

## `CONFIG_BPF_LSM=y`

This config option compiles LSM hook attachment points into the kernel for eBPF programs. Without it, `bpf()` programs of type `BPF_PROG_TYPE_LSM` cannot be loaded — which means ZASK has no way to intercept execution events at the kernel level. The entire enforcement model depends on this.

Reference: [BPF LSM programs — kernel docs](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)

---

## `CONFIG_DEBUG_INFO_BTF=y`

BTF (BPF Type Format) is a compact representation of kernel type information embedded directly in the kernel image. ZASK uses **CO-RE** (Compile Once – Run Everywhere): the eBPF C code is compiled once against a `vmlinux.h` type snapshot, then the libbpf loader uses BTF to relocate field offsets at load time so the same binary works across different kernel versions without recompilation.

Without `CONFIG_DEBUG_INFO_BTF=y`, BTF is absent from the running kernel and CO-RE relocation fails — the eBPF program cannot be loaded.

References:
- [BPF Type Format (BTF) — kernel docs](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [BPF CO-RE reference guide — Andrii Nakryiko](https://nakryiko.com/posts/bpf-core-reference-guide/)

---

## `CONFIG_BPF_SYSCALL=y`

Enables the `bpf(2)` syscall, which is the single entry point for all eBPF operations: loading programs, creating maps, pinning objects to the filesystem, and querying BTF. Without it none of the above is possible. This option is enabled in virtually all modern distribution kernels, but it is still a hard build-time prerequisite.

Reference: [bpf(2) — Linux man pages](https://man7.org/linux/man-pages/man2/bpf.2.html)

---

## `CONFIG_IMA=y`

**IMA (Integrity Measurement Architecture)** is the kernel subsystem that measures file content and stores the hash in the inode security blob. ZASK reads these measurements via `bpf_ima_file_hash()` at the point of `execve()`.

Without IMA:
- `bpf_ima_file_hash()` returns `-ENOENT` for unmeasured files.
- ZASK falls back gracefully: events are still processed, CEL rules still evaluate, but the kernel-side hash fast-path (`verdict_map` lookup) is bypassed.

> **Note:** `CONFIG_IMA_APPRAISE` is **not** required. ZASK only reads hashes — it does not use IMA's appraisal (signature verification) feature.

**Why content-derived identity matters:**

1. **Tamper detection.** If an attacker overwrites a binary in-place, the inode number is unchanged but IMA detects the content change (new hash). The old ALLOW verdict does not apply.
2. **Cross-container deduplication.** The same container image on N nodes has different inodes but identical content → one hash, one verdict evaluation.
3. **Hash-based threat intel compatibility.** STIX/TAXII feeds, VirusTotal, and Sigma `Hashes` fields distribute known-bad SHA-256 hashes. ZASK can consume them directly.

Reference: [IMA — kernel docs](https://www.kernel.org/doc/html/latest/security/IMA-templates.html)

---

## Boot Parameters

### `lsm=...,bpf,...`

The kernel only activates the LSMs explicitly listed in the `lsm=` boot parameter. `CONFIG_BPF_LSM=y` compiles the support in, but it is not enabled at runtime unless `bpf` appears in this list. Omitting it silently disables all eBPF LSM hooks even on a correctly compiled kernel.

### `ima_policy=tcb`

This boot parameter activates the built-in IMA Trusted Computing Base policy, which among other things enables measurement of all executed files (`func=BPRM_CHECK`). Without an active IMA measurement policy, `bpf_ima_file_hash()` may return `-ENOENT` for binaries IMA hasn't measured yet — ZASK handles this gracefully but loses the hash fast-path benefit.

Alternatively, a custom policy can be placed in `/etc/ima/ima-policy`:
```
measure func=BPRM_CHECK
```

For how to set boot parameters on your distribution, see [boot-parameter-setup.md](boot-parameter-setup.md).

Reference: [kernel-parameters.txt — `lsm=`, `ima_policy=`](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)

---

## BPF Filesystem (`/sys/fs/bpf`)

The BPF filesystem (`bpffs`) is a special-purpose virtual filesystem that lets eBPF objects — maps and programs — be **pinned** by path. Without it, any map or program would be destroyed as soon as the file descriptor that created it is closed. ZASK pins its policy maps to `bpffs` so they survive daemon restarts without losing state.

On systemd-based distributions `bpffs` is usually auto-mounted. If it is absent, it must be mounted manually or via a systemd unit before the daemon starts.

Reference: [BPF filesystem — kernel docs](https://docs.kernel.org/bpf/index.html)

---

## Runtime Capabilities

ZASK runs as a privileged daemon that requires three Linux capabilities. These should be granted via the service unit or a file capability rather than running as full root.

| Capability | Why ZASK needs it |
|---|---|
| `CAP_BPF` | Load eBPF programs and create/access BPF maps via the `bpf()` syscall |
| `CAP_SYS_ADMIN` | Pin BPF objects to the BPF filesystem (`/sys/fs/bpf`) |
| `CAP_KILL` | Send `SIGKILL` to processes blocked by policy enforcement |

Reference: [capabilities(7) — Linux man pages](https://man7.org/linux/man-pages/man7/capabilities.7.html)

---

## Verification

Run the bundled script to validate all prerequisites at once:

```bash
./scripts/check-env.sh
```
