# Kernel Requirements

ZASK requires a Linux kernel with eBPF LSM support. These are **hard prerequisites** — the daemon cannot start without them.

---

## Summary

| Requirement | Value |
|---|---|
| Kernel version | **≥ 5.8** |
| `CONFIG_BPF_LSM` | `=y` |
| `CONFIG_DEBUG_INFO_BTF` | `=y` |
| `CONFIG_BPF_SYSCALL` | `=y` |
| Boot parameter | `lsm=...,bpf,...` |
| BPF filesystem | mounted at `/sys/fs/bpf` |
| Runtime capabilities | `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_KILL` |

---

## Kernel Version ≥ 5.8

5.8 is the first kernel version where both core eBPF primitives used by ZASK are stable simultaneously:

- **`BPF_MAP_TYPE_RINGBUF`** — the ring buffer map type ZASK uses to stream security events from the kernel eBPF program to the userspace daemon with minimal overhead. It was added in 5.8.
- **eBPF LSM hooks** — hooks that allow eBPF programs to intercept Linux Security Module decisions (e.g. `bprm_check_security` for binary execution). They landed in 5.7 and stabilised in 5.8.

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

## Boot Parameter `lsm=...,bpf,...`

The kernel only activates the LSMs explicitly listed in the `lsm=` boot parameter. `CONFIG_BPF_LSM=y` compiles the support in, but it is not enabled at runtime unless `bpf` appears in this list. Omitting it silently disables all eBPF LSM hooks even on a correctly compiled kernel.

The exact set of other modules (e.g. `lockdown`, `capability`, `selinux`) depends on the distribution and security policy. ZASK only requires that `bpf` is present somewhere in the list.

For how to set this parameter on your distribution, see [boot-parameter-setup.md](boot-parameter-setup.md).

Reference: [kernel-parameters.txt — `lsm=`](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)

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
