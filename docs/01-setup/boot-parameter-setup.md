# Setting Kernel Boot Parameters

This page links to official distribution documentation for adding `bpf` and `ima_policy=tcb` to kernel boot parameters. For background on why these are required, see [kernel-requirements.md](kernel-requirements.md).

---

## What you are changing

ZASK requires two kernel boot parameters:

### 1. `lsm=` — Enable BPF LSM

The `lsm=` kernel parameter is a comma-separated list of Linux Security Modules the kernel activates at boot. You need to add `bpf` to whatever list your distribution already sets. The other entries (e.g. `selinux`, `lockdown`, `yama`) should be left as-is.

Example result:

```
lsm=lockdown,capability,yama,selinux,bpf
```

Reference: [`lsm=` in kernel-parameters.txt](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)

### 2. `ima_policy=tcb` — Enable IMA binary measurement

IMA (Integrity Measurement Architecture) must be configured to measure executed binaries. The built-in `tcb` (Trusted Computing Base) policy activates measurement of all `exec` calls, which allows ZASK's eBPF hook to read file hashes via `bpf_ima_file_hash()`.

```
ima_policy=tcb
```

Without this, `bpf_ima_file_hash()` returns `-ENOENT` for unmeasured files and ZASK falls back to behavioral-only rules (no hash fast-path, no tamper detection).

Alternatively, a custom IMA policy can be placed in `/etc/ima/ima-policy`:
```
measure func=BPRM_CHECK
```

Reference: [IMA policy — kernel docs](https://www.kernel.org/doc/html/latest/security/IMA-templates.html)

---

## RHEL / Fedora / Rocky Linux

Red Hat-family distributions use GRUB2 with Boot Loader Specification (BLS) entries. The preferred tool is `grubby`, which edits BLS entries directly.

- [Configuring kernel command-line parameters — Red Hat documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/managing_monitoring_and_updating_the_kernel/configuring-kernel-command-line-parameters_managing-monitoring-and-updating-the-kernel)
- [grubby(8) man page](https://man7.org/linux/man-pages/man8/grubby.8.html)

---

## Debian / Ubuntu

Debian-family distributions use GRUB2 with `update-grub` to regenerate the config from `/etc/default/grub`.

- [Grub2 — Ubuntu community documentation](https://help.ubuntu.com/community/Grub2)
- [KernelBootParameters — Ubuntu wiki](https://wiki.ubuntu.com/Kernel/KernelBootParameters)

---

## Arch Linux / systemd-boot

Arch Linux and other distributions using systemd-boot configure boot entries as plain-text `.conf` files under `/boot/loader/entries/`.

- [Kernel parameters — Arch wiki (systemd-boot)](https://wiki.archlinux.org/title/Kernel_parameters#systemd-boot)

---

## Verifying the change

After rebooting, confirm `bpf` is active in the LSM list:

```bash
cat /sys/kernel/security/lsm
```

Confirm IMA is active and measuring exec calls:

```bash
# IMA security filesystem should exist:
ls /sys/kernel/security/ima/

# IMA policy should include BPRM_CHECK:
grep func=BPRM_CHECK /sys/kernel/security/ima/policy
```

Or run the project verification script (checks all prerequisites at once):

```bash
./scripts/check-env.sh
```
