# Setting the `lsm=` Boot Parameter

This page links to official distribution documentation for adding `bpf` to the kernel `lsm=` boot parameter. For background on why this is required, see [kernel-requirements.md](kernel-requirements.md).

---

## What you are changing

The `lsm=` kernel parameter is a comma-separated list of Linux Security Modules the kernel activates at boot. You need to add `bpf` to whatever list your distribution already sets. The other entries (e.g. `selinux`, `lockdown`, `yama`) should be left as-is.

Example result:

```
lsm=lockdown,capability,yama,selinux,bpf
```

Reference: [`lsm=` in kernel-parameters.txt](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)

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

After rebooting, confirm `bpf` is active:

```bash
cat /sys/kernel/security/lsm
```

Or run the project verification script:

```bash
./scripts/check-env.sh
```
