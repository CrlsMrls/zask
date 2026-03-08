# SETUP


## Requirements

To quickly verify if your current kernel is already configured to support eBPF LSM, run the bundled script:

```bash
./scripts/check-env.sh
```

The expected output is:

```bash
=== ZASK Environment Check ===

Checking kernel version...
  [PASS] Kernel version 6.12.0 (≥ 5.8)
Checking kernel config options...
  [PASS] CONFIG_BPF_LSM=y
  [PASS] CONFIG_DEBUG_INFO_BTF=y
  [PASS] CONFIG_BPF_SYSCALL=y
Checking LSM modules...
  [PASS] BPF LSM active (lsm=lockdown,capability,landlock,yama,selinux,bpf,ima,evm)
Checking BPF filesystem...
  [PASS] BPF filesystem mounted

=== Results: 6 passed, 0 failed ===
Environment is ready for ZASK.
```


### Troubleshooting

In case the check fails, or you want to understand the requirements in more depth, please review the following documents:

1. **[`kernel-requirements.md`](kernel-requirements.md)**  
   **Start here.** This document details the fundamental prerequisites for the project. It covers the minimum supported kernel version (≥ 5.8), mandatory Kconfig flags (like `CO-RE/BTF` and `BPF_LSM` support), capability requirements, and filesystem dependencies (`bpffs`).

2. **[`boot-parameter-setup.md`](boot-parameter-setup.md)**  
   Even if your kernel is compiled correctly, eBPF LSM hooks are often dormant by default. This guide provides distribution-specific instructions (RHEL, Ubuntu, Arch, etc.) on how to modify your bootloader to activate the `bpf` module via the `lsm=` kernel parameter.


## Installation

> ⚠️ Work in progress: the goal is to include a Helm chart for easy deployment in Kubernetes and a mechanism to run the daemon on a standalone Linux host. For now, follow the instructions in the [Development](../04-development/README.md) folder. Contact the maintainer if you want need assistance getting it running.


## Safe Shutdown

When `selfProtection: true` (the default), `zaskd` registers its own PID in the eBPF `protected_pids` map. The `lsm/task_kill` hook then silently blocks `SIGKILL` and `SIGTERM` from any external process, preventing attackers or compromised software from terminating the security daemon.


- Running in the foreground: Press **Ctrl+C** to send `SIGINT`, which is not blocked.
- To safely stop the daemon, use `SIGINT` (e.g., `kill -INT <pid>` or `Ctrl+C` in the foreground). 
- For systemd, configure the unit to send `SIGINT` instead of `SIGTERM`. 

This self-protection can be disabled, in this case all signals work normally. 
 
See the [Shutdown Guide](shutdown.md) for more details.

