# Lima Development Guide

This guide explains how to set up a ZASK development environment on macOS using [Lima](https://lima-vm.io/). Lima provides lightweight Linux VMs that are required because macOS does not support eBPF LSM hooks.

## Prerequisites

- macOS with Homebrew installed
- At least 4 GB of free RAM for the VM
- At least 20 GB of free disk space

## Installation

### 1. Install Lima

```bash
brew install lima
```

### 2. Start the ZASK VM

The project includes a pre-configured Lima template at `lima/zask.yaml`. You can use the provided Makefile command to start it:

```bash
# start the VM (creates required host directories automatically)
make start-vm
```

This will:
- Download a Rocky Linux 10.1 cloud image
- Create a VM with 4 CPUs, 4 GB RAM, 20 GB disk
- Install clang, LLVM, bpftool, Go, golangci-lint, govulncheck
- Generate `vmlinux.h` from the kernel BTF
- Configure BPF LSM boot parameters

> **Note:** The first start takes several minutes while it downloads and provisions the VM.

### 3. Restart After Provisioning

The BPF LSM boot parameter requires a reboot to take effect:

```bash
limactl stop zask
limactl start zask
```

### 4. Enter the VM

```bash
limactl shell zask
```

## Verification

Once inside the VM, verify the environment:

```bash
limactl shell zask -- ./scripts/check-env.sh
```

OR inside the VM shell:

```bash
limactl shell zask

./scripts/check-env.sh
```

All checks should pass:

```
=== ZASK Environment Check ===

Checking kernel version...
  [PASS] Kernel version 6.12.0 (≥ 5.8)
Checking kernel config options...
  [PASS] CONFIG_BPF_LSM=y
  [PASS] CONFIG_DEBUG_INFO_BTF=y
  [PASS] CONFIG_BPF_SYSCALL=y
Checking LSM modules...
  [PASS] BPF LSM active (lsm=lockdown,capability,yama,selinux,bpf,landlock,ima,evm)
Checking BPF filesystem...
  [PASS] BPF filesystem mounted

=== Results: 6 passed, 0 failed ===
Environment is ready for ZASK.
```

## File Sharing

Lima automatically mounts your macOS home directory into the VM as read-only. The ZASK project directory is accessible at its normal macOS path inside the VM.


To edit files, do it on your host machine using your preferred editor. The project directory is mounted read-only in the VM, so you cannot edit files from inside the VM.

> **Warning:** A writable mount is generally discouraged. Because eBPF development requires `root`, generated files may end up owned by root on your Mac, causing permission issues. It also breaks VM isolation (risking accidental host damage from test payloads) and suffers from slower cross-OS I/O performance. If you must do this, only make the specific project directory writable, never your entire home directory as currently configured in `lima/zask.yaml`.

For write operations (like `make build`), you may need to copy the project to a writable location inside the VM:

```bash
limactl shell zask

# Inside the VM
cp -r . /tmp/zask
cd /tmp/zask
make build
```

### Developing with VS Code Remote-SSH

IF you need to develop directly inside the VM for quick iteration, use the **VS Code Remote - SSH** extension to connect to the VM and edit files with native Linux performance.

1. Add the Lima SSH config to your macOS SSH configuration:
   ```bash
   echo "Include ~/.lima/zask/ssh.config" >> ~/.ssh/config
   ```
2. Install the **Remote - SSH** extension in VS Code.
3. Press `Cmd + Shift + P`, select **Remote-SSH: Connect to Host...**, and choose `lima-zask`.
4. Once connected, go to **File > Open Folder...** and open `/tmp/zask`.

Since the mounted macOS directory is read-only inside the VM, you cannot copy files back directly from within the VM shell. To sync your changes back to your Mac, run this from your **macOS terminal**:

```bash
# Copy files from the VM back to your Mac
limactl cp -r zask:/tmp/zask/ $(pwd)
```

Be careful with this command as it will overwrite files on your Mac with the contents from the VM. Always ensure you have a backup or use version control to prevent data loss.

## Daily Development Workflow on macOS + Lima VM

eBPF development requires splitting work between macOS (editing, linting) and the Linux VM (compiling eBPF, running the daemon). The Makefile automates this.

```bash
# 1. Edit code on macOS in your editor

# 2. Compile eBPF and build in the VM (copies project, generates, builds, syncs back)
make vm-build

# 3. Lint and test on macOS (uses the synced generated files)
make lint && make test

# 4. Run the daemon in the VM for kernel-level testing
make vm-run

# 5. In a separate terminal, run kernel-level tests
make vm-test
```

`make vm-build` handles the entire copy → generate → build → sync-back cycle automatically. You never need to manually SSH into the VM or copy files around.

### What Runs Where and Why

- **`make generate`** needs Linux clang with BPF target — must run in the VM
- **`make build`** works on both, but the VM produces the Linux binary you run with `sudo`
- **`make lint`** is pure Go source analysis — runs on macOS where `golangci-lint` is installed
- **`make test`** runs Go unit tests — works on macOS with the synced generated files
- **`sudo ./zaskd`** loads eBPF programs into the Linux kernel — VM only

### Manual VM Build (alternative)

If you prefer to work interactively inside the VM:

```bash
limactl shell zask

# Inside the VM
cp -r /Users/$(whoami)/src/zask /tmp/zask-build
cd /tmp/zask-build
make generate && make build
sudo ./zaskd
```


## VM Management

Quick commands for managing the Lima VM:

```bash
# List VMs
limactl list

# Stop the VM
limactl stop zask

# Start the VM
make start-vm

# Delete the VM and prune downloaded images (destructive)
make clean-vm

# SSH into the VM
limactl shell zask

# Run a single command in the VM
limactl shell zask -- uname -r
```

more information at [Lima documentation](https://lima-vm.io/docs/).

## Troubleshooting

### VM fails to start

```bash
# Check Lima logs
limactl logs zask

# Delete and recreate
make clean-vm
make start-vm
```

### BPF LSM not active after restart

SSH into the VM and check:

```bash
cat /sys/kernel/security/lsm
```

If `bpf` is not listed, manually update the kernel boot parameters:

```bash
sudo grubby --update-kernel=ALL --args="lsm=lockdown,capability,landlock,yama,selinux,bpf"
```

Then restart the VM:

```bash
exit  # Leave the VM
limactl stop zask
limactl start zask
```

### vmlinux.h not generated

make sure you copied the project to a writable location inside the VM and you are in the correct directory.

Inside the VM:

```bash
# Check if BTF is available
ls -la /sys/kernel/btf/vmlinux

# Generate manually
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

### Slow performance

Increase VM resources in `lima/zask.yaml`:

```yaml
cpus: 8
memory: "8GiB"
```

Then recreate:

```bash
make clean-vm
make start-vm
```
