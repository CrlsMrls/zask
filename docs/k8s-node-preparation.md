# Kubernetes Node Preparation Guide

ZASK's eBPF programs load into the **host kernel** of worker nodes, not into containers. All containers on a node share the host kernel, so ZASK automatically monitors executions across all Pods once deployed to a node.

This guide covers how to prepare Kubernetes worker nodes to meet ZASK's kernel requirements.

## Overview

Worker nodes must run a Linux kernel meeting these requirements:

- Kernel **≥ 5.8** (recommended: ≥ 6.1)
- `CONFIG_BPF_LSM=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_SYSCALL=y`
- Boot parameter: `lsm=lockdown,capability,bpf`

See [kernel-requirements.md](kernel-requirements.md) for full details.

## AWS (EKS)

### Custom AMI Approach

Standard EKS-optimized AMIs may not have `CONFIG_BPF_LSM=y` or the correct boot parameters. You'll need a custom AMI.

1. **Start with the EKS-optimized AMI** as the base.

2. **Rebuild the kernel** (if BPF LSM is not enabled):
   ```bash
   # Check existing config
   zcat /proc/config.gz | grep CONFIG_BPF_LSM
   # If not =y, you need a custom kernel
   ```

3. **Modify boot parameters** via GRUB:
   ```bash
   sudo sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=lockdown,capability,landlock,yama,bpf"/' /etc/default/grub
   sudo update-grub
   ```

4. **Create the AMI:**
   ```bash
   aws ec2 create-image --instance-id <id> --name "eks-zask-node" --description "EKS node with BPF LSM"
   ```

5. **Use the custom AMI in your node group:**
   ```yaml
   apiVersion: eksctl.io/v1alpha5
   kind: ClusterConfig
   managedNodeGroups:
     - name: zask-nodes
       ami: ami-xxxxxxxxxxxx
       overrideBootstrapCommand: |
         /etc/eks/bootstrap.sh <cluster-name>
   ```

### Bottlerocket

[Bottlerocket](https://github.com/bottlerocket-os/bottlerocket) is an AWS-maintained OS for containers. Check if your Bottlerocket variant supports BPF LSM:

```bash
# On a Bottlerocket node
apiclient get os.kernel
```

## GCP (GKE)

### Custom Node Image

1. **Create a base image** from a GKE-compatible Ubuntu version:
   ```bash
   gcloud compute images create zask-node-image \
     --source-image-family=ubuntu-2404-lts-amd64 \
     --source-image-project=ubuntu-os-cloud
   ```

2. **Launch an instance, configure the kernel, and re-image:**
   ```bash
   # SSH into the instance
   gcloud compute ssh zask-builder

   # Modify boot parameters
   sudo sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=lockdown,capability,landlock,yama,bpf"/' /etc/default/grub
   sudo update-grub

   # Verify after reboot
   cat /sys/kernel/security/lsm
   ```

3. **Create the final image:**
   ```bash
   gcloud compute images create zask-gke-node \
     --source-disk=zask-builder \
     --source-disk-zone=us-central1-a
   ```

4. **Use in a GKE node pool:**
   ```bash
   gcloud container node-pools create zask-pool \
     --cluster=my-cluster \
     --image-type=UBUNTU_CONTAINERD \
     --node-version=latest
   ```

## Azure (AKS)

### Custom VHD

1. **Start with an AKS-compatible Ubuntu base image.**

2. **Configure the kernel** as described in the general instructions above.

3. **Create a managed image or Shared Image Gallery version** for use with AKS node pools.

## General Approach (Any Provider)

### 1. Verify Kernel Config

SSH into a worker node and run:

```bash
# Copy the check script
scp scripts/check-env.sh node:/tmp/
ssh node '/tmp/check-env.sh'
```

### 2. Modify Boot Parameters

If `bpf` is not in the LSM list:

```bash
# Edit GRUB
sudo vi /etc/default/grub
# Add to GRUB_CMDLINE_LINUX: lsm=lockdown,capability,landlock,yama,bpf

sudo update-grub
sudo reboot
```

### 3. Mount BPF Filesystem

Most modern distributions mount this automatically. If not:

```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

To make it persistent, add to `/etc/fstab`:

```
bpf  /sys/fs/bpf  bpf  defaults  0  0
```

### 4. Generate vmlinux.h

On the target node (needed for eBPF compilation):

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > /path/to/zask/bpf/vmlinux.h
```

## ZASK Deployment Model

ZASK runs as a **DaemonSet** on Kubernetes, with one instance per node:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: zask
  namespace: zask-system
spec:
  selector:
    matchLabels:
      app: zask
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
        - name: zaskd
          image: zask:latest
          securityContext:
            privileged: true  # Required for BPF operations
          volumeMounts:
            - name: bpf-fs
              mountPath: /sys/fs/bpf
            - name: kernel-btf
              mountPath: /sys/kernel/btf
              readOnly: true
      volumes:
        - name: bpf-fs
          hostPath:
            path: /sys/fs/bpf
        - name: kernel-btf
          hostPath:
            path: /sys/kernel/btf
      nodeSelector:
        zask.io/enabled: "true"
```

## Node Labeling

Label nodes that are prepared for ZASK:

```bash
kubectl label node <node-name> zask.io/enabled=true
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `CONFIG_BPF_LSM` not set | Rebuild kernel with this option or use a compatible distribution |
| `bpf` not in LSM list | Add `bpf` to the `lsm=` boot parameter and reboot |
| BPF filesystem not mounted | `mount -t bpf bpf /sys/fs/bpf` |
| `/sys/kernel/btf/vmlinux` missing | Kernel not built with `CONFIG_DEBUG_INFO_BTF=y` |
| Permission denied loading BPF | Ensure container runs with `privileged: true` or appropriate capabilities |
