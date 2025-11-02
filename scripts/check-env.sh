#!/usr/bin/env bash
# scripts/check-env.sh — Validates ZASK environment prerequisites.
#
# Checks:
#   1. Kernel version ≥ 5.8
#   2. CONFIG_BPF_LSM=y
#   3. CONFIG_DEBUG_INFO_BTF=y
#   4. CONFIG_BPF_SYSCALL=y
#   5. "bpf" listed in active LSM modules
#   6. BPF filesystem mounted at /sys/fs/bpf
#
# Exit codes:
#   0 — All prerequisites met
#   1 — One or more prerequisites failed

set -euo pipefail

PASS=0
FAIL=0

pass() {
    echo "  [PASS] $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  [FAIL] $1"
    FAIL=$((FAIL + 1))
}

echo "=== ZASK Environment Check ==="
echo ""

# --- 0. OS Check ---
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "  [FAIL] Operating System is $(uname -s), but Linux is required."
    echo "         If you are on macOS, please run this script inside the Lima VM."
    echo "         See docs/lima-dev-guide.md for instructions."
    exit 1
fi

# --- 1. Kernel version ≥ 5.8 ---
echo "Checking kernel version..."
KERNEL_VERSION=$(uname -r | cut -d'-' -f1)
MAJOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f1)
MINOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f2)

if [[ "$MAJOR" -gt 5 ]] || { [[ "$MAJOR" -eq 5 ]] && [[ "$MINOR" -ge 8 ]]; }; then
    pass "Kernel version $KERNEL_VERSION (≥ 5.8)"
else
    fail "Kernel version $KERNEL_VERSION (need ≥ 5.8)"
fi

# --- Helper: read kernel config ---
read_kconfig() {
    local key="$1"
    # Try /proc/config.gz first, then /boot/config-$(uname -r)
    if [[ -f /proc/config.gz ]]; then
        zcat /proc/config.gz 2>/dev/null | grep -E "^${key}=" | head -1 || true
    elif [[ -f "/boot/config-$(uname -r)" ]]; then
        grep -E "^${key}=" "/boot/config-$(uname -r)" | head -1 || true
    else
        echo ""
    fi
}

# --- 2. CONFIG_BPF_LSM=y ---
echo "Checking kernel config options..."
BPF_LSM=$(read_kconfig "CONFIG_BPF_LSM")
if [[ "$BPF_LSM" == "CONFIG_BPF_LSM=y" ]]; then
    pass "CONFIG_BPF_LSM=y"
else
    fail "CONFIG_BPF_LSM=y (got: ${BPF_LSM:-not found})"
fi

# --- 3. CONFIG_DEBUG_INFO_BTF=y ---
BTF=$(read_kconfig "CONFIG_DEBUG_INFO_BTF")
if [[ "$BTF" == "CONFIG_DEBUG_INFO_BTF=y" ]]; then
    pass "CONFIG_DEBUG_INFO_BTF=y"
else
    fail "CONFIG_DEBUG_INFO_BTF=y (got: ${BTF:-not found})"
fi

# --- 4. CONFIG_BPF_SYSCALL=y ---
BPF_SYSCALL=$(read_kconfig "CONFIG_BPF_SYSCALL")
if [[ "$BPF_SYSCALL" == "CONFIG_BPF_SYSCALL=y" ]]; then
    pass "CONFIG_BPF_SYSCALL=y"
else
    fail "CONFIG_BPF_SYSCALL=y (got: ${BPF_SYSCALL:-not found})"
fi

# --- 5. "bpf" in active LSM list ---
echo "Checking LSM modules..."
if [[ -f /sys/kernel/security/lsm ]]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    if echo "$LSM_LIST" | grep -q "bpf"; then
        pass "BPF LSM active (lsm=$LSM_LIST)"
    else
        fail "BPF not in LSM list (lsm=$LSM_LIST). Add 'bpf' to kernel boot parameter: lsm=lockdown,capability,bpf"
    fi
else
    fail "/sys/kernel/security/lsm not found"
fi

# --- 6. BPF filesystem mounted ---
echo "Checking BPF filesystem..."
if mount | grep -q "type bpf"; then
    pass "BPF filesystem mounted"
else
    fail "BPF filesystem not mounted at /sys/fs/bpf. Run: mount -t bpf bpf /sys/fs/bpf"
fi

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [[ "$FAIL" -gt 0 ]]; then
    echo ""
    echo "Environment does NOT meet ZASK prerequisites."
    echo "See docs/kernel-requirements.md for setup instructions."
    exit 1
fi

echo "Environment is ready for ZASK."
exit 0
