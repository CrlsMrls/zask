#!/usr/bin/env bash
# scripts/check-env.sh — Validates ZASK environment prerequisites.
#
# Checks:
#   1. Kernel version ≥ 5.18
#   2. CONFIG_BPF_LSM=y
#   3. CONFIG_DEBUG_INFO_BTF=y
#   4. CONFIG_BPF_SYSCALL=y
#   5. CONFIG_IMA=y
#   6. "bpf" listed in active LSM modules
#   7. BPF filesystem mounted at /sys/fs/bpf
#   8. IMA active with bprm_check policy
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

# --- 1. Kernel version ≥ 5.18 ---
echo "Checking kernel version..."
KERNEL_VERSION=$(uname -r | cut -d'-' -f1)
MAJOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f1)
MINOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f2)

if [[ "$MAJOR" -gt 5 ]] || { [[ "$MAJOR" -eq 5 ]] && [[ "$MINOR" -ge 18 ]]; }; then
    pass "Kernel version $KERNEL_VERSION (≥ 5.18)"
else
    fail "Kernel version $KERNEL_VERSION (need ≥ 5.18 for bpf_ima_file_hash)"
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

# --- 5. CONFIG_IMA=y ---
IMA=$(read_kconfig "CONFIG_IMA")
if [[ "$IMA" == "CONFIG_IMA=y" ]]; then
    pass "CONFIG_IMA=y"
else
    fail "CONFIG_IMA=y (got: ${IMA:-not found}). Required for bpf_ima_file_hash() support."
fi

# --- 6. "bpf" in active LSM list ---
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

# --- 7. BPF filesystem mounted ---
echo "Checking BPF filesystem..."
if mount | grep -q "type bpf"; then
    pass "BPF filesystem mounted"
else
    fail "BPF filesystem not mounted at /sys/fs/bpf. Run: mount -t bpf bpf /sys/fs/bpf"
fi

# --- 8. IMA active with bprm_check policy ---
echo "Checking IMA (Integrity Measurement Architecture)..."
if [[ -d /sys/kernel/security/ima ]]; then
    pass "IMA security fs present (/sys/kernel/security/ima)"
else
    fail "/sys/kernel/security/ima not found. Boot with ima_policy=tcb or add 'ima_policy=tcb' to kernel parameters."
fi

# The built-in ima_policy=tcb includes BPRM_CHECK but does not write rules to the
# policy pseudofile (which only reflects explicitly-loaded custom policies).
# Accept either: an explicit BPRM_CHECK rule in the policy file, or the tcb/exec-tcb
# built-in policy active via kernel cmdline.
if grep -q "func=BPRM_CHECK" /sys/kernel/security/ima/policy 2>/dev/null; then
    pass "IMA bprm_check policy active (explicit rule)"
elif grep -qE "ima_policy=(tcb|exec-tcb)" /proc/cmdline 2>/dev/null; then
    pass "IMA bprm_check policy active (built-in tcb via ima_policy= boot param)"
else
    fail "IMA policy does not include BPRM_CHECK. Boot with 'ima_policy=tcb' to enable binary measurement."
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
