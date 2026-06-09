#!/usr/bin/env bash
# preflight-check.sh — TKE 节点 eBPF 兼容性预检脚本
#
# 用法:
#   ./deploy/scripts/preflight-check.sh
#
# 此脚本检查当前节点是否满足 Kyanos eBPF Agent 的运行条件:
#   - 内核版本 ≥ 5.4
#   - BTF 支持
#   - BPF 系统调用可用
#   - 必要的 cgroup v2 挂载
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
WARN=0
FAIL=0

pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    ((PASS++))
}

warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
    ((WARN++))
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    ((FAIL++))
}

echo "=========================================="
echo "  Kyanos eBPF 节点预检"
echo "=========================================="
echo ""

# ── 1. 内核版本检查 ──────────────────────────────────────────────
echo "[1/6] 内核版本"
KERNEL_VERSION="$(uname -r)"
KERNEL_MAJOR="$(echo "$KERNEL_VERSION" | cut -d. -f1)"
KERNEL_MINOR="$(echo "$KERNEL_VERSION" | cut -d. -f2)"

echo "  当前内核: ${KERNEL_VERSION}"

if [ "$KERNEL_MAJOR" -ge 6 ] || ([ "$KERNEL_MAJOR" -ge 5 ] && [ "$KERNEL_MINOR" -ge 4 ]); then
    pass "内核版本 ${KERNEL_MAJOR}.${KERNEL_MINOR} ≥ 5.4"
elif [ "$KERNEL_MAJOR" -ge 5 ]; then
    warn "内核版本 ${KERNEL_MAJOR}.${KERNEL_MINOR}，建议升级到 5.4+ 以获得完整 eBPF 支持"
else
    fail "内核版本 ${KERNEL_MAJOR}.${KERNEL_MINOR} 过低，需要 ≥ 5.4"
fi

# ── 2. BTF 支持检查 ─────────────────────────────────────────────
echo ""
echo "[2/6] BTF (BPF Type Format) 支持"

if [ -f /sys/kernel/btf/vmlinux ]; then
    pass "/sys/kernel/btf/vmlinux 存在"
else
    warn "/sys/kernel/btf/vmlinux 不存在（Agent 将使用内置 BTF 回退文件）"
fi

# 检查内核编译选项
if [ -f /proc/config.gz ]; then
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_DEBUG_INFO_BTF=y"; then
        pass "CONFIG_DEBUG_INFO_BTF=y 已启用"
    else
        warn "CONFIG_DEBUG_INFO_BTF 未启用（Agent 将使用内置 BTF 回退文件）"
    fi
elif [ -f "/boot/config-${KERNEL_VERSION}" ]; then
    if grep -q "CONFIG_DEBUG_INFO_BTF=y" "/boot/config-${KERNEL_VERSION}" 2>/dev/null; then
        pass "CONFIG_DEBUG_INFO_BTF=y 已启用"
    else
        warn "CONFIG_DEBUG_INFO_BTF 配置未知（/boot/config 中未找到）"
    fi
else
    warn "无法检查内核配置（/proc/config.gz 和 /boot/config 均不存在）"
fi

# ── 3. BPF 系统调用 ─────────────────────────────────────────────
echo ""
echo "[3/6] BPF 系统调用"

if [ -e /sys/fs/bpf ]; then
    pass "/sys/fs/bpf (bpffs) 已挂载"
else
    fail "/sys/fs/bpf (bpffs) 未挂载"
fi

# 检查 bpf() 系统调用是否可用
if command -v bpftool &>/dev/null; then
    if bpftool prog list &>/dev/null; then
        pass "bpftool 可用且 BPF 系统调用正常"
    else
        warn "bpftool 存在但 BPF 系统调用可能受限"
    fi
else
    warn "bpftool 未安装（非必须，但有助于诊断）"
fi

# ── 4. cgroup 挂载 ──────────────────────────────────────────────
echo ""
echo "[4/6] cgroup 支持"

CGROUP_V1="$(mount | grep -c 'cgroup ' || true)"
CGROUP_V2="$(mount | grep -c 'cgroup2' || true)"

if [ "$CGROUP_V2" -gt 0 ]; then
    pass "cgroup v2 已挂载"
elif [ "$CGROUP_V1" -gt 0 ]; then
    pass "cgroup v1 已挂载（eBPF 网络探针兼容）"
else
    warn "未检测到 cgroup 挂载"
fi

# ── 5. 内核模块检查 ─────────────────────────────────────────────
echo ""
echo "[5/6] 必要的内核特性"

# 检查 perf_event 支持
if [ -e /sys/kernel/debug/tracing ]; then
    pass "tracefs 可用"
else
    warn "tracefs 未挂载（部分 BPF 探针可能受限）"
fi

# 检查 kprobe 支持
if [ -f /sys/kernel/debug/kprobe/enabled ] || [ -f /sys/kernel/debug/tracing/kprobe_events ]; then
    pass "kprobe 支持可用"
else
    warn "kprobe 支持未知（tracefs 中未找到 kprobe 文件）"
fi

# ── 6. 容器运行时 ───────────────────────────────────────────────
echo ""
echo "[6/6] 容器运行时检测"

FOUND_RUNTIME=false
if [ -S /run/containerd/containerd.sock ]; then
    pass "containerd socket 可用: /run/containerd/containerd.sock"
    FOUND_RUNTIME=true
fi
if [ -S /var/run/docker.sock ]; then
    pass "Docker socket 可用: /var/run/docker.sock"
    FOUND_RUNTIME=true
fi
if [ -S /run/crio/crio.sock ]; then
    pass "CRI-O socket 可用: /run/crio/crio.sock"
    FOUND_RUNTIME=true
fi
if [ "$FOUND_RUNTIME" = false ]; then
    warn "未检测到标准容器运行时 socket"
fi

# ── 汇总 ────────────────────────────────────────────────────────
echo ""
echo "=========================================="
echo "  预检结果汇总"
echo "=========================================="
echo -e "  通过: ${GREEN}${PASS}${NC}"
echo -e "  警告: ${YELLOW}${WARN}${NC}"
echo -e "  失败: ${RED}${FAIL}${NC}"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "  ${RED}节点不满足 Kyanos Agent 运行条件。${NC}"
    echo "  请升级内核版本或更换节点操作系统。"
    exit 1
elif [ "$WARN" -gt 0 ]; then
    echo -e "  ${YELLOW}节点基本满足条件，部分特性可能需要 Agent 内置回退机制。${NC}"
    exit 0
else
    echo -e "  ${GREEN}节点完全满足 Kyanos Agent 运行条件！${NC}"
    exit 0
fi
