#!/bin/bash
# =============================================================================
# TUI 驱动测试 — 使用 pcap 回放驱动 Kyanos Bubble Tea TUI
# =============================================================================
# 在 WSL2 中运行，kyanos 在前台接管终端显示 TUI，
# PCAP 回放在后台持续产生 NTRIP 流量。
#
# 用法:
#   ./test_ntrip_tui.sh                  # 默认 5x 速度，持续 120 秒
#   ./test_ntrip_tui.sh --speed 10       # 10x 加速
#   ./test_ntrip_tui.sh --duration 300   # 持续 5 分钟
#   ./test_ntrip_tui.sh --no-diag        # 不启用诊断引擎
# =============================================================================

export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PROJDIR=/mnt/e/Work/kyanos
cd "$PROJDIR"

REPLAY_PORT=25341
PCAP_FILE="testdata/testdata-small.pcap"
SPEED=5.0
DURATION=120
DIAG_FLAGS="--diag --diag-report --diag-jsonl /tmp/tui_sessions.jsonl --tcp-health"

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --speed)    SPEED=$2; shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --port)     REPLAY_PORT=$2; shift 2 ;;
        --pcap)     PCAP_FILE=$2; shift 2 ;;
        --no-diag)  DIAG_FLAGS=""; shift ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

echo "=============================================="
echo "  NTRIP TUI 驱动测试"
echo "  PCAP:    $PCAP_FILE"
echo "  端口:    $REPLAY_PORT"
echo "  速度:    ${SPEED}x"
echo "  持续:    ${DURATION}s"
echo "  诊断:    ${DIAG_FLAGS:-关闭}"
echo "=============================================="
echo ""

# 清理函数
REPLAY_PID=""
cleanup() {
    echo ""
    echo "=== 清理中 ==="
    [ -n "$REPLAY_PID" ] && kill -9 $REPLAY_PID 2>/dev/null
    # 清理可能残留的 python3 进程
    pkill -f "replay_pcap.py.*$REPLAY_PORT" 2>/dev/null
    wait 2>/dev/null
    echo "=== 完成 ==="
}
trap cleanup EXIT INT TERM

# 检查前置条件
if [ ! -f "./kyanos" ]; then
    echo "错误: 找不到 kyanos 二进制，请先运行 make"
    exit 1
fi
if [ ! -f "$PCAP_FILE" ]; then
    echo "错误: 找不到 PCAP 文件: $PCAP_FILE"
    exit 1
fi

# 先启动 PCAP 回放（后台）
echo "=== 启动 PCAP 回放 (端口 $REPLAY_PORT, ${SPEED}x, ${DURATION}s) ==="
python3 testdata/replay_pcap.py \
    --pcap "$PCAP_FILE" \
    --port $REPLAY_PORT \
    --inject-handshake GET \
    --speed $SPEED \
    --repeat \
    --duration $DURATION &
REPLAY_PID=$!
echo "  回放 PID: $REPLAY_PID"
sleep 2

# 启动 kyanos TUI（前台，接管终端）
echo ""
echo "=== 启动 Kyanos TUI ==="
echo "  操作提示:"
echo "    d     切换到诊断面板"
echo "    Enter 查看记录详情"
echo "    1-9   按列排序"
echo "    q     退出"
echo ""

./kyanos watch ntrip \
    --local-ports $REPLAY_PORT \
    --max-records 200 \
    $DIAG_FLAGS

# kyanos 退出后清理
echo ""
echo "=== Kyanos 已退出 ==="
