#!/bin/bash
# =============================================================================
# WebUI 驱动测试 — 使用 pcap 回放驱动 Web Console 全链路
# =============================================================================
# 在 WSL2 中运行完整 WebUI 栈：Console + Agent + PCAP 回放，
# 前端通过 Vite 代理访问（Windows 侧启动或使用内嵌模式）。
#
# 用法:
#   ./test_ntrip_webui.sh                     # 内嵌模式，自动打开浏览器
#   ./test_ntrip_webui.sh --separate          # 分离模式（Console + Agent 独立进程）
#   ./test_ntrip_webui.sh --speed 10          # 10x 加速
#   ./test_ntrip_webui.sh --duration 300      # 持续 5 分钟
#   ./test_ntrip_webui.sh --no-browser        # 不自动打开浏览器
# =============================================================================

export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PROJDIR=/mnt/e/Work/kyanos
cd "$PROJDIR"

REPLAY_PORT=25342
PCAP_FILE="testdata/testdata-small.pcap"
SPEED=5.0
DURATION=180
MODE="embedded"    # embedded | separate
OPEN_BROWSER=true

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --speed)       SPEED=$2; shift 2 ;;
        --duration)    DURATION=$2; shift 2 ;;
        --port)        REPLAY_PORT=$2; shift 2 ;;
        --pcap)        PCAP_FILE=$2; shift 2 ;;
        --separate)    MODE="separate"; shift ;;
        --no-browser)  OPEN_BROWSER=false; shift ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

echo "=============================================="
echo "  NTRIP WebUI 驱动测试"
echo "  模式:    $MODE"
echo "  PCAP:    $PCAP_FILE"
echo "  端口:    $REPLAY_PORT"
echo "  速度:    ${SPEED}x"
echo "  持续:    ${DURATION}s"
echo "=============================================="
echo ""

# 清理函数
PIDS=()
cleanup() {
    echo ""
    echo "=== 清理中 ==="
    for pid in "${PIDS[@]}"; do
        kill -9 $pid 2>/dev/null
    done
    pkill -f "replay_pcap.py.*$REPLAY_PORT" 2>/dev/null
    pkill -f "kyanos.*$REPLAY_PORT" 2>/dev/null
    wait 2>/dev/null
    echo "=== 完成 ==="
}
trap cleanup EXIT INT TERM

# 检查前置条件
if [ ! -f "./kyanos" ]; then
    echo "错误: 找不到 kyanos 二进制，请先运行 make"
    exit 1
fi

if [ "$MODE" = "embedded" ]; then
    # ================================================================
    # 内嵌模式：Agent + Console 在同一进程，前端从 dist/ 提供
    # ================================================================

    # 确保前端已构建
    if [ ! -d "console/frontend/dist" ]; then
        echo "=== 前端未构建，正在构建 ==="
        cd console/frontend && npm install && npm run build && cd "$PROJDIR"
    fi

    # 启动内嵌 WebUI Agent（后台）
    echo "=== 启动内嵌 WebUI Agent ==="
    BROWSER_FLAG=""
    if [ "$OPEN_BROWSER" = "true" ]; then
        BROWSER_FLAG="--open-browser"
    fi

    ./kyanos watch ntrip \
        --webui --webui-addr :8080 \
        $BROWSER_FLAG \
        --diag --diag-report --tcp-health \
        --local-ports $REPLAY_PORT \
        --no-tui > /tmp/webui_agent.log 2>&1 &
    KYANOS_PID=$!
    PIDS+=($KYANOS_PID)
    echo "  Agent PID: $KYANOS_PID"
    sleep 3

    echo ""
    echo "=============================================="
    echo "  WebUI 已启动（内嵌模式）"
    echo ""
    echo "  浏览器访问: http://localhost:8080"
    echo ""
    echo "  功能验证清单:"
    echo "    □ Cluster Topology — 查看 Agent 节点"
    echo "    □ Session Explorer — 实时会话列表"
    echo "    □ Session Detail — 事件时间线 + 实时统计"
    echo "    □ Alerts — 告警面板"
    echo "    □ Report — 诊断报告"
    echo "    □ 侧边栏 TUI ON/OFF 开关"
    echo "=============================================="
    echo ""

elif [ "$MODE" = "separate" ]; then
    # ================================================================
    # 分离模式：Console、Agent、前端各自独立
    # ================================================================

    # 启动 Console
    echo "=== 启动 Console 后端 ==="
    ./kyanos console --grpc-addr :50051 --http-addr :8080 &
    CONSOLE_PID=$!
    PIDS+=($CONSOLE_PID)
    echo "  Console PID: $CONSOLE_PID"
    sleep 2

    # 启动 Agent
    echo "=== 启动 Agent ==="
    ./kyanos watch ntrip \
        --grpc-server localhost:50051 \
        --diag --diag-report --tcp-health \
        --local-ports $REPLAY_PORT \
        --no-tui > /tmp/webui_agent.log 2>&1 &
    KYANOS_PID=$!
    PIDS+=($KYANOS_PID)
    echo "  Agent PID: $KYANOS_PID"
    sleep 3

    echo ""
    echo "=============================================="
    echo "  后端已启动（分离模式）"
    echo ""
    echo "  请在 Windows 终端中启动前端:"
    echo "    cd E:\\Work\\kyanos\\console\\frontend"
    echo "    npm run dev"
    echo ""
    echo "  然后浏览器访问: http://localhost:5173"
    echo "=============================================="
    echo ""
fi

# 启动 PCAP 回放
echo "=== 启动 PCAP 回放 (端口 $REPLAY_PORT, ${SPEED}x, ${DURATION}s) ==="
python3 testdata/replay_pcap.py \
    --pcap "$PCAP_FILE" \
    --port $REPLAY_PORT \
    --inject-handshake GET \
    --speed $SPEED \
    --repeat \
    --duration $DURATION &
REPLAY_PID=$!
PIDS+=($REPLAY_PID)
echo "  回放 PID: $REPLAY_PID"
echo ""
echo "=== 按 Ctrl+C 停止所有进程 ==="
echo ""

# 等待回放结束
wait $REPLAY_PID 2>/dev/null || true
echo ""
echo "=== 回放结束 ==="

# 显示结果
echo ""
echo "=============================================="
echo "  结果"
echo "=============================================="

if [ -f "/tmp/webui_agent.log" ]; then
    echo ""
    echo "--- 诊断报告数 ---"
    grep -c "NTRIP Session Diagnostic Report" /tmp/webui_agent.log 2>/dev/null || echo "0"

    echo ""
    echo "--- RTCM 帧数 ---"
    grep -c "RTCM3 Frame" /tmp/webui_agent.log 2>/dev/null || echo "0"

    echo ""
    echo "--- JSONL 会话数 ---"
    if [ -f "/tmp/tui_sessions.jsonl" ]; then
        wc -l < /tmp/tui_sessions.jsonl
    else
        echo "0"
    fi
fi

echo ""
echo "=== 测试完成 ==="
