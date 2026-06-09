#!/bin/bash
# =============================================================================
# NTRIP TUI/WebUI Integration Test
# =============================================================================
# Drives Kyanos TUI or WebUI using real PCAP replay traffic.
#
# Usage:
#   ./test_ntrip_ui.sh --tui             # Test TUI mode (interactive)
#   ./test_ntrip_ui.sh --webui           # Test WebUI mode (Console + Agent + frontend)
#   ./test_ntrip_ui.sh --webui --open    # WebUI + auto-open browser
#   ./test_ntrip_ui.sh --debug           # Debug output mode (non-interactive)
#
# Requirements:
#   - WSL2 with eBPF support
#   - Built kyanos binary (run 'make' first)
#   - Python3 (for PCAP replay)
#   - For --webui: npm installed (for 'npm run dev' frontend)
# =============================================================================

set -e
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PROJDIR=$(pwd)
cd "$PROJDIR"

REPLAY_PORT=25340
PCAP_FILE="testdata/testdata-small.pcap"
REPLAY_SPEED=5.0
REPLAY_DURATION=120  # seconds

# Parse arguments
MODE="tui"
OPEN_BROWSER=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --tui) MODE="tui"; shift ;;
        --webui) MODE="webui"; shift ;;
        --debug) MODE="debug"; shift ;;
        --open) OPEN_BROWSER=true; shift ;;
        --port) REPLAY_PORT=$2; shift 2 ;;
        --speed) REPLAY_SPEED=$2; shift 2 ;;
        --pcap) PCAP_FILE=$2; shift 2 ;;
        --duration) REPLAY_DURATION=$2; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=============================================="
echo "  NTRIP UI Integration Test"
echo "  Mode: $MODE"
echo "  PCAP: $PCAP_FILE"
echo "  Port: $REPLAY_PORT"
echo "  Speed: ${REPLAY_SPEED}x"
echo "  Duration: ${REPLAY_DURATION}s"
echo "=============================================="
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    [ -n "$KYANOS_PID" ] && kill -9 $KYANOS_PID 2>/dev/null || true
    [ -n "$CONSOLE_PID" ] && kill -9 $CONSOLE_PID 2>/dev/null || true
    [ -n "$REPLAY_PID" ] && kill -9 $REPLAY_PID 2>/dev/null || true
    [ -n "$FRONTEND_PID" ] && kill -9 $FRONTEND_PID 2>/dev/null || true
    wait 2>/dev/null || true
    echo "=== Cleanup done ==="
}
trap cleanup EXIT

# Check prerequisites
if [ ! -f "./kyanos" ]; then
    echo "ERROR: kyanos binary not found. Run 'make' first."
    exit 1
fi
if [ ! -f "$PCAP_FILE" ]; then
    echo "ERROR: PCAP file not found: $PCAP_FILE"
    exit 1
fi

# --- Start based on mode ---

if [ "$MODE" = "webui" ]; then
    # WebUI mode: start Console + Agent + frontend + replay

    echo "=== Starting Console backend ==="
    ./kyanos console --grpc-addr :50051 --http-addr :8080 &
    CONSOLE_PID=$!
    sleep 2

    echo "=== Starting frontend dev server ==="
    cd console/frontend
    npx vite --port 5173 --host > /tmp/frontend.log 2>&1 &
    FRONTEND_PID=$!
    cd "$PROJDIR"
    sleep 2

    echo "=== Starting Agent with gRPC ==="
    ./kyanos watch ntrip --grpc-server localhost:50051 --diag --diag-report \
        --local-ports $REPLAY_PORT --no-tui &
    KYANOS_PID=$!
    sleep 3

    echo ""
    echo "=============================================="
    echo "  WebUI is running!"
    echo "  Frontend: http://localhost:5173"
    echo "  API:      http://localhost:8080"
    echo "=============================================="
    echo ""

elif [ "$MODE" = "tui" ]; then
    # TUI mode: start Agent with TUI + replay

    echo "=== Starting Kyanos TUI ==="
    echo "  (TUI will take over the terminal)"
    echo "  (Press 'd' for diagnostic view, 'q' to quit)"
    echo ""
    sleep 1

    ./kyanos watch ntrip --diag --diag-report --local-ports $REPLAY_PORT &
    KYANOS_PID=$!
    sleep 3

elif [ "$MODE" = "debug" ]; then
    # Debug mode: non-interactive, log to file

    echo "=== Starting Kyanos in debug mode ==="
    ./kyanos watch ntrip --diag --diag-report --diag-jsonl /tmp/ui_test_sessions.jsonl \
        --local-ports $REPLAY_PORT --debug-output > /tmp/ui_test_debug.log 2>&1 &
    KYANOS_PID=$!
    sleep 3
fi

# --- Start PCAP replay ---
echo "=== Starting PCAP replay (port $REPLAY_PORT, ${REPLAY_SPEED}x speed, ${REPLAY_DURATION}s) ==="
python3 testdata/replay_pcap.py \
    --pcap "$PCAP_FILE" \
    --port $REPLAY_PORT \
    --inject-handshake GET \
    --speed $REPLAY_SPEED \
    --repeat \
    --duration $REPLAY_DURATION &
REPLAY_PID=$!

# --- Wait for replay ---
echo "=== Replay running (PID $REPLAY_PID) ==="
echo "  Press Ctrl+C to stop"
echo ""

# Wait for replay to finish or user interrupt
wait $REPLAY_PID 2>/dev/null || true

echo ""
echo "=== Replay finished ==="

# Debug mode: show results
if [ "$MODE" = "debug" ]; then
    echo ""
    echo "=============================================="
    echo "  RESULTS"
    echo "=============================================="

    echo ""
    echo "--- Diagnostic reports ---"
    grep "NTRIP Session Diagnostic Report" /tmp/ui_test_debug.log | wc -l
    echo " sessions reported"

    echo ""
    echo "--- JSONL sessions ---"
    if [ -f "/tmp/ui_test_sessions.jsonl" ]; then
        wc -l < /tmp/ui_test_sessions.jsonl
        echo " sessions exported"
    else
        echo "No JSONL output"
    fi

    echo ""
    echo "--- Protocol detection ---"
    grep "protocol=15" /tmp/ui_test_debug.log | wc -l
    echo " NTRIP protocol events"

    echo ""
    echo "--- RTCM frames ---"
    grep "RTCM3 Frame" /tmp/ui_test_debug.log | wc -l
    echo " RTCM frames captured"
fi

echo ""
echo "=== TEST COMPLETE ==="
