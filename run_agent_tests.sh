#!/usr/bin/env bash
# Kyanos Agent Integration Test Runner
#
# Usage:
#   ./run_agent_tests.sh              # Full test suite
#   ./run_agent_tests.sh --quick      # Quick smoke test (4 key tests)
#   ./run_agent_tests.sh --test NAME  # Run a single test by name
#
# Requires: Go, curl, internet access
# Root is auto-elevated when not already root.

set -o pipefail

# ── Root auto-elevation ─────────────────────────────────────────
ensure_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[INFO] This script requires root privileges. Re-executing with sudo..."
        exec sudo -E env "PATH=$PATH" "$0" "$@"
    fi
}

# ── Project root detection ──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KYANOS_DIR="$SCRIPT_DIR"
LOG_DIR="$KYANOS_DIR/test_logs"
mkdir -p "$LOG_DIR"

# ── Go auto-detection ───────────────────────────────────────────
detect_go() {
    if command -v go &>/dev/null; then
        return 0
    fi
    # Common Go install paths
    for p in /usr/local/go/bin /snap/bin /home/*/go/bin /home/*/local/go/bin; do
        if [ -x "$p/go" ]; then
            export PATH="$p:$PATH"
            return 0
        fi
    done
    echo "ERROR: Go not found. Install Go or add it to PATH."
    exit 1
}

# ── Parse arguments ─────────────────────────────────────────────
MODE="full"
SINGLE_TEST=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)
            MODE="quick"
            shift
            ;;
        --test)
            MODE="single"
            SINGLE_TEST="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--quick | --test TEST_NAME]"
            echo ""
            echo "  (no args)     Run full test suite"
            echo "  --quick        Quick smoke test (4 key tests)"
            echo "  --test NAME    Run a single test by name"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Auto-elevate to root
ensure_root "$@"

detect_go

cd "$KYANOS_DIR"

echo "============================================="
echo "  Kyanos Agent Integration Test Suite"
echo "  Mode: $MODE"
echo "  $(date)"
echo "  Kernel: $(uname -r)"
echo "  Go: $(go version)"
echo "============================================="
echo ""

# Check prerequisites
echo "[Pre-flight] Checking prerequisites..."
if ! which curl &>/dev/null; then
    echo "  ERROR: curl not found"
    exit 1
fi
echo "  Go: $(go version)"
echo "  curl: $(curl --version | head -1)"
echo "  User: $(whoami) (uid=$(id -u))"
echo ""

# ── Test execution helper ───────────────────────────────────────
run_test() {
    local test="$1"
    local timeout="${2:-120}"
    echo "--- Running: $test ---"
    local start=$(date +%s)
    go test -v -count=1 -timeout "${timeout}s" -run "^${test}$" ./agent/ 2>&1 | tee "$LOG_DIR/${test}.log"
    local exit_code=${PIPESTATUS[0]}
    local end=$(date +%s)
    local elapsed=$((end - start))

    if [ $exit_code -eq 0 ]; then
        echo "  => PASS (${elapsed}s)"
        PASS_COUNT=$((PASS_COUNT + 1))
        PASS_LIST="$PASS_LIST $test"
    else
        echo "  => FAIL (exit=$exit_code, ${elapsed}s)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAIL_LIST="$FAIL_LIST $test"
    fi
    echo ""
}

PASS_COUNT=0
FAIL_COUNT=0
PASS_LIST=""
FAIL_LIST=""

# ── Quick mode: 4 key tests ─────────────────────────────────────
run_quick() {
    echo "============================================="
    echo "  Quick Smoke Test (4 tests)"
    echo "============================================="
    echo ""
    run_test "TestConnectSyscall"
    run_test "TestRead"
    run_test "TestWrite"
    run_test "TestSslRead"
}

# ── Full mode: all phases ────────────────────────────────────────
run_full() {
    echo "============================================="
    echo "  Phase 1: Basic Syscall Tests"
    echo "============================================="
    echo ""
    for test in TestConnectSyscall TestAccept TestRead TestWrite; do
        run_test "$test"
    done

    echo "============================================="
    echo "  Phase 2: Syscall Variant Tests"
    echo "============================================="
    echo ""
    for test in TestRecvFrom TestSendto TestReadv TestWritev TestRecvmsg TestSendMsg; do
        run_test "$test"
    done

    echo "============================================="
    echo "  Phase 3: Kernel Network Stack Tests"
    echo "============================================="
    echo ""
    for test in TestIpXmit TestDevQueueXmit TestDevHardStartXmit TestTracepointNetifReceiveSkb TestIpRcvCore TestTcpV4DoRcv TestSkbCopyDatagramIter; do
        run_test "$test"
    done

    echo "============================================="
    echo "  Phase 4: SSL/TLS Tests"
    echo "============================================="
    echo ""
    for test in TestSslRead TestSslWrite TestSslEventsCanRelatedToKernEvents; do
        run_test "$test"
    done

    echo "============================================="
    echo "  Phase 5: Connection Lifecycle Tests"
    echo "============================================="
    echo ""
    for test in TestExistedConn TestCloseSyscall; do
        run_test "$test"
    done
}

# ── Dispatch ─────────────────────────────────────────────────────
case "$MODE" in
    quick)
        run_quick
        ;;
    single)
        if [ -z "$SINGLE_TEST" ]; then
            echo "ERROR: --test requires a test name"
            exit 1
        fi
        echo "============================================="
        echo "  Single Test: $SINGLE_TEST"
        echo "============================================="
        echo ""
        run_test "$SINGLE_TEST"
        ;;
    full)
        run_full
        ;;
esac

# ── Summary ──────────────────────────────────────────────────────
echo "============================================="
echo "  Test Summary"
echo "============================================="
echo ""

TOTAL=$((PASS_COUNT + FAIL_COUNT))

if [ $PASS_COUNT -gt 0 ]; then
    for t in $PASS_LIST; do
        echo "  PASS: $t"
    done
fi

if [ $FAIL_COUNT -gt 0 ]; then
    for t in $FAIL_LIST; do
        echo "  FAIL: $t"
    done
fi

echo ""
echo "Total: $TOTAL  Passed: $PASS_COUNT  Failed: $FAIL_COUNT"
echo ""
echo "Logs saved to: $LOG_DIR/"
echo "============================================="

exit $FAIL_COUNT
