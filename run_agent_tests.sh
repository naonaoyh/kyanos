#!/bin/bash
# Kyanos Agent Integration Test Runner
# Run in WSL terminal: bash ~/projects/kyanos/run_agent_tests.sh
#
# Requires: sudo, Go at ~/local/go, curl, internet access

set -o pipefail

export PATH="/home/naonaoyh/local/go/bin:/home/naonaoyh/local/bin:$PATH"
KYANOS_DIR="$HOME/projects/kyanos"
LOG_DIR="$KYANOS_DIR/test_logs"
mkdir -p "$LOG_DIR"

cd "$KYANOS_DIR"

echo "============================================="
echo "  Kyanos Agent Integration Test Suite"
echo "  $(date)"
echo "  Kernel: $(uname -r)"
echo "  Go: $(go version)"
echo "============================================="
echo ""

# Check prerequisites
echo "[Pre-flight] Checking prerequisites..."
if ! go version &>/dev/null; then
    echo "  ERROR: Go not found in PATH"
    exit 1
fi
if ! which curl &>/dev/null; then
    echo "  ERROR: curl not found"
    exit 1
fi
echo "  Go: $(go version)"
echo "  curl: $(curl --version | head -1)"
echo "  sudo: $(sudo -n true 2>&1 && echo 'OK (cached)' || echo 'will prompt')"
echo ""

# ============================================================
# Phase 1: Basic syscall tests (connect, accept, read, write)
# ============================================================
echo "============================================="
echo "  Phase 1: Basic Syscall Tests"
echo "============================================="
echo ""

TESTS_PHASE1="TestConnectSyscall TestAccept TestRead TestWrite"
for test in $TESTS_PHASE1; do
    echo "--- Running: $test ---"
    START=$(date +%s)
    sudo -E env "PATH=$PATH" go test -v -count=1 -timeout 120s -run "^${test}$" ./agent/ 2>&1 | tee "$LOG_DIR/${test}.log"
    EXIT_CODE=${PIPESTATUS[0]}
    END=$(date +%s)
    ELAPSED=$((END - START))
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "  => PASS (${ELAPSED}s)"
    else
        echo "  => FAIL (exit=$EXIT_CODE, ${ELAPSED}s)"
    fi
    echo ""
done

# ============================================================
# Phase 2: Syscall variants (recvfrom, sendto, readv, writev, recvmsg, sendmsg)
# ============================================================
echo "============================================="
echo "  Phase 2: Syscall Variant Tests"
echo "============================================="
echo ""

TESTS_PHASE2="TestRecvFrom TestSendto TestReadv TestWritev TestRecvmsg TestSendMsg"
for test in $TESTS_PHASE2; do
    echo "--- Running: $test ---"
    START=$(date +%s)
    sudo -E env "PATH=$PATH" go test -v -count=1 -timeout 120s -run "^${test}$" ./agent/ 2>&1 | tee "$LOG_DIR/${test}.log"
    EXIT_CODE=${PIPESTATUS[0]}
    END=$(date +%s)
    ELAPSED=$((END - START))
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "  => PASS (${ELAPSED}s)"
    else
        echo "  => FAIL (exit=$EXIT_CODE, ${ELAPSED}s)"
    fi
    echo ""
done

# ============================================================
# Phase 3: Kernel-level tests (network stack monitoring)
# ============================================================
echo "============================================="
echo "  Phase 3: Kernel Network Stack Tests"
echo "============================================="
echo ""

TESTS_PHASE3="TestIpXmit TestDevQueueXmit TestDevHardStartXmit TestTracepointNetifReceiveSkb TestIpRcvCore TestTcpV4DoRcv TestSkbCopyDatagramIter"
for test in $TESTS_PHASE3; do
    echo "--- Running: $test ---"
    START=$(date +%s)
    sudo -E env "PATH=$PATH" go test -v -count=1 -timeout 120s -run "^${test}$" ./agent/ 2>&1 | tee "$LOG_DIR/${test}.log"
    EXIT_CODE=${PIPESTATUS[0]}
    END=$(date +%s)
    ELAPSED=$((END - START))
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "  => PASS (${ELAPSED}s)"
    else
        echo "  => FAIL (exit=$EXIT_CODE, ${ELAPSED}s)"
    fi
    echo ""
done

# ============================================================
# Phase 4: SSL/TLS tests
# ============================================================
echo "============================================="
echo "  Phase 4: SSL/TLS Tests"
echo "============================================="
echo ""

TESTS_PHASE4="TestSslRead TestSslWrite TestSslEventsCanRelatedToKernEvents"
for test in $TESTS_PHASE4; do
    echo "--- Running: $test ---"
    START=$(date +%s)
    sudo -E env "PATH=$PATH" go test -v -count=1 -timeout 120s -run "^${test}$" ./agent/ 2>&1 | tee "$LOG_DIR/${test}.log"
    EXIT_CODE=${PIPESTATUS[0]}
    END=$(date +%s)
    ELAPSED=$((END - START))
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "  => PASS (${ELAPSED}s)"
    else
        echo "  => FAIL (exit=$EXIT_CODE, ${ELAPSED}s)"
    fi
    echo ""
done

# ============================================================
# Phase 5: Connection lifecycle tests
# ============================================================
echo "============================================="
echo "  Phase 5: Connection Lifecycle Tests"
echo "============================================="
echo ""

TESTS_PHASE5="TestExistedConn TestCloseSyscall"
for test in $TESTS_PHASE5; do
    echo "--- Running: $test ---"
    START=$(date +%s)
    sudo -E env "PATH=$PATH" go test -v -count=1 -timeout 120s -run "^${test}$" ./agent/ 2>&1 | tee "$LOG_DIR/${test}.log"
    EXIT_CODE=${PIPESTATUS[0]}
    END=$(date +%s)
    ELAPSED=$((END - START))
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "  => PASS (${ELAPSED}s)"
    else
        echo "  => FAIL (exit=$EXIT_CODE, ${ELAPSED}s)"
    fi
    echo ""
done

# ============================================================
# Summary
# ============================================================
echo "============================================="
echo "  Test Summary"
echo "============================================="
echo ""

ALL_TESTS="$TESTS_PHASE1 $TESTS_PHASE2 $TESTS_PHASE3 $TESTS_PHASE4 $TESTS_PHASE5"
PASS=0
FAIL=0
for test in $ALL_TESTS; do
    if grep -q "^ok" "$LOG_DIR/${test}.log" 2>/dev/null; then
        echo "  PASS: $test"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "Total: $((PASS + FAIL))  Passed: $PASS  Failed: $FAIL"
echo ""
echo "Logs saved to: $LOG_DIR/"
echo "============================================="
