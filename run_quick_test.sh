#!/bin/bash
# Kyanos Quick Smoke Test - 4 key tests to demonstrate packet capture
# Run in WSL terminal: bash ~/projects/kyanos/run_quick_test.sh

set -o pipefail

export PATH="/home/naonaoyh/local/go/bin:/home/naonaoyh/local/bin:$PATH"
KYANOS_DIR="$HOME/projects/kyanos"
LOG_DIR="$KYANOS_DIR/test_logs"
mkdir -p "$LOG_DIR"

cd "$KYANOS_DIR"

echo "============================================="
echo "  Kyanos Quick Smoke Test"
echo "  $(date)"
echo "  Kernel: $(uname -r)"
echo "  Go: $(go version)"
echo "============================================="
echo ""

QUICK_TESTS="TestConnectSyscall TestRead TestWrite TestSslRead"
PASS=0
FAIL=0

for test in $QUICK_TESTS; do
    echo "--- Running: $test ---"
    START=$(date +%s)
    sudo -E env "PATH=$PATH" go test -v -count=1 -timeout 120s -run "^${test}$" ./agent/ 2>&1 | tee "$LOG_DIR/${test}.log"
    EXIT_CODE=${PIPESTATUS[0]}
    END=$(date +%s)
    ELAPSED=$((END - START))

    if [ $EXIT_CODE -eq 0 ]; then
        echo "  => PASS (${ELAPSED}s)"
        PASS=$((PASS + 1))
    else
        echo "  => FAIL (exit=$EXIT_CODE, ${ELAPSED}s)"
        FAIL=$((FAIL + 1))
    fi
    echo ""
done

echo "============================================="
echo "  Summary: $((PASS + FAIL)) tests, $PASS passed, $FAIL failed"
echo "  Logs: $LOG_DIR/"
echo "============================================="
