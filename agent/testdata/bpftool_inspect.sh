#!/bin/bash
export PATH=/usr/local/go/bin:/root/go/bin:/usr/bin:/bin:/usr/sbin:/sbin
export GOPATH=/root/go
export HOME=/root

# Run the test in background
cd /mnt/e/Work/kyanos
go test -v -run TestPidFilterOnly -count=1 -timeout 30s ./agent/ > /tmp/gotest_output.txt 2>&1 &
TEST_PID=$!
sleep 8  # Wait for BPF to load and attach

echo "=== BPF programs (tracing type) ==="
bpftool prog list type tracing 2>/dev/null | head -20

echo ""
echo "=== BPF maps containing 'filter_pid' ==="
bpftool map list 2>/dev/null | grep -A5 "filter_pid"

echo ""
echo "=== BPF links ==="
bpftool link list 2>/dev/null | head -20

echo ""
echo "=== Dumping filter_pid_map contents ==="
# Find filter_pid_map ID
MAP_ID=$(bpftool map list 2>/dev/null | grep -B1 "filter_pid" | head -1 | awk '{print $1}' | tr -d ':')
if [ -n "$MAP_ID" ]; then
    echo "Map ID: $MAP_ID"
    bpftool map dump id $MAP_ID 2>/dev/null
fi

# Kill the test
kill $TEST_PID 2>/dev/null
wait $TEST_PID 2>/dev/null

echo ""
echo "=== Test output ==="
cat /tmp/gotest_output.txt
