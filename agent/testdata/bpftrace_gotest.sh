#!/bin/bash
# Run bpftrace while go test is running to see if kprobes fire for the test process

echo "Starting bpftrace..."
bpftrace -e '
kprobe:__sys_connect { printf("kprobe __sys_connect PID=%d TID=%d comm=%s\n", pid, tid, comm); }
tracepoint:syscalls:sys_enter_connect { printf("tp sys_enter_connect PID=%d TID=%d comm=%s\n", pid, tid, comm); }
' > /tmp/bpftrace_gotest.txt 2>&1 &
BPF_PID=$!
sleep 2

echo "Running go test TestGoConnectPath..."
cd /mnt/e/Work/kyanos
export PATH=/usr/local/go/bin:/root/go/bin:$PATH
export GOPATH=/root/go
export HOME=/root
go test -v -run TestGoConnectPath -count=1 -timeout 30s ./agent/ 2>&1 | head -30

sleep 2
echo "Stopping bpftrace..."
kill -INT $BPF_PID 2>/dev/null
sleep 1
wait $BPF_PID 2>/dev/null

echo ""
echo "=== bpftrace captured events ==="
cat /tmp/bpftrace_gotest.txt
echo ""
echo "=== Filtering for go test PIDs ==="
# Show events from go, agent_test, or similar
grep -E "(go|agent|test)" /tmp/bpftrace_gotest.txt 2>/dev/null || echo "(no matching events)"
