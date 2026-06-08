#!/bin/bash
export PATH=/usr/local/go/bin:/root/go/bin:/usr/bin:/bin:/usr/sbin:/sbin
export GOPATH=/root/go
export HOME=/root

echo "Starting bpftrace to check if kyanos BPF functions fire..."
# Trace the match_trace_tgid function AND submit_new_conn
bpftrace -e '
kprobe:match_trace_tgid { @match_called = count(); printf("match_trace_tgid called PID=%d TID=%d\n", pid, tid); }
kprobe:submit_new_conn { @submit_called = count(); printf("submit_new_conn called PID=%d TID=%d\n", pid, tid); }
kprobe:process_syscall_connect { @process_called = count(); printf("process_syscall_connect called PID=%d TID=%d\n", pid, tid); }
kprobe:handle_syscall_exit_connect { printf("handle_syscall_exit_connect called PID=%d TID=%d\n", pid, tid); }
kprobe:handle_syscall_enter_connect { printf("handle_syscall_enter_connect called PID=%d TID=%d\n", pid, tid); }
' > /tmp/bpftrace_kyanos.txt 2>&1 &
BPF_PID=$!
sleep 2

echo "Running TestPidFilterOnly..."
cd /mnt/e/Work/kyanos
go test -v -run TestPidFilterOnly -count=1 -timeout 20s ./agent/ 2>&1 | tail -10
sleep 2

kill -INT $BPF_PID 2>/dev/null
sleep 1
wait $BPF_PID 2>/dev/null

echo ""
echo "=== bpftrace output ==="
cat /tmp/bpftrace_kyanos.txt
