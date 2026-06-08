#!/bin/bash
# Trace connect-related kernel functions with bpftrace while running Go and C programs

echo "Starting bpftrace on connect functions..."
bpftrace -e '
kprobe:__sys_connect { printf("kprobe __sys_connect PID=%d TID=%d comm=%s\n", pid, tid, comm); }
kprobe:__sys_connect_file { printf("kprobe __sys_connect_file PID=%d TID=%d comm=%s\n", pid, tid, comm); }
kprobe:__x64_sys_connect { printf("kprobe __x64_sys_connect PID=%d TID=%d comm=%s\n", pid, tid, comm); }
tracepoint:syscalls:sys_enter_connect { printf("tp sys_enter_connect PID=%d TID=%d comm=%s\n", pid, tid, comm); }
' > /tmp/bpftrace_output.txt 2>&1 &
BPF_PID=$!
sleep 2

echo "=== Running Go connect program ==="
/tmp/simple_connect 2>&1
sleep 1

echo "=== Running C connect program ==="
gcc -o /tmp/c_connect /mnt/e/Work/kyanos/agent/testdata/c_connect.c 2>&1 && /tmp/c_connect 2>&1
sleep 1

echo "=== Running curl ==="
curl -s --connect-timeout 2 http://127.0.0.1:1 > /dev/null 2>&1
sleep 1

echo "Stopping bpftrace..."
kill -INT $BPF_PID 2>/dev/null
sleep 1
wait $BPF_PID 2>/dev/null

echo ""
echo "=== bpftrace output ==="
cat /tmp/bpftrace_output.txt
