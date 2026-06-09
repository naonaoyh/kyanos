#!/bin/bash
# Check if the kprobe events come from specific CPUs
export PATH=/usr/local/go/bin:/root/go/bin:/usr/bin:/bin:/usr/sbin:/sbin
export GOPATH=/root/go
export HOME=/root

echo "Checking CPU info..."
nproc
lscpu | grep -E "^CPU\(s\)|Thread|Core|Socket|NUMA"

echo ""
echo "Starting bpftrace to check which CPU connect events fire on..."
bpftrace -e '
kprobe:__sys_connect {
    printf("__sys_connect PID=%d TID=%d comm=%s CPU=%d\n", pid, tid, comm, cpu);
}
' > /tmp/bpftrace_cpu.txt 2>&1 &
BPF_PID=$!
sleep 2

echo "Running Go dial_only..."
/tmp/dial_only 2>&1
sleep 0.5

echo "Running C connect..."
/tmp/c_connect 2>&1
sleep 0.5

echo "Running curl..."
curl -s --connect-timeout 2 http://127.0.0.1:1 > /dev/null 2>&1
sleep 0.5

kill -INT $BPF_PID 2>/dev/null
sleep 1
wait $BPF_PID 2>/dev/null

echo ""
echo "=== bpftrace CPU output ==="
cat /tmp/bpftrace_cpu.txt
