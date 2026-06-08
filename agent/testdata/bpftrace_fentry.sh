#!/bin/bash
export PATH=/usr/local/go/bin:/root/go/bin:/usr/bin:/bin:/usr/sbin:/sbin
export GOPATH=/root/go
export HOME=/root

# First build the simple connect program
go build -o /tmp/dial_only ./agent/testdata/dial_only.go 2>/dev/null

echo "=== Testing fentry with bpftrace ==="
bpftrace -e '
fentry:__sys_connect { printf("fentry __sys_connect PID=%d TID=%d comm=%s\n", pid, tid, comm); }
fexit:__sys_connect { printf("fexit __sys_connect PID=%d TID=%d comm=%s ret=%d\n", pid, tid, comm, retval); }
' > /tmp/bpftrace_fentry.txt 2>&1 &
BPF_PID=$!
sleep 2

echo "Running Go dial_only..."
/tmp/dial_only 2>&1
sleep 1

echo "Running C connect..."
/tmp/c_connect 2>&1
sleep 1

kill -INT $BPF_PID 2>/dev/null
sleep 1
wait $BPF_PID 2>/dev/null

echo ""
echo "=== fentry bpftrace output ==="
cat /tmp/bpftrace_fentry.txt
