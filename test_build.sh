#!/bin/bash
export PATH="/usr/local/go/bin:$PATH"
echo "=== Go Version ==="
go version
cd /mnt/e/Work/kyanos
echo "=== Go Build ==="
export CGO_LDFLAGS="-Xlinker -rpath=. -static"
go build -o kyanos -v
echo "=== Files ==="
ls -la kyanos
echo "=== Done ==="
