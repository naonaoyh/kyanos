#!/bin/bash
# Real packet capture integration test for Kyanos (no PID filter)
export PATH=/usr/local/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH
cd /home/naonaoyh/projects/kyanos

echo "=== Starting HTTP server on port 18086 ==="
python3 -m http.server 18086 > /dev/null 2>&1 &
SERVER_PID=$!
sleep 1
echo "=== Server PID: $SERVER_PID ==="

echo "=== Starting Kyanos watch http (no PID filter, local port 18086) ==="
./kyanos watch http --local-ports 18086 --debug-output > /tmp/kyanos_capture.log 2>&1 &
KYANOS_PID=$!
sleep 3

echo "=== Making HTTP requests ==="
curl -s http://127.0.0.1:18086/ > /dev/null
curl -s http://127.0.0.1:18086/go.mod > /dev/null
curl -s http://127.0.0.1:18086/Makefile > /dev/null
echo "=== 3 requests done ==="
sleep 3

echo "=== Stopping kyanos ==="
kill -INT $KYANOS_PID 2>/dev/null
sleep 2
kill -9 $KYANOS_PID 2>/dev/null
kill $SERVER_PID 2>/dev/null

echo ""
echo "=== Capture log (last 80 lines) ==="
tail -80 /tmp/kyanos_capture.log
echo ""
echo "=== Lines with HTTP keywords ==="
grep -i "GET\|HTTP\|200\|request\|response\|record" /tmp/kyanos_capture.log | wc -l
echo "=== DONE ==="
