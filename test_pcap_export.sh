#!/bin/bash
# Test standalone PCAP-NG export via --pcap-output flag
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PROJDIR=/mnt/e/Work/kyanos
cd "$PROJDIR"

PCAP_PORT=25332
PCAP_FILE=/tmp/test_pcap_output.pcapng
DIAG_LOG=/tmp/pcap_diag.log

rm -f "$PCAP_FILE" "$PCAP_FILE"_part*.pcapng

echo "=== Starting caster on port $PCAP_PORT ==="
python3 /tmp/diag_caster.py $PCAP_PORT > /tmp/pcap_caster2.log 2>&1 &
CASTER_PID=$!
sleep 1

echo "=== Starting kyanos with --pcap-output ==="
./kyanos watch ntrip --diag --pcap-output "$PCAP_FILE" --local-ports $PCAP_PORT --debug-output > "$DIAG_LOG" 2>&1 &
KYANOS_PID=$!
sleep 3

echo "=== Running NTRIP client ==="
python3 /tmp/diag_client.py $PCAP_PORT 2>&1
sleep 3

echo "=== Stopping ==="
kill -INT $KYANOS_PID 2>/dev/null
sleep 2
kill -9 $KYANOS_PID 2>/dev/null
kill $CASTER_PID 2>/dev/null
wait $KYANOS_PID 2>/dev/null
wait $CASTER_PID 2>/dev/null

echo ""
echo "=============================================="
echo "  PCAP EXPORT VERIFICATION"
echo "=============================================="

echo ""
echo "--- PCAP file ---"
if [ -f "$PCAP_FILE" ]; then
    ls -la "$PCAP_FILE"
    echo "File type: $(file "$PCAP_FILE")"
else
    echo "PCAP file NOT FOUND"
fi

echo ""
echo "--- Part files ---"
ls -la "${PCAP_FILE}"_part*.pcapng 2>/dev/null || echo "No part files"

echo ""
echo "--- PCAP log entries ---"
grep -i "pcap\|PCAP" "$DIAG_LOG" | head -5 || echo "No pcap log entries"

echo ""
echo "--- Diagnostic report check ---"
grep "NTRIP Session Diagnostic Report" "$DIAG_LOG" | head -2 || echo "No diagnostic report"

echo ""
echo "=== TEST COMPLETE ==="
