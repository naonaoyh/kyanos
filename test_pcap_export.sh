#!/bin/bash
# Test standalone PCAP-NG export via --pcap-output flag
#
# Self-contained: embeds a minimal NTRIP caster and client.
# Root is auto-elevated when not already root.

set -e

# ── Root auto-elevation ─────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "[INFO] This script requires root privileges (kyanos uses eBPF). Re-executing with sudo..."
    exec sudo -E env "PATH=$PATH" "$0" "$@"
fi

PROJDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJDIR"

PCAP_PORT=25332
PCAP_FILE=/tmp/test_pcap_output.pcapng
DIAG_LOG=/tmp/pcap_diag.log
CASTER_PY=/tmp/pcap_test_caster.py
CLIENT_PY=/tmp/pcap_test_client.py

# ── Cleanup trap ─────────────────────────────────────────────────
cleanup() {
    kill $KYANOS_PID 2>/dev/null || true
    kill $CASTER_PID 2>/dev/null || true
    wait $KYANOS_PID 2>/dev/null || true
    wait $CASTER_PID 2>/dev/null || true
    rm -f "$CASTER_PY" "$CLIENT_PY"
}
trap cleanup EXIT

rm -f "$PCAP_FILE" "$PCAP_FILE"_part*.pcapng

# ── Embedded NTRIP Caster ───────────────────────────────────────
cat > "$CASTER_PY" << 'PYEOF'
import http.server, struct, time, sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 25332

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[caster] {fmt % args}\n")
    def do_GET(self):
        if self.path == "/":
            table = "STR;RTCM3;RTCM3;RTCM 3.2;1005(1);2;GPS;NONE;CHN;31;121;0;0;sNTRIP;none;B;N;0;\r\nENDSOURCETABLE\r\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(table.encode())
        elif self.path == "/RTCM3":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            msg_types = [1005, 1077, 1087]
            try:
                for _ in range(10):
                    for mt in msg_types:
                        payload = struct.pack('>H', mt << 4) + bytes(30)
                        header = struct.pack('>BH', 0xD3, len(payload) & 0x3FF)
                        crc = b'\x00\x00\x00'
                        self.wfile.write(header + payload + crc)
                    self.wfile.flush()
                    time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError):
                pass

server = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
print(f"Caster running on port {PORT}", flush=True)
server.serve_forever()
PYEOF

# ── Embedded NTRIP Client ───────────────────────────────────────
cat > "$CLIENT_PY" << 'PYEOF'
import urllib.request, sys, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 25332
url = f"http://127.0.0.1:{PORT}/RTCM3"

req = urllib.request.Request(url)
req.add_header("Ntrip-Version", "Ntrip/2.0")
req.add_header("User-Agent", "PcapTestClient/1.0")

print(f"Connecting to {url}...", flush=True)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        total = 0
        while True:
            data = resp.read(1024)
            if not data:
                break
            total += len(data)
            if total > 2000:
                break
        print(f"Received {total} bytes", flush=True)
except Exception as e:
    print(f"Client error: {e}", flush=True)
PYEOF

echo "=== Starting caster on port $PCAP_PORT ==="
python3 "$CASTER_PY" $PCAP_PORT > /tmp/pcap_caster.log 2>&1 &
CASTER_PID=$!
sleep 1

echo "=== Starting kyanos with --pcap-output ==="
./kyanos watch ntrip --diag --pcap-output "$PCAP_FILE" --local-ports $PCAP_PORT --no-tui --debug-output > "$DIAG_LOG" 2>&1 &
KYANOS_PID=$!
sleep 3

echo "=== Running NTRIP client ==="
python3 "$CLIENT_PY" $PCAP_PORT 2>&1
sleep 3

echo "=== Stopping ==="
kill -INT $KYANOS_PID 2>/dev/null || true
sleep 2
kill -9 $KYANOS_PID 2>/dev/null || true
kill $CASTER_PID 2>/dev/null || true
wait $KYANOS_PID 2>/dev/null || true
wait $CASTER_PID 2>/dev/null || true

echo ""
echo "=============================================="
echo "  PCAP EXPORT VERIFICATION"
echo "=============================================="

echo ""
echo "--- PCAP file ---"
if [ -f "$PCAP_FILE" ]; then
    ls -la "$PCAP_FILE"
    echo "File type: $(file "$PCAP_FILE" 2>/dev/null || echo 'unknown')"
else
    echo "PCAP file NOT FOUND"
fi

echo ""
echo "--- Part files ---"
ls -la "${PCAP_FILE}"_part*.pcapng 2>/dev/null || echo "No part files"

echo ""
echo "--- PCAP log entries ---"
grep -i "pcap\|PCAP" "$DIAG_LOG" 2>/dev/null | head -5 || echo "No pcap log entries"

echo ""
echo "--- Diagnostic report check ---"
grep "NTRIP Session Diagnostic Report" "$DIAG_LOG" 2>/dev/null | head -2 || echo "No diagnostic report"

echo ""
echo "=============================================="
echo "  RESULT"
echo "=============================================="
STATUS=0
if [ -f "$PCAP_FILE" ] && [ "$(stat -c%s "$PCAP_FILE" 2>/dev/null || echo 0)" -gt 0 ]; then
    echo "PCAP file created: PASS ($(stat -c%s "$PCAP_FILE") bytes)"
else
    echo "PCAP file created: FAIL"
    STATUS=1
fi

echo ""
echo "=== TEST COMPLETE (exit=$STATUS) ==="
exit $STATUS
