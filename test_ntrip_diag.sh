#!/bin/bash
# =============================================================================
# NTRIP Diagnostic Engine End-to-End Test
# =============================================================================
# Tests the full kyanos --diag pipeline: NTRIP capture → session tracking →
# GGA/RTCM analysis → disconnect classification → diagnostic report
#
# Uses a fake NTRIP caster that simulates a realistic session lifecycle:
#   1. Client connects with Basic Auth
#   2. Server responds ICY 200 OK
#   3. Client sends multiple GGA position updates (at intervals)
#   4. Server streams RTCM frames (multiple types, at intervals)
#   5. Connection closes (server-initiated)
# =============================================================================

set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH
PROJDIR=/mnt/e/Work/kyanos
cd $PROJDIR

CASTER_PORT=25326
DIAG_LOG=/tmp/kyanos_diag.log
JSONL_LOG=/tmp/kyanos_sessions.jsonl

# --- Create a realistic fake NTRIP caster ---
cat > /tmp/diag_caster.py << 'PYEOF'
import socket, struct, time, threading

def crc24q(data):
    crc = 0
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF

def make_rtcm_frame(msg_type, payload_body):
    type_bytes = struct.pack('>H', (msg_type << 4) & 0xFFF0)
    payload = type_bytes + payload_body
    length = len(payload)
    header = bytes([0xD3, (length >> 8) & 0x03, length & 0xFF])
    frame_no_crc = header + payload
    crc = crc24q(frame_no_crc)
    crc_bytes = struct.pack('>I', crc)[1:]
    return frame_no_crc + crc_bytes

def handle_client(conn, addr):
    print(f"[caster] client connected from {addr}")
    data = conn.recv(4096)
    request = data.decode('latin-1')
    
    if 'GET' not in request or 'RTCM3' not in request:
        conn.sendall(b"HTTP/1.1 401 Unauthorized\r\n\r\n")
        conn.close()
        return

    # Send ICY 200 OK
    conn.sendall(b"ICY 200 OK\r\n\r\n")
    print("[caster] sent ICY 200 OK")
    time.sleep(0.3)

    # Receive GGA #1
    try:
        gga = conn.recv(4096)
        if gga:
            print(f"[caster] received GGA: {gga.decode('latin-1').strip()[:60]}...")
    except:
        pass

    # Stream RTCM frames with realistic intervals
    # Simulates a 5-second RTCM session with 1004/1005/1077 frames
    rtcm_sequence = [
        (1004, 0.3),  # GPS observations
        (1005, 0.3),  # Station coordinates
        (1077, 0.5),  # GPS MSM7
        (1004, 0.3),
        (1077, 0.5),
        (1004, 0.3),
        (1005, 0.3),
        (1077, 0.5),
        (1004, 0.3),
        (1077, 0.5),
    ]

    for msg_type, delay in rtcm_sequence:
        body = struct.pack('>I', int(time.time() * 1000) & 0xFFFFFFFF) + b'\x00' * 28
        frame = make_rtcm_frame(msg_type, body)
        try:
            conn.sendall(frame)
        except BrokenPipeError:
            print("[caster] client disconnected")
            return
        time.sleep(delay)

    # Receive GGA #2 (client should send periodic GGA)
    try:
        conn.settimeout(1)
        gga2 = conn.recv(4096)
        if gga2:
            print(f"[caster] received GGA #2: {gga2.decode('latin-1').strip()[:60]}...")
    except:
        pass

    # Server closes connection (simulates normal disconnect)
    time.sleep(0.5)
    conn.close()
    print("[caster] connection closed (server-initiated)")

def run_caster(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(2)
    srv.settimeout(30)
    print(f"[caster] listening on port {port}")
    try:
        conn, addr = srv.accept()
        handle_client(conn, addr)
        # Accept second connection for reconnect test
        try:
            srv.settimeout(5)
            conn2, addr2 = srv.accept()
            handle_client(conn2, addr2)
        except socket.timeout:
            pass
    except socket.timeout:
        print("[caster] timeout")
    srv.close()

if __name__ == '__main__':
    import sys
    run_caster(int(sys.argv[1]) if len(sys.argv) > 1 else 2106)
PYEOF

# --- Create a realistic NTRIP client ---
cat > /tmp/diag_client.py << 'PYEOF'
import socket, time, base64, sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 2106

def connect_session(session_num):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', port))
    
    # NTRIP v1 request with auth
    auth = base64.b64encode(b'gnss_user:secret123').decode()
    request = (
        f"GET /RTCM3_MOUNT HTTP/1.0\r\n"
        f"User-Agent: NTRIP GNSSReceiver/2.1\r\n"
        f"Authorization: Basic {auth}\r\n"
        f"Ntrip-Version: Ntrip/1.0\r\n"
        f"\r\n"
    )
    sock.sendall(request.encode())
    print(f"[client #{session_num}] sent NTRIP request (user=gnss_user, mount=RTCM3_MOUNT)")

    # Read response
    time.sleep(0.3)
    resp = sock.recv(1024)
    print(f"[client #{session_num}] response: {resp.decode('latin-1').strip()}")

    # Send GGA position #1
    gga1 = "$GPGGA,083000.00,3130.1234,N,12115.5678,E,1,10,0.9,25.3,M,-2.1,M,1.5,0003*5B\r\n"
    sock.sendall(gga1.encode())
    print(f"[client #{session_num}] sent GGA #1 (lat=31.502, lon=121.259)")

    # Receive RTCM frames for ~4 seconds
    total = 0
    start = time.time()
    try:
        while time.time() - start < 6:
            sock.settimeout(2)
            data = sock.recv(4096)
            if not data:
                break
            total += len(data)
    except socket.timeout:
        pass
    except ConnectionResetError:
        pass

    # Send GGA position #2 (moved slightly)
    try:
        gga2 = "$GPGGA,083005.00,3130.1240,N,12115.5685,E,1,11,0.8,25.5,M,-2.1,M,1.2,0003*58\r\n"
        sock.sendall(gga2.encode())
        print(f"[client #{session_num}] sent GGA #2 (moved ~1m)")
    except:
        pass

    print(f"[client #{session_num}] received {total} RTCM bytes total")
    sock.close()
    print(f"[client #{session_num}] disconnected")
    return total

# Session 1
print("=== Session 1 ===")
connect_session(1)

# Brief pause then reconnect (tests reconnection detection)
time.sleep(1)
print("\n=== Session 2 (reconnect) ===")
try:
    connect_session(2)
except ConnectionRefusedError:
    print("[client #2] connection refused (caster shut down)")
PYEOF

echo "=============================================="
echo "  NTRIP Diagnostic Engine E2E Test"
echo "=============================================="
echo ""

# Clean up old logs
rm -f $DIAG_LOG $JSONL_LOG

# --- Start caster ---
echo "=== Starting fake NTRIP caster ==="
python3 /tmp/diag_caster.py $CASTER_PORT > /tmp/diag_caster.log 2>&1 &
CASTER_PID=$!
sleep 1

# --- Start Kyanos with --diag --diag-report ---
echo "=== Starting Kyanos with diagnostics enabled ==="
./kyanos watch ntrip --diag --diag-report --diag-jsonl $JSONL_LOG \
    --tcp-health --debug-output -d \
    > $DIAG_LOG 2>&1 &
KYANOS_PID=$!
sleep 4

# --- Run client ---
echo "=== Running NTRIP client (2 sessions) ==="
python3 /tmp/diag_client.py $CASTER_PORT 2>&1
echo ""

# --- Wait for diagnostic processing ---
echo "=== Waiting for diagnostic engine to process ==="
sleep 6

# --- Stop ---
echo "=== Stopping ==="
kill -INT $KYANOS_PID 2>/dev/null
sleep 2
kill -9 $KYANOS_PID 2>/dev/null
kill $CASTER_PID 2>/dev/null
wait $KYANOS_PID 2>/dev/null
wait $CASTER_PID 2>/dev/null

echo ""
echo "=============================================="
echo "  RESULTS"
echo "=============================================="

echo ""
echo "--- Caster log ---"
cat /tmp/diag_caster.log

echo ""
echo "--- JSONL session export ---"
if [ -f "$JSONL_LOG" ]; then
    echo "Sessions exported: $(wc -l < $JSONL_LOG)"
    cat $JSONL_LOG | python3 -m json.tool 2>/dev/null | head -50 || cat $JSONL_LOG
else
    echo "No JSONL output (file not created)"
fi

echo ""
echo "--- Diagnostic report output ---"
grep -i "diag\|score\|session\|issue\|disconnect\|GGA\|RTCM\|auth\|report" $DIAG_LOG | grep -v "fexit\|fentry\|256 color\|openssl\|btf" | head -30

echo ""
echo "--- Protocol detection ---"
grep "protocol updated\|protocol=15\|NTRIP" $DIAG_LOG | head -5

echo ""
echo "--- Session data captured ---"
grep "syscall.*protocol=15" $DIAG_LOG | wc -l
echo "syscall events with NTRIP protocol"

echo ""
echo "=== TEST COMPLETE ==="
