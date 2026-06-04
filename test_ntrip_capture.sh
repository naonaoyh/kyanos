#!/bin/bash
# NTRIP/GGA/RTCM end-to-end capture test for Kyanos
# Simulates a minimal NTRIP caster that:
#   1. Receives NTRIP v1 request with Basic Auth
#   2. Receives GGA position upload from client
#   3. Streams RTCM 3.2 frames back to client
#
# Then uses Kyanos to capture and verify all three phases.
export PATH=/usr/local/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH
PROJDIR=/home/naonaoyh/projects/kyanos
cd $PROJDIR

CASTER_PORT=2101
LOG=/tmp/kyanos_ntrip.log
CASTER_SCRIPT=/tmp/fake_caster.py

# --- Step 1: Create a fake NTRIP caster ---
cat > $CASTER_SCRIPT << 'PYEOF'
import socket, struct, time, threading

def crc24q(data):
    """Compute CRC-24Q for RTCM framing."""
    crc = 0
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF

def make_rtcm_frame(msg_type, payload_body):
    """Build a valid RTCM 3.2 frame: D3 + 10-bit len + payload + CRC24Q."""
    # payload = 12-bit msg_type + body bits, but for simplicity pack as bytes
    # First 2 bytes of payload carry the message type (12 bits) + 4 padding bits
    type_bytes = struct.pack('>H', (msg_type << 4) & 0xFFF0)
    payload = type_bytes + payload_body
    length = len(payload)
    header = bytes([0xD3, (length >> 8) & 0x03, length & 0xFF])
    frame_no_crc = header + payload
    crc = crc24q(frame_no_crc)
    crc_bytes = struct.pack('>I', crc)[1:]  # 3 bytes
    return frame_no_crc + crc_bytes

def handle_client(conn, addr):
    print(f"[caster] connection from {addr}")
    data = conn.recv(4096)
    request = data.decode('latin-1')
    print(f"[caster] received request:\n{request[:200]}")

    # Check for NTRIP v1 GET request
    if 'GET' in request and 'RTCM3_TEST' in request:
        # Send ICY 200 OK (NTRIP v1 response)
        response = "ICY 200 OK\r\n\r\n"
        conn.sendall(response.encode())
        print("[caster] sent ICY 200 OK")

        # Wait for GGA sentence from client
        time.sleep(0.5)
        try:
            gga_data = conn.recv(4096)
            if gga_data:
                print(f"[caster] received GGA: {gga_data.decode('latin-1').strip()}")
        except:
            pass

        # Stream RTCM frames (1004, 1005, 1077)
        time.sleep(0.3)
        for msg_type in [1004, 1005, 1077, 1004, 1077]:
            # Create a dummy payload body (32 bytes of pseudo-observation data)
            body = struct.pack('>I', int(time.time() * 1000) & 0xFFFFFFFF) + b'\x00' * 28
            frame = make_rtcm_frame(msg_type, body)
            conn.sendall(frame)
            print(f"[caster] sent RTCM frame type={msg_type}, len={len(frame)}")
            time.sleep(0.2)

        time.sleep(0.5)
    else:
        conn.sendall(b"HTTP/1.1 401 Unauthorized\r\n\r\n")
        print("[caster] rejected (not NTRIP)")

    conn.close()
    print("[caster] connection closed")

def run_caster(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(1)
    srv.settimeout(15)
    print(f"[caster] listening on port {port}")
    try:
        conn, addr = srv.accept()
        handle_client(conn, addr)
    except socket.timeout:
        print("[caster] timeout waiting for client")
    srv.close()
    print("[caster] shutdown")

if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2101
    run_caster(port)
PYEOF

# --- Step 2: Create a fake NTRIP client ---
NTRIP_CLIENT_SCRIPT=/tmp/fake_ntrip_client.py
cat > $NTRIP_CLIENT_SCRIPT << 'PYEOF'
import socket, time, base64, sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 2101

# Connect to caster
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', port))
print("[client] connected to caster")

# Send NTRIP v1 GET request with Basic Auth
auth = base64.b64encode(b'testuser:testpass').decode()
request = (
    f"GET /RTCM3_TEST HTTP/1.0\r\n"
    f"User-Agent: NTRIP KyanosTest/1.0\r\n"
    f"Authorization: Basic {auth}\r\n"
    f"Ntrip-Version: Ntrip/1.0\r\n"
    f"\r\n"
)
sock.sendall(request.encode())
print(f"[client] sent NTRIP request (user=testuser, mount=RTCM3_TEST)")

# Read response
time.sleep(0.5)
resp = sock.recv(1024)
print(f"[client] response: {resp.decode('latin-1').strip()}")

# Send GGA position upload
gga = "$GPGGA,120000.00,3123.4567,N,12145.6789,E,1,12,0.8,50.0,M,0.0,M,1.0,0000*6A\r\n"
sock.sendall(gga.encode())
print(f"[client] sent GGA: {gga.strip()}")

# Receive RTCM frames
time.sleep(2)
total_received = 0
try:
    while True:
        sock.settimeout(3)
        data = sock.recv(4096)
        if not data:
            break
        total_received += len(data)
        # Count RTCM frames (look for 0xD3 sync byte)
        frames = data.count(b'\xD3')
        print(f"[client] received {len(data)} bytes ({frames} potential RTCM frames)")
except socket.timeout:
    pass

print(f"[client] total RTCM bytes received: {total_received}")
sock.close()
print("[client] disconnected")
PYEOF

echo "=============================================="
echo "  NTRIP/GGA/RTCM Capture Integration Test"
echo "=============================================="
echo ""

# --- Step 3: Start fake caster ---
echo "=== Starting fake NTRIP caster on port $CASTER_PORT ==="
python3 $CASTER_SCRIPT $CASTER_PORT > /tmp/caster.log 2>&1 &
CASTER_PID=$!
sleep 1

# --- Step 4: Start Kyanos to capture NTRIP traffic ---
echo "=== Starting Kyanos watch ntrip (port $CASTER_PORT) ==="
./kyanos watch ntrip --local-ports $CASTER_PORT --debug-output > $LOG 2>&1 &
KYANOS_PID=$!
sleep 3

# --- Step 5: Run NTRIP client ---
echo "=== Running NTRIP client ==="
python3 $NTRIP_CLIENT_SCRIPT $CASTER_PORT 2>&1
echo ""

# --- Step 6: Wait for Kyanos to process ---
echo "=== Waiting for Kyanos to process events ==="
sleep 4

# --- Step 7: Stop everything ---
echo "=== Stopping Kyanos and caster ==="
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
cat /tmp/caster.log

echo ""
echo "--- Kyanos NTRIP capture (full) ---"
cat $LOG

echo ""
echo "--- Verification ---"
echo -n "Auth/NTRIP request captured: "
grep -c "NTRIP\|Authorization\|testuser\|RTCM3_TEST\|ICY 200" $LOG || echo "0"
echo -n "GGA sentence captured: "
grep -c "GGA\|GPGGA\|3123\|12145" $LOG || echo "0"
echo -n "RTCM frames captured: "
grep -c -i "rtcm\|1004\|1005\|1077\|D3" $LOG || echo "0"
echo ""
echo "=== TEST COMPLETE ==="
