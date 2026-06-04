#!/usr/bin/env python3
"""
NTRIP Caster using socketserver.TCPServer framework.

This uses the same Python socketserver framework as `python3 -m http.server`,
which Kyanos can track on WSL2 (its accept() triggers the BPF tracepoint).

The caster:
1. Accepts a GET request (NTRIP v1 or v2)
2. Responds with ICY 200 OK (for v1) or HTTP/1.1 200 (for v2)
3. Streams RTCM3.2 frames at ~1Hz with realistic message types
4. Accepts GGA position backchannel from client
5. Closes after a configurable duration

For use with: sudo kyanos watch ntrip --diag --debug-output
"""

import socketserver
import struct
import time
import threading
import sys

# RTCM CRC-24Q
def crc24q(data):
    crc = 0
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF

def make_rtcm_frame(msg_type, epoch_ms=None):
    """Build a valid RTCM 3.2 frame."""
    if epoch_ms is None:
        epoch_ms = int(time.time() * 1000) % 604800000  # GPS week ms
    # Payload: 12-bit msg_type + 20-bit station_id + 30-bit epoch + padding
    type_and_station = struct.pack('>I', (msg_type << 20) | 1234)[:3]  # 12+12 bits
    epoch_bytes = struct.pack('>I', epoch_ms)[:4]
    # Pad to realistic size based on message type
    if msg_type == 1005:
        padding = b'\x00' * 15  # station coord: ~19 bytes total
    elif msg_type in (1004, 1012):
        padding = b'\x00' * 50  # observations: ~55 bytes
    elif msg_type in (1077, 1087, 1097, 1127):
        padding = b'\x00' * 80  # MSM7: ~85 bytes
    else:
        padding = b'\x00' * 30

    payload = type_and_station + epoch_bytes + padding
    length = len(payload)
    header = bytes([0xD3, (length >> 8) & 0x03, length & 0xFF])
    frame_no_crc = header + payload
    crc = crc24q(frame_no_crc)
    crc_bytes = struct.pack('>I', crc)[1:]
    return frame_no_crc + crc_bytes


class NTRIPHandler(socketserver.StreamRequestHandler):
    """Handle one NTRIP client connection."""

    def handle(self):
        client_addr = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[caster] client connected: {client_addr}")

        # Read the HTTP request
        request_lines = []
        while True:
            line = self.rfile.readline()
            if not line or line == b'\r\n':
                break
            request_lines.append(line.decode('latin-1').strip())

        if not request_lines:
            print(f"[caster] empty request from {client_addr}")
            return

        request_line = request_lines[0]
        print(f"[caster] request: {request_line}")

        # Parse headers
        headers = {}
        for line in request_lines[1:]:
            if ':' in line:
                key, val = line.split(':', 1)
                headers[key.strip().lower()] = val.strip()

        # Extract auth info
        username = "unknown"
        if 'authorization' in headers:
            auth = headers['authorization']
            if auth.lower().startswith('basic '):
                import base64
                try:
                    decoded = base64.b64decode(auth[6:]).decode()
                    username = decoded.split(':')[0]
                except:
                    pass
            print(f"[caster] auth: user={username}")

        # Detect NTRIP version
        ntrip_ver = headers.get('ntrip-version', 'Ntrip/1.0')
        print(f"[caster] version: {ntrip_ver}")

        # Send NTRIP v1 response: ICY 200 OK
        # (This is what Kyanos's NTRIP protocol inference looks for)
        response = b"ICY 200 OK\r\n\r\n"
        self.wfile.write(response)
        self.wfile.flush()
        print(f"[caster] sent: ICY 200 OK")

        # Start a thread to read GGA backchannel from client
        gga_received = []
        def read_gga():
            try:
                while True:
                    self.request.settimeout(0.5)
                    data = self.request.recv(4096)
                    if not data:
                        break
                    text = data.decode('latin-1').strip()
                    if text.startswith('$'):
                        gga_received.append(text)
                        print(f"[caster] GGA received: {text[:60]}")
            except:
                pass

        gga_thread = threading.Thread(target=read_gga, daemon=True)
        gga_thread.start()

        # Stream RTCM frames at ~1Hz for 8 seconds
        # Typical NTRIP station sends: 1004 + 1005 + 1077 per epoch
        rtcm_sequence = [1004, 1005, 1077]  # GPS obs + coord + MSM7
        duration = 8  # seconds
        start = time.time()
        frame_count = 0

        try:
            while time.time() - start < duration:
                epoch_ms = int(time.time() * 1000) % 604800000
                for msg_type in rtcm_sequence:
                    frame = make_rtcm_frame(msg_type, epoch_ms)
                    self.wfile.write(frame)
                    frame_count += 1
                self.wfile.flush()
                time.sleep(1.0)
        except (BrokenPipeError, ConnectionResetError):
            print(f"[caster] client disconnected early")

        print(f"[caster] streamed {frame_count} RTCM frames, {len(gga_received)} GGA received")
        print(f"[caster] connection closed: {client_addr}")


class NTRIPCaster(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2101
    max_clients = int(sys.argv[2]) if len(sys.argv) > 2 else 2

    server = NTRIPCaster(("0.0.0.0", port), NTRIPHandler)
    print(f"[caster] NTRIP Caster (socketserver) listening on port {port}")
    print(f"[caster] Will handle {max_clients} client(s) then exit")
    sys.stdout.flush()

    # Handle a fixed number of clients then exit
    for i in range(max_clients):
        server.handle_request()

    server.server_close()
    print("[caster] shutdown")


if __name__ == '__main__':
    main()
