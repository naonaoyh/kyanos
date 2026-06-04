"""HTTP-based NTRIP caster using Python's http.server framework.

This uses the same socketserver/HTTPServer architecture as python3 -m http.server
which Kyanos can capture. It responds to GET requests with RTCM frames.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import struct, time, sys

def crc24q(data):
    crc = 0
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF

def make_rtcm_frame(msg_type):
    type_bytes = struct.pack(">H", (msg_type << 4) & 0xFFF0)
    payload = type_bytes + struct.pack(">I", int(time.time()*1000) & 0xFFFFFFFF) + b"\x00"*28
    length = len(payload)
    header = bytes([0xD3, (length >> 8) & 0x03, length & 0xFF])
    frame = header + payload
    crc = crc24q(frame)
    return frame + struct.pack(">I", crc)[1:]

class NTRIPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Send ICY-style response (NTRIP v1) but as valid HTTP
        self.send_response(200, "OK")
        self.send_header("Server", "NTRIP FakeCaster/1.0")
        self.send_header("Content-Type", "gnss/data")
        self.end_headers()

        # Read GGA from client (if any - sent as follow-up data)
        # Note: in real NTRIP, GGA is sent on the same connection after response

        # Stream RTCM frames with delays
        for msg_type in [1004, 1005, 1077, 1004, 1077, 1004, 1005, 1077, 1004, 1077]:
            try:
                self.wfile.write(make_rtcm_frame(msg_type))
                self.wfile.flush()
                time.sleep(0.3)
            except BrokenPipeError:
                return

    def log_message(self, format, *args):
        print(f"[caster] {args[0]}")

port = int(sys.argv[1]) if len(sys.argv) > 1 else 2113
print(f"[caster] Starting HTTP-based NTRIP caster on port {port}")
srv = HTTPServer(("127.0.0.1", port), NTRIPHandler)
srv.timeout = 30
# Handle 2 requests (for reconnect test)
srv.handle_request()
srv.handle_request()
print("[caster] Done")
