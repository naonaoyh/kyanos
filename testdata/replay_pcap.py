import struct
import socket
import time
import sys
import threading
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="NTRIP PCAP Replay Tool")
    parser.add_argument("--pcap", type=str, default="testdata/testdata-small.pcap", help="Path to the PCAP file")
    parser.add_argument("--port", type=int, default=25322, help="Local TCP port to replay on")
    parser.add_argument("--inject-handshake", type=str, choices=["GET", "SOURCE", "NONE"], default="GET",
                        help="Inject standard NTRIP handshake before replaying payload")
    parser.add_argument("--speed", type=float, default=1.0, help="Replay speed multiplier (e.g. 1.0 = normal, 20.0 = fast)")
    parser.add_argument("--repeat", action="store_true", help="Loop replay indefinitely (for manual TUI/WebUI testing)")
    parser.add_argument("--duration", type=float, default=0, help="Total replay duration in seconds (0 = play once, ignored if --repeat)")
    return parser.parse_args()

def read_pcap(filepath):
    """
    Parses Ethernet -> IPv4 -> TCP headers from a PCAP file.
    Returns a list of application payloads: {
        'ts': float,
        'src_ip': str, 'src_port': int,
        'dst_ip': str, 'dst_port': int,
        'payload': bytes
    }
    """
    packets = []
    try:
        f = open(filepath, 'rb')
    except Exception as e:
        print(f"[replay] Error opening PCAP file: {e}")
        sys.exit(1)
        
    global_header = f.read(24)
    if len(global_header) < 24:
        print("[replay] Invalid PCAP global header")
        sys.exit(1)
        
    magic, major, minor, tz, sig, snaplen, linktype = struct.unpack('<IHHIIII', global_header)
    
    # Check Magic & Endianness / Nanosecond resolution
    # 0xa1b2c3d4: microsecond, little-endian
    # 0xd4c3b2a1: microsecond, big-endian
    # 0xa1b23c4d: nanosecond, little-endian
    # 0x4d3cb2a1: nanosecond, big-endian
    if magic in (0xa1b2c3d4, 0xa1b23c4d):
        fmt_char = '<'
    elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
        fmt_char = '>'
    else:
        print(f"[replay] Unsupported PCAP magic: {hex(magic)}")
        sys.exit(1)
        
    is_nanosecond = magic in (0xa1b23c4d, 0x4d3cb2a1)
    time_div = 1000000000.0 if is_nanosecond else 1000000.0
    
    if linktype != 1:
        print(f"[replay] Unsupported LinkType: {linktype}. Only Ethernet (LinkType=1) is supported.")
        sys.exit(1)
        
    packet_count = 0
    while True:
        pkt_hdr = f.read(16)
        if not pkt_hdr or len(pkt_hdr) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{fmt_char}IIII', pkt_hdr)
        pkt_data = f.read(incl_len)
        packet_count += 1
        
        # Ethernet Header (14 bytes)
        if len(pkt_data) < 14:
            continue
        proto = struct.unpack('>H', pkt_data[12:14])[0]
        ip_offset = 14
        if proto == 0x8100: # VLAN tag
            if len(pkt_data) < 18:
                continue
            proto = struct.unpack('>H', pkt_data[16:18])[0]
            ip_offset = 18
            
        if proto != 0x0800: # IPv4
            continue
            
        # IP Header
        if len(pkt_data) < ip_offset + 20:
            continue
        ver_ihl = pkt_data[ip_offset]
        ip_header_len = (ver_ihl & 0x0f) * 4
        ip_proto = pkt_data[ip_offset + 9]
        if ip_proto != 6: # TCP only
            continue
            
        src_ip = '.'.join(map(str, pkt_data[ip_offset+12 : ip_offset+16]))
        dst_ip = '.'.join(map(str, pkt_data[ip_offset+16 : ip_offset+20]))
        
        # TCP Header
        tcp_offset = ip_offset + ip_header_len
        if len(pkt_data) < tcp_offset + 20:
            continue
        src_port, dst_port = struct.unpack('>HH', pkt_data[tcp_offset : tcp_offset+4])
        data_offset = (pkt_data[tcp_offset + 12] >> 4) * 4
        payload_offset = tcp_offset + data_offset
        
        payload = pkt_data[payload_offset:]
        ts = ts_sec + ts_usec / time_div
        
        if len(payload) > 0:
            packets.append({
                'ts': ts,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'payload': payload
            })
            
    f.close()
    print(f"[replay] Parsed {packet_count} packets. Found {len(packets)} TCP packets with application payloads.")
    return packets

def run_server(port, expected_clients, accepted_event, server_mapping, server_socks_list):
    """
    TCP Server that acts as the Caster.
    Listens on the local port and accepts client connections.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(expected_clients + 5)
    print(f"[replay-server] Listening on port {port}")
    
    count = 0
    while count < expected_clients:
        try:
            conn, addr = srv.accept()
            client_port = addr[1]
            server_mapping[client_port] = conn
            server_socks_list.append(conn)
            count += 1
            print(f"[replay-server] Accepted connection {count}/{expected_clients} from {addr}")
        except Exception as e:
            print(f"[replay-server] Error accepting: {e}")
            break
            
    srv.close()
    accepted_event.set()

def main():
    args = parse_args()
    print(f"[replay] Starting replay of {args.pcap} on local port {args.port} at {args.speed}x speed")
    
    # 1. Read and parse packets
    packets = read_pcap(args.pcap)
    if not packets:
        print("[replay] No data packets found in PCAP.")
        return
        
    # 2. Identify unique client-side TCP endpoints.
    # In this PCAP, the Caster Server runs on 10.144.140.64:8003.
    # Thus, any packet with src_port != 8003 is a client endpoint.
    unique_clients = set()
    for pkt in packets:
        if pkt['src_port'] != 8003:
            unique_clients.add((pkt['src_ip'], pkt['src_port']))
        elif pkt['dst_port'] != 8003:
            unique_clients.add((pkt['dst_ip'], pkt['dst_port']))
            
    num_clients = len(unique_clients)
    print(f"[replay] Unique NTRIP clients identified in PCAP: {num_clients}")
    
    # 3. Start the TCP Server
    accepted_event = threading.Event()
    server_mapping = {}  # local_port -> server_side_socket
    server_socks_list = []
    server_thread = threading.Thread(target=run_server, args=(args.port, num_clients, accepted_event, server_mapping, server_socks_list))
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.5)  # Let server bind
    
    # 4. Connect the Client Sockets
    client_mapping = {}  # original_client_key -> client_socket
    local_ports_to_client_key = {}
    client_socks_list = []
    
    for client_key in unique_clients:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', args.port))
            local_ip, local_port = sock.getsockname()
            client_mapping[client_key] = sock
            local_ports_to_client_key[local_port] = client_key
            client_socks_list.append(sock)
            print(f"[replay-client] Client connected. Original {client_key} mapped to localhost local_port {local_port}")
        except Exception as e:
            print(f"[replay-client] Error connecting to server: {e}")
            sys.exit(1)
            
    # Wait for server to accept all connections
    accepted_event.wait(timeout=10)
    
    # Establish final server-side mapping: original_client_key -> server_side_socket
    server_client_mapping = {}
    for local_port, conn in server_mapping.items():
        if local_port in local_ports_to_client_key:
            client_key = local_ports_to_client_key[local_port]
            server_client_mapping[client_key] = conn
            
    print(f"[replay] Connected mapping successfully established. Ready to replay.")
    time.sleep(1.0) # Let connection tracking settle in eBPF
    
    # 5. Inject Handshakes if requested
    if args.inject_handshake != "NONE":
        print(f"[replay] Injecting handshake: {args.inject_handshake}")
        for client_key, c_sock in client_mapping.items():
            s_sock = server_client_mapping[client_key]
            
            if args.inject_handshake == "GET":
                req = (
                    "GET /RTCM3_TEST HTTP/1.1\r\n"
                    "User-Agent: NTRIP KyanosPCAPReplay/1.0\r\n"
                    "Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3M=\r\n" # testuser:testpass
                    "Ntrip-Version: Ntrip/2.0\r\n"
                    "\r\n"
                )
                resp = "ICY 200 OK\r\n\r\n"
                
                # Send HTTP Request
                c_sock.sendall(req.encode())
                time.sleep(0.1)
                s_sock.recv(1024) # Consume on server side
                
                # Send ICY Response
                s_sock.sendall(resp.encode())
                time.sleep(0.1)
                c_sock.recv(1024) # Consume on client side
                
            elif args.inject_handshake == "SOURCE":
                req = (
                    "SOURCE testpass /RTCM3_TEST\r\n"
                    "Source-Agent: NTRIP SourceKyanos/1.0\r\n"
                    "\r\n"
                )
                resp = "ICY 200 OK\r\n\r\n"
                
                # Send SOURCE Request
                c_sock.sendall(req.encode())
                time.sleep(0.1)
                s_sock.recv(1024) # Consume on server side
                
                # Send ICY Response
                s_sock.sendall(resp.encode())
                time.sleep(0.1)
                c_sock.recv(1024) # Consume on client side
                
        print("[replay] Handshake injection completed.")
        time.sleep(0.5)
        
    # 6. Replay Packets
    print(f"[replay] Playback starting now at {args.speed}x speed (repeat={args.repeat}, duration={args.duration}s)...")
    first_ts = packets[0]['ts']
    pcap_span = (packets[-1]['ts'] - packets[0]['ts']) / args.speed
    global_start = time.time()
    loop_count = 0

    while True:
        loop_count += 1
        loop_start = time.time()
        gga_count = 0
        rtcm_count = 0
        other_count = 0
        total_bytes = 0

        if loop_count > 1:
            print(f"[replay] Starting loop #{loop_count}...", flush=True)
            # Re-inject handshake on each loop to simulate reconnection
            if args.inject_handshake != "NONE":
                for client_key, c_sock in client_mapping.items():
                    s_sock = server_client_mapping[client_key]
                    if args.inject_handshake == "GET":
                        req = (
                            "GET /RTCM3_TEST HTTP/1.1\r\n"
                            "User-Agent: NTRIP KyanosPCAPReplay/1.0\r\n"
                            "Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3M=\r\n"
                            "Ntrip-Version: Ntrip/2.0\r\n"
                            "\r\n"
                        )
                        resp = "ICY 200 OK\r\n\r\n"
                        try:
                            c_sock.sendall(req.encode())
                            time.sleep(0.05)
                            s_sock.recv(1024)
                            s_sock.sendall(resp.encode())
                            time.sleep(0.05)
                            c_sock.recv(1024)
                        except:
                            pass

        last_report_time = loop_start
        report_interval = 1.0

        for i, pkt in enumerate(packets):
            # Check duration limit
            if args.duration > 0 and (time.time() - global_start) >= args.duration:
                print(f"[replay] Duration limit ({args.duration}s) reached. Stopping.", flush=True)
                break

            # Calculate absolute time target to emit
            elapsed_pcap = (pkt['ts'] - first_ts) / args.speed
            elapsed_real = time.time() - loop_start

            sleep_time = elapsed_pcap - elapsed_real
            if sleep_time > 0:
                time.sleep(sleep_time)

            payload = pkt['payload']
            src_port = pkt['src_port']
            dst_port = pkt['dst_port']

            # Analyze packet type
            if payload.startswith(b'$'):
                gga_count += 1
            elif len(payload) >= 3 and payload[0] == 0xD3 and (payload[1] & 0xFC) == 0:
                rtcm_count += 1
            else:
                other_count += 1

            total_bytes += len(payload)

            # Periodically report emission for continuous output check
            now = time.time()
            if now - last_report_time >= report_interval:
                print(f"[replay-progress] Loop #{loop_count} {now - global_start:.1f}s, sent: {i+1}/{len(packets)} packets (GGA={gga_count}, RTCM={rtcm_count}, Bytes={total_bytes})", flush=True)
                last_report_time = now

            # Identify the client key
            if src_port != 8003:
                client_key = (pkt['src_ip'], pkt['src_port'])
                is_client_sending = True
            else:
                client_key = (pkt['dst_ip'], pkt['dst_port'])
                is_client_sending = False

            if client_key not in client_mapping:
                continue

            c_sock = client_mapping[client_key]
            s_sock = server_client_mapping[client_key]

            # Direction: client-originating data goes through client socket,
            # server-originating data goes through server socket.
            try:
                t0_send = time.time()
                if is_client_sending:
                    c_sock.sendall(payload)
                else:
                    s_sock.sendall(payload)
                    c_sock.sendall(payload)
                send_duration_ms = (time.time() - t0_send) * 1000.0
                if send_duration_ms > 50.0:
                    print(f"[WARN] Socket send blocked for {send_duration_ms:.1f} ms on packet {i}!", flush=True)
            except Exception as e:
                print(f"[replay] Socket send error on packet {i}: {e}", flush=True)
                break
        else:
            # Loop completed normally (no break)
            duration = time.time() - loop_start
            print(f"[replay] Loop #{loop_count} completed: GGA={gga_count}, RTCM={rtcm_count}, Duration={duration:.2f}s", flush=True)

            if not args.repeat:
                # Single play mode — done
                break
            # Repeat mode — brief pause then loop again
            time.sleep(0.5)
            continue

        # Break from inner loop (duration limit or error)
        break

    total_duration = time.time() - global_start
    print(f"[replay-summary] Total loops={loop_count}, Total Duration={total_duration:.2f}s", flush=True)
    
    # 7. Cleanup Sockets
    time.sleep(1.0)
    for s in client_socks_list + server_socks_list:
        try:
            s.close()
        except:
            pass
    print("[replay] All sockets closed. Replay tools exit.")

if __name__ == "__main__":
    main()
