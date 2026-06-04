package export

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// PCAP-NG Block Types
const (
	blockTypeSHB = 0x0A0D0D0A // Section Header Block
	blockTypeIDB = 0x00000001 // Interface Description Block
	blockTypeNRB = 0x00000004 // Name Resolution Block
	blockTypeEPB = 0x00000006 // Enhanced Packet Block
)

// tcpState tracks sequence and acknowledgment numbers for a virtual TCP stream.
type tcpState struct {
	clientSeq  uint32
	serverSeq  uint32
	handshaked bool
}

// PcapNgWriter handles serialization of packet data into the Wireshark-compatible PCAP-NG format.
// It supports injecting Name Resolution Blocks (NRBs) to resolve IPs to Pod names,
// and Enhanced Packet Blocks (EPBs) with packet comments (e.g. usernames or diagnostics).
type PcapNgWriter struct {
	mu         sync.Mutex
	out        io.Writer
	ipToName   map[string]string // String IP -> Pod Name
	tcpStreams map[string]*tcpState
}

// NewPcapNgWriter creates a new writer and writes the global PCAP-NG headers (SHB, IDB, NRB).
func NewPcapNgWriter(out io.Writer, ipToName map[string]string) (*PcapNgWriter, error) {
	w := &PcapNgWriter{
		out:        out,
		ipToName:   ipToName,
		tcpStreams: make(map[string]*tcpState),
	}

	if err := w.writeGlobalHeaders(); err != nil {
		return nil, err
	}

	return w, nil
}

// Close closes the underlying writer if it implements io.Closer.
func (w *PcapNgWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if closer, ok := w.out.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// GetGlobalHeaderBytes serializes SHB, IDB and NRB into a byte slice.
// This is used by RotateWriter to prefix newly rotated part files.
func GetGlobalHeaderBytes(ipToName map[string]string) []byte {
	var buf bytes.Buffer

	// 1. Write Section Header Block
	shbBody := make([]byte, 16)
	binary.LittleEndian.PutUint32(shbBody[0:4], 0x1A2B3C4D) // Byte-Order Magic (Little Endian)
	binary.LittleEndian.PutUint16(shbBody[4:6], 1)          // Version Major = 1
	binary.LittleEndian.PutUint16(shbBody[6:8], 0)          // Version Minor = 0
	binary.LittleEndian.PutUint64(shbBody[8:16], 0xFFFFFFFFFFFFFFFF) // Section Length = -1 (undefined)
	_ = writeBlockToBuf(&buf, blockTypeSHB, shbBody)

	// 2. Write Interface Description Block
	idbBody := make([]byte, 8)
	binary.LittleEndian.PutUint16(idbBody[0:2], 1)      // LinkType = 1 (Ethernet)
	binary.LittleEndian.PutUint16(idbBody[2:4], 0)      // Reserved
	binary.LittleEndian.PutUint32(idbBody[4:8], 65535)  // SnapLen
	_ = writeBlockToBuf(&buf, blockTypeIDB, idbBody)

	// 3. Write Name Resolution Block (NRB) if mappings exist
	if len(ipToName) > 0 {
		var nrbBuf bytes.Buffer
		for ipStr, name := range ipToName {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue // Skip IPv6 for simplicity in NRB
			}
			nameBytes := []byte(name)
			recordLen := uint16(4 + len(nameBytes))

			binary.Write(&nrbBuf, binary.LittleEndian, uint16(1)) // Type = 1 (IPv4 record)
			binary.Write(&nrbBuf, binary.LittleEndian, recordLen)
			nrbBuf.Write(ip4)
			nrbBuf.Write(nameBytes)

			// Record padding to 32-bit boundary
			pad := (4 - (recordLen % 4)) % 4
			if pad > 0 {
				nrbBuf.Write(make([]byte, pad))
			}
		}
		// End of records
		binary.Write(&nrbBuf, binary.LittleEndian, uint16(0)) // End type = 0
		binary.Write(&nrbBuf, binary.LittleEndian, uint16(0)) // End length = 0

		_ = writeBlockToBuf(&buf, blockTypeNRB, nrbBuf.Bytes())
	}

	return buf.Bytes()
}

func (w *PcapNgWriter) writeGlobalHeaders() error {
	headers := GetGlobalHeaderBytes(w.ipToName)
	_, err := w.out.Write(headers)
	return err
}

// WritePacket writes a payload packet as a synthesized TCP segment inside an EPB.
func (w *PcapNgWriter) WritePacket(ts time.Time, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte, isReq bool, comment string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Normalize IPs to IPv4. If not IPv4, map to 127.0.0.1 to maintain format safety
	sIP := srcIP.To4()
	if sIP == nil {
		sIP = net.ParseIP("127.0.0.1").To4()
	}
	dIP := dstIP.To4()
	if dIP == nil {
		dIP = net.ParseIP("127.0.0.1").To4()
	}

	// Compute TCP stream key
	var streamKey string
	if isReq {
		streamKey = fmt.Sprintf("%s:%d->%s:%d", sIP.String(), srcPort, dIP.String(), dstPort)
	} else {
		streamKey = fmt.Sprintf("%s:%d->%s:%d", dIP.String(), dstPort, sIP.String(), srcPort)
	}

	state, exists := w.tcpStreams[streamKey]
	if !exists {
		state = &tcpState{
			clientSeq: 1000,
			serverSeq: 2000,
		}
		w.tcpStreams[streamKey] = state
	}

	// Inject 3-way handshake on first packet for clean TCP stream assembly in Wireshark
	if !state.handshaked {
		cIP, srvIP := sIP, dIP
		cPort, srvPort := srcPort, dstPort
		if !isReq {
			cIP, srvIP = dIP, sIP
			cPort, srvPort = dstPort, srcPort
		}

		// Packet 1: Client -> Server [SYN], Seq=1000, Ack=0
		pkt1 := w.synthesizeTCPPacket(cIP, srvIP, cPort, srvPort, 1000, 0, 0x02, nil)
		if err := w.writeEPB(ts, pkt1, ""); err != nil {
			return err
		}
		// Packet 2: Server -> Client [SYN, ACK], Seq=2000, Ack=1001
		pkt2 := w.synthesizeTCPPacket(srvIP, cIP, srvPort, cPort, 2000, 1001, 0x12, nil)
		if err := w.writeEPB(ts, pkt2, ""); err != nil {
			return err
		}
		// Packet 3: Client -> Server [ACK], Seq=1001, Ack=2001
		pkt3 := w.synthesizeTCPPacket(cIP, srvIP, cPort, srvPort, 1001, 2001, 0x10, nil)
		if err := w.writeEPB(ts, pkt3, ""); err != nil {
			return err
		}

		state.clientSeq = 1001
		state.serverSeq = 2001
		state.handshaked = true
	}

	// Set Seq/Ack based on direction
	var seq, ack uint32
	var flags uint8 = 0x18 // PSH | ACK
	if isReq {
		seq = state.clientSeq
		ack = state.serverSeq
		state.clientSeq += uint32(len(payload))
	} else {
		seq = state.serverSeq
		ack = state.clientSeq
		state.serverSeq += uint32(len(payload))
	}

	pkt := w.synthesizeTCPPacket(sIP, dIP, srcPort, dstPort, seq, ack, flags, payload)
	return w.writeEPB(ts, pkt, comment)
}

// WriteFIN injects FIN-ACK sequence to cleanly terminate the session in Wireshark
func (w *PcapNgWriter) WriteFIN(ts time.Time, clientIP, serverIP net.IP, clientPort, serverPort uint16, isClientInitiated bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	cIP := clientIP.To4()
	if cIP == nil {
		cIP = net.ParseIP("127.0.0.1").To4()
	}
	sIP := serverIP.To4()
	if sIP == nil {
		sIP = net.ParseIP("127.0.0.1").To4()
	}

	streamKey := fmt.Sprintf("%s:%d->%s:%d", cIP.String(), clientPort, sIP.String(), serverPort)
	state, exists := w.tcpStreams[streamKey]
	if !exists || !state.handshaked {
		return nil
	}

	var firstIP, secondIP net.IP
	var firstPort, secondPort uint16
	var firstSeq, firstAck *uint32
	var secondSeq *uint32

	if isClientInitiated {
		firstIP, secondIP = cIP, sIP
		firstPort, secondPort = clientPort, serverPort
		firstSeq, firstAck = &state.clientSeq, &state.serverSeq
		secondSeq = &state.serverSeq
	} else {
		firstIP, secondIP = sIP, cIP
		firstPort, secondPort = serverPort, clientPort
		firstSeq, firstAck = &state.serverSeq, &state.clientSeq
		secondSeq = &state.clientSeq
	}

	// 1. FIN-ACK from first side
	pkt1 := w.synthesizeTCPPacket(firstIP, secondIP, firstPort, secondPort, *firstSeq, *firstAck, 0x11, nil) // FIN | ACK
	if err := w.writeEPB(ts, pkt1, "Session Termination Initiated"); err != nil {
		return err
	}
	*firstSeq++

	// 2. ACK from second side
	pkt2 := w.synthesizeTCPPacket(secondIP, firstIP, secondPort, firstPort, *secondSeq, *firstAck, 0x10, nil) // ACK
	if err := w.writeEPB(ts, pkt2, ""); err != nil {
		return err
	}

	// 3. FIN-ACK from second side
	pkt3 := w.synthesizeTCPPacket(secondIP, firstIP, secondPort, firstPort, *secondSeq, *firstAck, 0x11, nil) // FIN | ACK
	if err := w.writeEPB(ts, pkt3, ""); err != nil {
		return err
	}
	*secondSeq++

	// 4. Final ACK from first side
	pkt4 := w.synthesizeTCPPacket(firstIP, secondIP, firstPort, secondPort, *firstSeq, *secondSeq, 0x10, nil) // ACK
	_ = w.writeEPB(ts, pkt4, "Session Closed")

	delete(w.tcpStreams, streamKey)
	return nil
}

func (w *PcapNgWriter) writeEPB(ts time.Time, packetData []byte, comment string) error {
	micros := uint64(ts.UnixNano() / 1000)
	tsHigh := uint32(micros >> 32)
	tsLow := uint32(micros & 0xFFFFFFFF)

	var epbBody bytes.Buffer
	binary.Write(&epbBody, binary.LittleEndian, uint32(0)) // Interface ID = 0
	binary.Write(&epbBody, binary.LittleEndian, tsHigh)
	binary.Write(&epbBody, binary.LittleEndian, tsLow)
	binary.Write(&epbBody, binary.LittleEndian, uint32(len(packetData)))
	binary.Write(&epbBody, binary.LittleEndian, uint32(len(packetData)))
	epbBody.Write(packetData)

	// Add options if comment is provided
	if comment != "" {
		commentBytes := []byte(comment)
		binary.Write(&epbBody, binary.LittleEndian, uint16(1)) // Option Code = 1 (opt_comment)
		binary.Write(&epbBody, binary.LittleEndian, uint16(len(commentBytes)))
		epbBody.Write(commentBytes)

		// Option padding to 32-bit boundary
		pad := (4 - (len(commentBytes) % 4)) % 4
		if pad > 0 {
			epbBody.Write(make([]byte, pad))
		}

		// Option list terminator
		binary.Write(&epbBody, binary.LittleEndian, uint16(0))
		binary.Write(&epbBody, binary.LittleEndian, uint16(0))
	}

	return writeBlock(w.out, blockTypeEPB, epbBody.Bytes())
}

// synthesizeTCPPacket constructs a raw Ethernet+IPv4+TCP frame byte stream
func (w *PcapNgWriter) synthesizeTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	ethLen := 14
	ipLen := 20
	tcpLen := 20
	totalLen := ethLen + ipLen + tcpLen + len(payload)
	pkt := make([]byte, totalLen)

	// 1. Ethernet Header (MAC destination, MAC source, EtherType=0x0800)
	copy(pkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // Dst MAC
	copy(pkt[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}) // Src MAC
	pkt[12] = 0x08                                              // EtherType High
	pkt[13] = 0x00                                              // EtherType Low

	// 2. IPv4 Header
	pkt[14] = 0x45 // Version=4, IHL=5 (20 bytes)
	pkt[15] = 0x00 // TOS
	binary.BigEndian.PutUint16(pkt[16:18], uint16(ipLen+tcpLen+len(payload))) // Total Length
	binary.BigEndian.PutUint16(pkt[18:20], 0x1234)                           // Identification
	binary.BigEndian.PutUint16(pkt[20:22], 0x4000)                           // Flags (Don't Fragment)
	pkt[22] = 64                                                             // TTL = 64
	pkt[23] = 6                                                              // Protocol = 6 (TCP)
	// Checksum (offset 24:26) is left zero during checksum calculation
	copy(pkt[26:30], srcIP.To4())
	copy(pkt[30:34], dstIP.To4())

	// Compute IP checksum
	ipChecksum := checksum(pkt[14:34])
	binary.BigEndian.PutUint16(pkt[24:26], ipChecksum)

	// 3. TCP Header
	binary.BigEndian.PutUint16(pkt[34:36], srcPort)
	binary.BigEndian.PutUint16(pkt[36:38], dstPort)
	binary.BigEndian.PutUint32(pkt[38:42], seq)
	binary.BigEndian.PutUint32(pkt[42:46], ack)
	pkt[46] = 0x50 // Data Offset = 5 (20 bytes TCP header)
	pkt[47] = flags
	binary.BigEndian.PutUint16(pkt[48:50], 65535) // Window Size
	// Checksum (offset 50:52) is left zero during calculation
	// Urgent Pointer (offset 52:54) is 0

	// 4. Payload
	if len(payload) > 0 {
		copy(pkt[54:], payload)
	}

	// Compute TCP Checksum including IPv4 pseudo-header
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6 // Protocol TCP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(tcpLen+len(payload)))

	tcpChecksumBuf := make([]byte, len(pseudoHeader)+tcpLen+len(payload))
	copy(tcpChecksumBuf[0:12], pseudoHeader)
	copy(tcpChecksumBuf[12:32], pkt[34:54]) // TCP Header with checksum field=0
	if len(payload) > 0 {
		copy(tcpChecksumBuf[32:], payload)
	}

	tcpChecksum := checksum(tcpChecksumBuf)
	binary.BigEndian.PutUint16(pkt[50:52], tcpChecksum)

	return pkt
}

func writeBlockToBuf(buf *bytes.Buffer, blockType uint32, body []byte) error {
	return writeBlock(buf, blockType, body)
}

func writeBlock(w io.Writer, blockType uint32, body []byte) error {
	bodyLen := len(body)
	paddingLen := (4 - (bodyLen % 4)) % 4
	totalLength := uint32(12 + bodyLen + paddingLen)

	if err := binary.Write(w, binary.LittleEndian, blockType); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, totalLength); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	if paddingLen > 0 {
		if _, err := w.Write(make([]byte, paddingLen)); err != nil {
			return err
		}
	}
	if err := binary.Write(w, binary.LittleEndian, totalLength); err != nil {
		return err
	}
	return nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}
