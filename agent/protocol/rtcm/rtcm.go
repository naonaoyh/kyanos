// Package rtcm provides RTCM 3.2 protocol parsing for Kyanos.
// It implements the ProtocolStreamParser interface for capturing and analyzing
// RTCM 3.x frames from GNSS correction data streams.
package rtcm

import (
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"time"
)

// Compile-time interface checks
var _ protocol.ProtocolStreamParser = &RTCMStreamParser{}
var _ protocol.ParsedMessage = &RTCMFrame{}

// RTCMFrame represents a single parsed RTCM 3.x frame.
type RTCMFrame struct {
	protocol.FrameBase
	Preamble      uint8         // Always 0xD3
	Length        uint16        // Payload length (0-1023)
	MessageType   int           // RTCM message type (12-bit, 0-4095)
	Constellation Constellation // Inferred GNSS constellation
	MSMClass      MSMClass      // MSM class if applicable (MSM1-MSM7)
	CRCValid      bool          // Whether CRC-24Q validation passed
	PayloadLen    int           // Actual payload bytes captured
	TotalLen      int           // Total frame length (header + payload + CRC)
	RawBytes      []byte        // Raw frame bytes (for export to .rtcm files)
}

// IsReq returns true. RTCM is a unidirectional push stream,
// we treat all frames as "requests" since there is no req/resp pairing.
func (f *RTCMFrame) IsReq() bool {
	return true
}

// StreamId returns 0. RTCM streams don't have multiplexed streams.
func (f *RTCMFrame) StreamId() protocol.StreamId {
	return 0
}

// FormatToString returns a human-readable representation of the RTCM frame.
func (f *RTCMFrame) FormatToString() string {
	msgName := GetMessageName(f.MessageType)

	result := fmt.Sprintf(
		"RTCM3 Frame: type=%d (%s)\n",
		f.MessageType, msgName,
	)

	if f.Constellation != ConstellationUnknown {
		result += fmt.Sprintf("  Constellation: %s\n", f.Constellation.String())
	}
	if f.MSMClass != MSMUnknown {
		desc := MSMDescription(f.MSMClass)
		result += fmt.Sprintf("  MSM Class:     %s (%s)\n", f.MSMClass.String(), desc)
	}

	result += fmt.Sprintf("  Payload Length: %d bytes\n", f.PayloadLen)
	result += fmt.Sprintf("  Total Length:   %d bytes\n", f.TotalLen)

	crcStatus := "PASS"
	if !f.CRCValid {
		crcStatus = "FAIL"
	}
	result += fmt.Sprintf("  CRC-24Q:       %s", crcStatus)

	return result
}

// FormatToSummaryString returns a concise summary suitable for table display.
func (f *RTCMFrame) FormatToSummaryString() string {
	msgName := GetMessageName(f.MessageType)
	crcMark := "✓"
	if !f.CRCValid {
		crcMark = "✗"
	}

	if f.Constellation != ConstellationUnknown {
		return fmt.Sprintf("[%s] %s len=%d crc=%s",
			f.Constellation.String(), msgName, f.PayloadLen, crcMark)
	}
	return fmt.Sprintf("RTCM %d len=%d crc=%s", f.MessageType, f.PayloadLen, crcMark)
}

// RTCMStreamParser implements ProtocolStreamParser for RTCM 3.x protocol.
type RTCMStreamParser struct{}

// FindBoundary scans the stream buffer for the next valid RTCM frame preamble (0xD3).
// It also validates the reserved bits to reduce false positives.
func (p *RTCMStreamParser) FindBoundary(
	streamBuffer *buffer.StreamBuffer,
	messageType protocol.MessageType,
	startPos int,
) int {
	head := streamBuffer.Head()
	if head == nil {
		return -1
	}
	buf := head.Buffer()
	for i := startPos; i < len(buf)-2; i++ {
		if buf[i] == RTCMPreamble {
			// Validate reserved bits: byte1 high 6 bits must be 0
			if (buf[i+1] & 0xFC) == 0x00 {
				return i
			}
		}
	}
	return -1
}

// ParseStream attempts to parse one RTCM frame from the head of the stream buffer.
// Returns NeedsMoreData if the buffer doesn't contain a complete frame.
// Returns Invalid if the preamble check fails.
// Returns Success with the parsed RTCMFrame on success.
func (p *RTCMStreamParser) ParseStream(
	streamBuffer *buffer.StreamBuffer,
	messageType protocol.MessageType,
) protocol.ParseResult {
	head := streamBuffer.Head()
	if head == nil {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	buf := head.Buffer()

	// Need at least header (3 bytes) to start parsing
	if len(buf) < RTCMHeaderLen {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	// Check preamble
	if buf[0] != RTCMPreamble {
		return protocol.ParseResult{ParseState: protocol.Invalid}
	}

	// Validate reserved bits (high 6 bits of byte 1 must be 0)
	if (buf[1] & 0xFC) != 0x00 {
		return protocol.ParseResult{ParseState: protocol.Invalid}
	}

	// Extract payload length (10 bits: low 2 bits of byte1 + byte2)
	payloadLen := uint16(buf[1]&0x03)<<8 | uint16(buf[2])

	// Total frame length: header(3) + payload + CRC(3)
	totalFrameLen := int(payloadLen) + RTCMHeaderLen + RTCMCRCLen

	// Sanity check on payload length
	if int(payloadLen) > RTCMMaxPayload {
		return protocol.ParseResult{ParseState: protocol.Invalid}
	}

	// Wait for complete frame
	if len(buf) < totalFrameLen {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	// Extract message type from payload (first 12 bits of payload)
	var msgType int
	if payloadLen >= 2 {
		msgType = int(buf[3])<<4 | int(buf[4]>>4)
		msgType &= 0x0FFF // Mask to 12 bits
	}

	// Verify CRC-24Q
	frameData := buf[:totalFrameLen]
	crcValid := VerifyCRC24Q(frameData)

	// Get timestamp and sequence from stream buffer
	seq := head.LeftBoundary()
	ts, ok := streamBuffer.FindTimestampBySeq(seq)
	if !ok {
		// After RemovePrefix shifts the buffer position, the old timestamp
		// entries may have been cleaned up. Use a fallback: the current time
		// as a reasonable approximation for the frame timestamp.
		ts = uint64(time.Now().UnixNano())
	}

	// Build the RTCMFrame
	frame := &RTCMFrame{
		FrameBase:     protocol.NewFrameBase(ts, totalFrameLen, seq),
		Preamble:      RTCMPreamble,
		Length:        payloadLen,
		MessageType:   msgType,
		Constellation: InferConstellation(msgType),
		MSMClass:      InferMSMClass(msgType),
		CRCValid:      crcValid,
		PayloadLen:    int(payloadLen),
		TotalLen:      totalFrameLen,
		RawBytes:      append([]byte(nil), frameData...),
	}

	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{frame},
		ReadBytes:      totalFrameLen,
	}
}

// Match pairs RTCM frames into Records.
// RTCM is a unidirectional push stream with no request/response pairing.
// Each frame is returned as an independent Record with only the Request field set.
func (p *RTCMStreamParser) Match(
	reqStreams map[protocol.StreamId]*protocol.ParsedMessageQueue,
	respStreams map[protocol.StreamId]*protocol.ParsedMessageQueue,
) []protocol.Record {
	records := make([]protocol.Record, 0)

	if reqStream, ok := reqStreams[0]; ok {
		for _, msg := range *reqStream {
			records = append(records, protocol.Record{
				Req: msg,
			})
		}
	}

	return records
}

// init registers the RTCM parser in the global ParsersMap.
func init() {
	protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolRTCM] = func() protocol.ProtocolStreamParser {
		return &RTCMStreamParser{}
	}
}
