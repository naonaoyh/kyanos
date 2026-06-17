// Package ntrip provides NTRIP v1/v2 protocol parsing for Kyanos.
// NTRIP (Networked Transport of RTCM via Internet Protocol) streams GNSS
// correction data over HTTP. This parser handles the full session lifecycle:
//   - Phase 1: HTTP-like handshake (request/response with NTRIP-specific extensions)
//   - Phase 2: Binary RTCM 3.x data stream (server→client)
//   - Phase 2b: NMEA GGA backchannel (client→server, for VRS positioning)
//
// NTRIP v1 uses non-standard HTTP with ICY/SOURCETABLE responses and the SOURCE
// method. NTRIP v2 is standard HTTP/1.1 with a "Ntrip-Version: Ntrip/2.0" header.
package ntrip

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/rtcm"
	"kyanos/bpf"
	"net/textproto"
	"strconv"
	"strings"
)

// Compile-time interface checks
var _ protocol.ProtocolStreamParser = &NTRIPStreamParser{}
var _ protocol.ParsedMessage = &NTRIPRequest{}
var _ protocol.ParsedMessage = &NTRIPResponse{}
var _ protocol.ParsedMessage = &NTRIPRTCMFrame{}
var _ protocol.ParsedMessage = &NTRIPNMEASentence{}

// ==========================================================================
// Parsed message types
// ==========================================================================

// NTRIPRequest represents a parsed NTRIP client request.
type NTRIPRequest struct {
	protocol.FrameBase
	Method      string           // GET, POST, SOURCE
	Path        string           // Request path (mountpoint)
	Version     NTRIPVersion     // Detected NTRIP version
	SessionType NTRIPSessionType // DataStream, SourcePush, Sourcetable
	MountPoint  string           // Extracted mountpoint name
	HasAuth     bool             // Whether Authorization header is present
	Username    string           // Extracted username (from Basic auth or SOURCE method)
	Password    string           // Extracted password (from Basic auth or SOURCE method)
	UserAgent   string           // Client User-Agent string
	ContentType string           // Content-Type header (v2 POST may carry gnss/data)
	// ForwardedFor is the raw X-Forwarded-For header value (may be a
	// comma-separated client chain). Populated unconditionally so the session
	// tracker can resolve the real client IP behind a load balancer (CLB/LB).
	// Empty when the header is absent. See agent/session resolveRealClientIP.
	ForwardedFor string
	// XRealIP is the raw X-Real-IP header value, an alternative single-value
	// real-client-IP signal some LBs inject. Empty when absent.
	XRealIP    string
	ClientIP   string
	ClientPort uint16
	ConnKey    string
}

func (r *NTRIPRequest) IsReq() bool                 { return true }
func (r *NTRIPRequest) StreamId() protocol.StreamId { return 0 }

func (r *NTRIPRequest) FormatToString() string {
	result := fmt.Sprintf("NTRIP Request: %s %s\n", r.Method, r.Path)
	result += fmt.Sprintf("  Version:      %s\n", r.Version)
	result += fmt.Sprintf("  Session Type: %s\n", r.SessionType)
	if r.MountPoint != "" && r.MountPoint != "/" {
		result += fmt.Sprintf("  Mountpoint:   %s\n", r.MountPoint)
	}
	result += fmt.Sprintf("  Auth:         %v", r.HasAuth)
	if r.Username != "" {
		result += fmt.Sprintf("\n  Username:     %s", r.Username)
	}
	if r.Password != "" {
		result += fmt.Sprintf("\n  Password:     %s", r.Password)
	}
	if r.UserAgent != "" {
		result += fmt.Sprintf("\n  User-Agent:   %s", r.UserAgent)
	}
	if r.ContentType != "" {
		result += fmt.Sprintf("\n  Content-Type: %s", r.ContentType)
	}
	if r.ForwardedFor != "" {
		result += fmt.Sprintf("\n  X-Forwarded-For: %s", r.ForwardedFor)
	}
	if r.XRealIP != "" {
		result += fmt.Sprintf("\n  X-Real-IP: %s", r.XRealIP)
	}
	return result
}

func (r *NTRIPRequest) FormatToSummaryString() string {
	switch r.SessionType {
	case SessionTypeSourcetable:
		return fmt.Sprintf("NTRIP %s / (sourcetable) [%s]", r.Method, r.Version)
	case SessionTypeSourcePush:
		return fmt.Sprintf("NTRIP SOURCE %s [%s]", r.MountPoint, r.Version)
	default:
		return fmt.Sprintf("NTRIP %s %s [%s]", r.Method, r.MountPoint, r.Version)
	}
}

// NTRIPResponse represents a parsed NTRIP server response.
type NTRIPResponse struct {
	protocol.FrameBase
	Version        NTRIPVersion     // Detected NTRIP version
	SessionType    NTRIPSessionType // DataStream, Sourcetable
	StatusCode     int              // HTTP status code (200, 401, etc.)
	StatusLine     string           // Raw status line (e.g. "ICY 200 OK")
	IsICY          bool             // Whether response used ICY status line
	ContentType    string           // Content-Type header value
	HasSourcetable bool             // Whether response body contains a sourcetable
	Sourcetable    *Sourcetable     // Parsed sourcetable (if applicable)
	BodyLen        int              // Body length in bytes
	ClientIP       string
	ClientPort     uint16
	ConnKey        string
}

func (r *NTRIPResponse) IsReq() bool                 { return false }
func (r *NTRIPResponse) StreamId() protocol.StreamId { return 0 }

func (r *NTRIPResponse) FormatToString() string {
	result := fmt.Sprintf("NTRIP Response: %s\n", r.StatusLine)
	result += fmt.Sprintf("  Status Code:  %d\n", r.StatusCode)
	result += fmt.Sprintf("  Version:      %s\n", r.Version)
	result += fmt.Sprintf("  Session Type: %s\n", r.SessionType)
	if r.IsICY {
		result += "  ICY Mode:     true (NTRIP v1 Icecast protocol)\n"
	}
	if r.ContentType != "" {
		result += fmt.Sprintf("  Content-Type: %s\n", r.ContentType)
	}
	if r.BodyLen > 0 {
		result += fmt.Sprintf("  Body Length:  %d bytes\n", r.BodyLen)
	}
	if r.HasSourcetable && r.Sourcetable != nil {
		result += fmt.Sprintf("  Sourcetable:  %d casters, %d networks, %d mountpoints",
			len(r.Sourcetable.Casters), len(r.Sourcetable.Networks), len(r.Sourcetable.Mounts))
	}
	return result
}

func (r *NTRIPResponse) FormatToSummaryString() string {
	switch {
	case r.IsICY:
		return fmt.Sprintf("NTRIP ICY %d (%s)", r.StatusCode, r.SessionType)
	case r.HasSourcetable:
		count := 0
		if r.Sourcetable != nil {
			count = len(r.Sourcetable.Mounts)
		}
		return fmt.Sprintf("NTRIP SOURCETABLE %d (%d mounts)", r.StatusCode, count)
	default:
		return fmt.Sprintf("NTRIP %d %s [%s]", r.StatusCode, r.SessionType, r.Version)
	}
}

// NTRIPRTCMFrame wraps an RTCM frame observed within an NTRIP data stream.
type NTRIPRTCMFrame struct {
	protocol.FrameBase
	Inner      *rtcm.RTCMFrame // The underlying RTCM frame
	ClientIP   string
	ClientPort uint16
	ConnKey    string
	isResp     bool // when true, this frame is on the response side of a record
}

func (f *NTRIPRTCMFrame) IsReq() bool                 { return !f.isResp }
func (f *NTRIPRTCMFrame) SetIsResp(v bool)            { f.isResp = v }
func (f *NTRIPRTCMFrame) StreamId() protocol.StreamId { return 0 }

func (f *NTRIPRTCMFrame) FormatToString() string {
	return "NTRIP> " + f.Inner.FormatToString()
}

func (f *NTRIPRTCMFrame) FormatToSummaryString() string {
	return "NTRIP> " + f.Inner.FormatToSummaryString()
}

// NTRIPNMEASentence represents an NMEA sentence sent by the NTRIP client
// back to the server (typically GGA for VRS positioning).
type NTRIPNMEASentence struct {
	protocol.FrameBase
	SentenceType string // e.g. "GGA", "RMC"
	Raw          string // Complete NMEA sentence text
	// GGA-specific parsed fields (populated when SentenceType == "GGA")
	GGAParsed     bool    // Whether GGA fields were successfully parsed
	UTCTime       string  // UTC time string (hhmmss.ss)
	Latitude      float64 // Latitude in decimal degrees (negative = South)
	Longitude     float64 // Longitude in decimal degrees (negative = West)
	FixQuality    int     // GPS fix quality: 0=invalid,1=GPS,2=DGPS,4=RTK-fixed,5=RTK-float
	NumSatellites int     // Number of satellites in use
	HDOP          float64 // Horizontal dilution of precision
	Altitude      float64 // Antenna altitude above MSL (metres)
	DiffAge       float64 // Age of differential GPS data in seconds (-1 if not present)
	DiffStationID string  // Differential reference station ID (empty if not present)
	ClientIP      string
	ClientPort    uint16
	ConnKey       string
	isReq         bool
}

func (s *NTRIPNMEASentence) IsReq() bool                 { return true }
func (s *NTRIPNMEASentence) StreamId() protocol.StreamId { return 0 }

func (s *NTRIPNMEASentence) FormatToString() string {
	result := fmt.Sprintf("NTRIP NMEA: %s", s.Raw)
	if s.GGAParsed {
		result += fmt.Sprintf("\n  Type:         %s", s.SentenceType)
		if s.UTCTime != "" {
			result += fmt.Sprintf("\n  UTC Time:     %s", s.UTCTime)
		}
		result += fmt.Sprintf("\n  Position:     %.6f, %.6f", s.Latitude, s.Longitude)
		result += fmt.Sprintf("\n  Fix Quality:  %d (%s)", s.FixQuality, fixQualityName(s.FixQuality))
		result += fmt.Sprintf("\n  Satellites:   %d", s.NumSatellites)
		if s.HDOP > 0 {
			result += fmt.Sprintf("\n  HDOP:         %.1f", s.HDOP)
		}
		if s.Altitude != 0 {
			result += fmt.Sprintf("\n  Altitude:     %.1f m", s.Altitude)
		}
		if s.DiffAge >= 0 {
			result += fmt.Sprintf("\n  Diff Age:     %.1f s", s.DiffAge)
		}
		if s.DiffStationID != "" {
			result += fmt.Sprintf("\n  Diff Station: %s", s.DiffStationID)
		}
	}
	return result
}

func (s *NTRIPNMEASentence) FormatToSummaryString() string {
	if s.GGAParsed {
		return fmt.Sprintf("NMEA %s [%.4f,%.4f fix=%d sats=%d]",
			s.SentenceType, s.Latitude, s.Longitude, s.FixQuality, s.NumSatellites)
	}
	return fmt.Sprintf("NMEA %s", s.SentenceType)
}

// fixQualityName returns a human-readable name for the GPS fix quality indicator.
func fixQualityName(q int) string {
	switch q {
	case 0:
		return "Invalid"
	case 1:
		return "GPS"
	case 2:
		return "DGPS"
	case 3:
		return "PPS"
	case 4:
		return "RTK-Fixed"
	case 5:
		return "RTK-Float"
	case 6:
		return "Estimated"
	case 7:
		return "Manual"
	case 8:
		return "Simulation"
	default:
		return "Unknown"
	}
}

// ==========================================================================
// Stream Parser
// ==========================================================================

// parserMode indicates which direction/phase this parser instance is handling.
type parserMode int

const (
	modeAutoDetect   parserMode = iota
	modeRequestSide             // Client → Server: HTTP requests + NMEA backchannel
	modeResponseSide            // Server → Client: HTTP/ICY/SOURCETABLE responses + RTCM stream
)

// NTRIPStreamParser implements ProtocolStreamParser for NTRIP v1/v2.
//
// It auto-detects the traffic direction on the first ParseStream call:
//   - If the first message looks like an HTTP request → modeRequestSide
//   - If the first message looks like an HTTP/ICY response → modeResponseSide
//
// After the handshake phase completes, the parser seamlessly transitions to
// binary mode: RTCM frame parsing on the response side, NMEA sentence parsing
// on the request side.
type NTRIPStreamParser struct {
	mode       parserMode
	rtcmParser *rtcm.RTCMStreamParser // Lazily initialized for post-handshake phase
}

// --------------------------------------------------------------------------
// HTTP request patterns (client → server)
// --------------------------------------------------------------------------

var ntripReqPrefixes = []string{
	"GET ",
	"POST ",
	"SOURCE ",
}

// --------------------------------------------------------------------------
// HTTP/NTRIP response patterns (server → client)
// --------------------------------------------------------------------------

var ntripRespPrefixes = []string{
	"HTTP/1.1 ",
	"HTTP/1.0 ",
	"ICY ",
	"SOURCETABLE ",
	"ERROR ",
}

// --------------------------------------------------------------------------
// FindBoundary
// --------------------------------------------------------------------------

// FindBoundary scans the stream buffer for the next valid message start.
func (p *NTRIPStreamParser) FindBoundary(
	streamBuffer *buffer.StreamBuffer,
	messageType protocol.MessageType,
	startPos int,
) int {
	head := streamBuffer.Head()
	if head == nil {
		return -1
	}
	buf := head.Buffer()

	// Try all boundary types regardless of mode. NTRIP streams mix request
	// data (GGA) and response data (RTCM, ICY) in the same direction, and a
	// single parser instance is shared across both stream buffers. The mode
	// may lag behind the actual data, so we always scan for all boundary types.
	if pos := p.findRequestBoundary(buf, startPos); pos >= 0 {
		return pos
	}
	if pos := p.findResponseBoundary(buf, startPos); pos >= 0 {
		return pos
	}
	// Last resort: raw RTCM frame preamble
	for i := startPos; i < len(buf)-2; i++ {
		if buf[i] == 0xD3 && (buf[i+1]&0xFC) == 0x00 {
			return i
		}
	}
	return -1
}

func (p *NTRIPStreamParser) findRequestBoundary(buf []byte, startPos int) int {
	for i := startPos; i < len(buf); i++ {
		for _, prefix := range ntripReqPrefixes {
			if i+len(prefix) <= len(buf) && string(buf[i:i+len(prefix)]) == prefix {
				return i
			}
		}
		// NMEA sentence start
		if buf[i] == '$' && i+6 < len(buf) {
			return i
		}
	}
	return -1
}

func (p *NTRIPStreamParser) findResponseBoundary(buf []byte, startPos int) int {
	for i := startPos; i < len(buf); i++ {
		for _, prefix := range ntripRespPrefixes {
			if i+len(prefix) <= len(buf) && string(buf[i:i+len(prefix)]) == prefix {
				return i
			}
		}
		// RTCM frame preamble with reserved-bits validation
		if buf[i] == 0xD3 && i+2 < len(buf) && (buf[i+1]&0xFC) == 0x00 {
			return i
		}
	}
	return -1
}

// --------------------------------------------------------------------------
// ParseStream
// --------------------------------------------------------------------------

// ParseStream attempts to parse one message from the head of the stream buffer.
func (p *NTRIPStreamParser) ParseStream(
	streamBuffer *buffer.StreamBuffer,
	messageType protocol.MessageType,
) protocol.ParseResult {
	head := streamBuffer.Head()
	if head == nil {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	buf := head.Buffer()
	if len(buf) == 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	// 1. 如果以 '$' 开头，一定是 NMEA 语句（GGA 语句等）
	if buf[0] == '$' {
		return p.parseNMEA(buf, streamBuffer, messageType)
	}

	// 2. 如果以 0xD3 开头且符合 RTCM 帧头，一定是 RTCM 帧
	if buf[0] == 0xD3 && len(buf) >= 3 && (buf[1]&0xFC) == 0x00 {
		return p.parseRTCMFrame(buf, streamBuffer, messageType)
	}

	// 3. 检查是否匹配 HTTP-like 请求前缀
	for _, prefix := range ntripReqPrefixes {
		if len(buf) >= len(prefix) && string(buf[:len(prefix)]) == prefix {
			return p.parseRequest(buf, streamBuffer)
		}
	}

	// 4. 检查是否匹配 HTTP-like 响应前缀
	for _, prefix := range ntripRespPrefixes {
		if len(buf) >= len(prefix) && string(buf[:len(prefix)]) == prefix {
			return p.parseResponse(buf, streamBuffer)
		}
	}

	return protocol.ParseResult{ParseState: protocol.Invalid}
}

// detectMode sets the parser mode based on the first bytes of the buffer.
func (p *NTRIPStreamParser) detectMode(buf []byte) {
	for _, prefix := range ntripReqPrefixes {
		if len(buf) >= len(prefix) && string(buf[:len(prefix)]) == prefix {
			p.mode = modeRequestSide
			return
		}
	}
	for _, prefix := range ntripRespPrefixes {
		if len(buf) >= len(prefix) && string(buf[:len(prefix)]) == prefix {
			p.mode = modeResponseSide
			return
		}
	}
	// If starts with '$', it's NMEA from client side
	if len(buf) > 0 && buf[0] == '$' {
		p.mode = modeRequestSide
		return
	}
	// RTCM preamble (0xD3 with reserved bits zero) → response side
	// This handles the case where BPF misassigns the role and RTCM data
	// lands in the request buffer.
	if len(buf) >= 3 && buf[0] == 0xD3 && (buf[1]&0xFC) == 0x00 {
		p.mode = modeResponseSide
	}
}

// --------------------------------------------------------------------------
// Request-side parsing (Client → Server)
// --------------------------------------------------------------------------

func (p *NTRIPStreamParser) parseRequestSide(
	buf []byte, streamBuffer *buffer.StreamBuffer,
) protocol.ParseResult {
	if len(buf) == 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	// NMEA sentence (post-handshake backchannel)
	if buf[0] == '$' {
		return p.parseNMEA(buf, streamBuffer, protocol.Request)
	}

	// HTTP-like request
	return p.parseRequest(buf, streamBuffer)
}

// parseRequest parses an HTTP-like NTRIP request (GET, POST, SOURCE).
//
// Wire formats:
//
//	GET /MOUNTPOINT HTTP/1.1\r\nHost: ...\r\nNtrip-Version: Ntrip/2.0\r\n\r\n
//	SOURCE <password> /MOUNTPOINT\r\nSource-Agent: ...\r\n\r\n
//	POST /MOUNTPOINT HTTP/1.1\r\nNtrip-Version: Ntrip/2.0\r\n\r\n
func (p *NTRIPStreamParser) parseRequest(
	buf []byte, streamBuffer *buffer.StreamBuffer,
) protocol.ParseResult {
	// Find end of request line
	crlfIdx := bytes.Index(buf, []byte("\r\n"))
	if crlfIdx < 0 {
		if len(buf) > 4096 {
			return protocol.ParseResult{ParseState: protocol.Invalid}
		}
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	requestLine := string(buf[:crlfIdx])
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return protocol.ParseResult{ParseState: protocol.Invalid}
	}

	method := strings.ToUpper(parts[0])

	// Find end of headers (\r\n\r\n)
	headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		if len(buf) > 8192 {
			return protocol.ParseResult{ParseState: protocol.Invalid}
		}
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	totalLen := headerEnd + 4

	// Parse headers using textproto (requires bufio.Reader)
	headerBlock := string(buf[crlfIdx+2 : headerEnd+2])
	tpReader := textproto.NewReader(bufio.NewReader(strings.NewReader(headerBlock)))
	mimeHeader, err := tpReader.ReadMIMEHeader()
	if err != nil {
		// ReadMIMEHeader returns io.EOF when the input doesn't end with
		// \r\n\r\n, but it still returns the headers parsed so far.
		// Only create an empty header if nil was returned.
		if mimeHeader == nil {
			mimeHeader = make(textproto.MIMEHeader)
		}
	}

	// Detect NTRIP version
	version := NTRIPv1
	if strings.EqualFold(mimeHeader.Get(NTRIPVersionHeaderKey), NTRIPVersionHeaderValueV2) {
		version = NTRIPv2
	}

	// Determine session type and extract mountpoint
	var sessionType NTRIPSessionType
	var mountPoint string
	var username, password string

	switch method {
	case MethodSource:
		sessionType = SessionTypeSourcePush
		// SOURCE <password> /mountpoint
		if len(parts) >= 3 {
			password = parts[1]
			mountPoint = normalizePath(parts[2])
		} else if len(parts) == 2 {
			mountPoint = normalizePath(parts[1])
		}
	case MethodGet:
		mountPoint = normalizePath(parts[1])
		if mountPoint == "/" || mountPoint == "" {
			sessionType = SessionTypeSourcetable
		} else {
			sessionType = SessionTypeDataStream
		}
	case MethodPost:
		sessionType = SessionTypeSourcePush
		mountPoint = normalizePath(parts[1])
	default:
		sessionType = SessionTypeDataStream
		mountPoint = normalizePath(parts[1])
	}

	// Extract credentials from Authorization header (Basic auth)
	authHeader := mimeHeader.Get("Authorization")
	hasAuth := authHeader != ""
	if hasAuth && username == "" {
		if u, p, ok := parseBasicAuth(authHeader); ok {
			username = u
			password = p
		}
	}

	seq := streamBuffer.Head().LeftBoundary()
	ts, ok := streamBuffer.FindTimestampBySeq(seq)
	if !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore}
	}

	req := &NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(ts, totalLen, seq),
		Method:      method,
		Path:        parts[1],
		Version:     version,
		SessionType: sessionType,
		MountPoint:  mountPoint,
		HasAuth:     hasAuth,
		Username:    username,
		Password:    password,
		UserAgent:   mimeHeader.Get("User-Agent"),
		ContentType: mimeHeader.Get("Content-Type"),
		// Load-balancer (CLB) real-client-IP signals. Extracted unconditionally;
		// the session tracker decides whether/which to trust based on config.
		ForwardedFor: mimeHeader.Get("X-Forwarded-For"),
		XRealIP:      mimeHeader.Get("X-Real-IP"),
	}

	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{req},
		ReadBytes:      totalLen,
	}
}

// --------------------------------------------------------------------------
// Response-side parsing (Server → Client)
// --------------------------------------------------------------------------

func (p *NTRIPStreamParser) parseResponseSide(
	buf []byte, streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType,
) protocol.ParseResult {
	if len(buf) == 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	// RTCM frame (post-handshake data stream)
	if buf[0] == 0xD3 && len(buf) >= 3 && (buf[1]&0xFC) == 0x00 {
		return p.parseRTCMFrame(buf, streamBuffer, messageType)
	}

	// HTTP-like response
	return p.parseResponse(buf, streamBuffer)
}

// parseResponse parses an HTTP/ICY/SOURCETABLE/ERROR response.
//
// Wire formats:
//
//	ICY 200 OK\r\n\r\n                               (v1 data stream success)
//	SOURCETABLE 200 OK\r\n...Content-Length: N\r\n\r\n...ENDSOURCETABLE\r\n
//	HTTP/1.1 200 OK\r\nNtrip-Version: Ntrip/2.0\r\nContent-Type: gnss/data\r\n\r\n
//	ERROR - Bad Password\r\n                          (v1 SOURCE error)
func (p *NTRIPStreamParser) parseResponse(
	buf []byte, streamBuffer *buffer.StreamBuffer,
) protocol.ParseResult {
	if len(buf) < 4 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	statusLine := string(buf)

	// --- NTRIP v1 ICY response ---
	if strings.HasPrefix(statusLine, NTRIPv1ICYPrefix) {
		return p.parseICYResponse(buf, streamBuffer)
	}

	// --- NTRIP v1 SOURCETABLE response ---
	if strings.HasPrefix(statusLine, NTRIPv1SourcetablePrefix) {
		return p.parseSourcetableResponse(buf, streamBuffer)
	}

	// --- NTRIP v1 ERROR response (short, single line) ---
	if strings.HasPrefix(statusLine, NTRIPv1ErrorPrefix) {
		return p.parseErrorResponse(buf, streamBuffer)
	}

	// --- Standard HTTP response ---
	if strings.HasPrefix(statusLine, "HTTP/1.1 ") || strings.HasPrefix(statusLine, "HTTP/1.0 ") {
		return p.parseHTTPResponse(buf, streamBuffer)
	}

	return protocol.ParseResult{ParseState: protocol.Invalid}
}

// parseICYResponse handles NTRIP v1 "ICY 200 OK\r\n\r\n" responses.
// After the blank line, raw RTCM data begins immediately.
func (p *NTRIPStreamParser) parseICYResponse(
	buf []byte, streamBuffer *buffer.StreamBuffer,
) protocol.ParseResult {
	// ICY responses may have optional headers or just \r\n\r\n
	headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		// Some implementations use just \r\n without a blank line separator
		crlfIdx := bytes.Index(buf[4:], []byte("\r\n"))
		if crlfIdx < 0 {
			if len(buf) > 512 {
				return protocol.ParseResult{ParseState: protocol.Invalid}
			}
			return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
		}
		headerEnd = 4 + crlfIdx
		totalLen := headerEnd + 2 // consume through \r\n
		return p.buildResponseResult(buf, streamBuffer, totalLen, "ICY 200 OK", 200, true, false, nil)
	}

	totalLen := headerEnd + 4
	return p.buildResponseResult(buf, streamBuffer, totalLen, "ICY 200 OK", 200, true, false, nil)
}

// parseSourcetableResponse handles NTRIP v1 "SOURCETABLE 200 OK" responses.
// The body contains CAS/NET/STR lines terminated by ENDSOURCETABLE.
func (p *NTRIPStreamParser) parseSourcetableResponse(
	buf []byte, streamBuffer *buffer.StreamBuffer,
) protocol.ParseResult {
	headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		if len(buf) > 8192 {
			return protocol.ParseResult{ParseState: protocol.Invalid}
		}
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	bodyStart := headerEnd + 4

	// Find ENDSOURCETABLE marker in the body
	endMarker := []byte("ENDSOURCETABLE")
	endIdx := bytes.Index(buf[bodyStart:], endMarker)
	if endIdx < 0 {
		if len(buf) > 65536 {
			return protocol.ParseResult{ParseState: protocol.Invalid}
		}
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	bodyEnd := bodyStart + endIdx + len(endMarker)
	// Consume trailing \r\n if present
	if bodyEnd+2 <= len(buf) && buf[bodyEnd] == '\r' && buf[bodyEnd+1] == '\n' {
		bodyEnd += 2
	} else if bodyEnd+1 <= len(buf) && buf[bodyEnd] == '\n' {
		bodyEnd++
	}

	// Parse the sourcetable body
	bodyText := string(buf[bodyStart : bodyStart+endIdx+len(endMarker)])
	st := ParseSourcetable(bodyText)

	return p.buildResponseResult(buf, streamBuffer, bodyEnd, "SOURCETABLE 200 OK", 200, false, true, st)
}

// parseErrorResponse handles NTRIP v1 "ERROR - <message>\r\n" responses.
func (p *NTRIPStreamParser) parseErrorResponse(
	buf []byte, streamBuffer *buffer.StreamBuffer,
) protocol.ParseResult {
	crlfIdx := bytes.Index(buf, []byte("\r\n"))
	if crlfIdx < 0 {
		if len(buf) > 256 {
			return protocol.ParseResult{ParseState: protocol.Invalid}
		}
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	statusLine := string(buf[:crlfIdx])
	totalLen := crlfIdx + 2

	return p.buildResponseResult(buf, streamBuffer, totalLen, statusLine, 0, false, false, nil)
}

// parseHTTPResponse handles standard HTTP/1.x responses (NTRIP v2 or v1 HTTP errors).
func (p *NTRIPStreamParser) parseHTTPResponse(
	buf []byte, streamBuffer *buffer.StreamBuffer,
) protocol.ParseResult {
	headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		if len(buf) > 8192 {
			return protocol.ParseResult{ParseState: protocol.Invalid}
		}
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	// Parse status code from "HTTP/1.x NNN ..."
	firstLine := string(buf[:bytes.Index(buf, []byte("\r\n"))])
	statusCode := extractHTTPStatusCode(firstLine)

	// Parse headers
	headerBlock := string(buf[bytes.Index(buf, []byte("\r\n"))+2 : headerEnd+2])
	tpReader := textproto.NewReader(bufio.NewReader(strings.NewReader(headerBlock)))
	mimeHeader, err := tpReader.ReadMIMEHeader()
	if err != nil {
		if mimeHeader == nil {
			mimeHeader = make(textproto.MIMEHeader)
		}
	}

	bodyStart := headerEnd + 4
	var st *Sourcetable
	contentType := mimeHeader.Get("Content-Type")

	// Check if this is a sourcetable response (v2 with text/plain body)
	if strings.Contains(contentType, "text/plain") {
		endIdx := bytes.Index(buf[bodyStart:], []byte("ENDSOURCETABLE"))
		if endIdx >= 0 {
			bodyEnd := bodyStart + endIdx + len("ENDSOURCETABLE")
			if bodyEnd+2 <= len(buf) && buf[bodyEnd] == '\r' && buf[bodyEnd+1] == '\n' {
				bodyEnd += 2
			}
			bodyText := string(buf[bodyStart:bodyEnd])
			st = ParseSourcetable(bodyText)
			return p.buildResponseResult(buf, streamBuffer, bodyEnd, firstLine, statusCode, false, true, st)
		}
	}

	// Determine body length
	var totalLen int
	if cl := mimeHeader.Get("Content-Length"); cl != "" {
		contentLen, _ := strconv.Atoi(cl)
		totalLen = bodyStart + contentLen
	} else {
		// No Content-Length: for data stream responses (gnss/data), body is empty
		// and RTCM frames follow immediately. Treat the headers as the complete message.
		totalLen = bodyStart
	}

	if len(buf) < totalLen {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	return p.buildResponseResult(buf, streamBuffer, totalLen, firstLine, statusCode, false, false, nil)
}

// buildResponseResult constructs the ParseResult for any response type.
func (p *NTRIPStreamParser) buildResponseResult(
	buf []byte,
	streamBuffer *buffer.StreamBuffer,
	totalLen int,
	statusLine string,
	statusCode int,
	isICY bool,
	hasSourcetable bool,
	st *Sourcetable,
) protocol.ParseResult {
	seq := streamBuffer.Head().LeftBoundary()
	ts, ok := streamBuffer.FindTimestampBySeq(seq)
	if !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore}
	}

	version := NTRIPv1
	if !isICY && strings.Contains(statusLine, "HTTP/1.1") {
		// Could be v2 if Ntrip-Version header is present, but we check later
		version = NTRIPv1
	}

	sessionType := SessionTypeDataStream
	if hasSourcetable {
		sessionType = SessionTypeSourcetable
	}

	bodyLen := 0
	headerEnd := bytes.Index(buf[:min(totalLen, len(buf))], []byte("\r\n\r\n"))
	if headerEnd >= 0 {
		bodyLen = totalLen - (headerEnd + 4)
	}

	resp := &NTRIPResponse{
		FrameBase:      protocol.NewFrameBase(ts, totalLen, seq),
		Version:        version,
		SessionType:    sessionType,
		StatusCode:     statusCode,
		StatusLine:     statusLine,
		IsICY:          isICY,
		HasSourcetable: hasSourcetable,
		Sourcetable:    st,
		BodyLen:        bodyLen,
	}

	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{resp},
		ReadBytes:      totalLen,
	}
}

// --------------------------------------------------------------------------
// Post-handshake parsers
// --------------------------------------------------------------------------

// parseRTCMFrame delegates to the RTCM parser for binary RTCM 3.x frames
// within the NTRIP data stream, wrapping the result in an NTRIPRTCMFrame.
func (p *NTRIPStreamParser) parseRTCMFrame(
	buf []byte, streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType,
) protocol.ParseResult {
	if p.rtcmParser == nil {
		p.rtcmParser = &rtcm.RTCMStreamParser{}
	}

	result := p.rtcmParser.ParseStream(streamBuffer, messageType)

	// When the RTCM parser returns Invalid but the buffer starts with a valid
	// RTCM preamble (0xD3 + reserved bits=0), the CRC likely failed on a
	// partial/truncated frame.  Advance past 1 byte and search for the next
	// valid RTCM frame so the outer parse loop doesn't re-find the same
	// invalid preamble and spin.
	if result.ParseState == protocol.Invalid &&
		len(buf) > 2 && buf[0] == rtcm.RTCMPreamble && (buf[1]&0xFC) == 0x00 {
		for i := 1; i < len(buf)-2; i++ {
			if buf[i] == rtcm.RTCMPreamble && (buf[i+1]&0xFC) == 0x00 {
				return protocol.ParseResult{
					ParseState: protocol.Invalid,
					ReadBytes:  i,
				}
			}
		}
		// No next frame found — return original result (NeedsMoreData or Invalid)
		return result
	}

	if result.ParseState != protocol.Success {
		return result
	}

	// Wrap inner RTCM frames
	wrapped := make([]protocol.ParsedMessage, 0, len(result.ParsedMessages))
	for _, msg := range result.ParsedMessages {
		if inner, ok := msg.(*rtcm.RTCMFrame); ok {
			wrapped = append(wrapped, &NTRIPRTCMFrame{
				FrameBase: protocol.NewFrameBase(inner.TimestampNs(), inner.ByteSize(), inner.Seq()),
				Inner:     inner,
			})
		}
	}

	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: wrapped,
		ReadBytes:      result.ReadBytes,
	}
}

// parseNMEA parses an NMEA sentence from the client backchannel.
// NMEA sentences are ASCII text starting with '$' and ending with '*XX\r\n'.
func (p *NTRIPStreamParser) parseNMEA(
	buf []byte, streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType,
) protocol.ParseResult {
	if len(buf) < 6 || buf[0] != '$' {
		return protocol.ParseResult{ParseState: protocol.Invalid}
	}

	// Find end of sentence (\r\n or \n)
	endIdx := -1
	for i := 1; i < len(buf) && i < 256; i++ {
		if buf[i] == '\n' {
			if i > 0 && buf[i-1] == '\r' {
				endIdx = i + 1
			} else {
				endIdx = i + 1
			}
			break
		}
	}

	if endIdx < 0 {
		if len(buf) > 256 {
			return protocol.ParseResult{ParseState: protocol.Invalid}
		}
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	sentence := strings.TrimRight(string(buf[:endIdx]), "\r\n")

	// Basic NMEA validation: must contain '*' for checksum
	starIdx := strings.LastIndex(sentence, "*")
	if starIdx < 0 || starIdx >= len(sentence)-2 {
		// Not a valid NMEA sentence, skip this line
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
			ReadBytes:  endIdx,
		}
	}

	// Extract sentence type (e.g., "GPGGA" → "GGA", "GNGGA" → "GGA")
	rawType := ""
	if commaIdx := strings.Index(sentence, ","); commaIdx > 0 && commaIdx < starIdx-2 {
		rawType = sentence[1:commaIdx]
	}
	sentenceType := rawType
	if len(rawType) > 2 {
		sentenceType = rawType[2:] // Strip talker ID (GP, GN, GL, etc.)
	}

	seq := streamBuffer.Head().LeftBoundary()
	ts, ok := streamBuffer.FindTimestampBySeq(seq)
	if !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore}
	}

	nmea := &NTRIPNMEASentence{
		FrameBase:    protocol.NewFrameBase(ts, endIdx, seq),
		SentenceType: sentenceType,
		Raw:          sentence,
	}

	// Parse GGA-specific fields
	if sentenceType == "GGA" {
		parseGGASentence(sentence, nmea)
	}

	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{nmea},
		ReadBytes:      endIdx,
	}
}

// --------------------------------------------------------------------------
// Match
// --------------------------------------------------------------------------

// Match pairs NTRIP handshake messages into Records and emits RTCM/NMEA
// frames as independent records.
func (p *NTRIPStreamParser) Match(
	reqStreams map[protocol.StreamId]*protocol.ParsedMessageQueue,
	respStreams map[protocol.StreamId]*protocol.ParsedMessageQueue,
) []protocol.Record {
	records := make([]protocol.Record, 0)

	var reqMsgs []protocol.ParsedMessage
	var respMsgs []protocol.ParsedMessage

	if q, ok := reqStreams[0]; ok {
		reqMsgs = *q
	}
	if q, ok := respStreams[0]; ok {
		respMsgs = *q
	}

	reqIdx := 0
	respIdx := 0

	// Pair handshake messages: NTRIPRequest ↔ NTRIPResponse
	for reqIdx < len(reqMsgs) && respIdx < len(respMsgs) {
		req, isReq := reqMsgs[reqIdx].(*NTRIPRequest)
		resp, isResp := respMsgs[respIdx].(*NTRIPResponse)

		if isReq && isResp {
			status := protocol.UnknownStatus
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				status = protocol.SuccessStatus
			} else if resp.StatusCode >= 400 {
				status = protocol.FailStatus
			} else if resp.IsICY {
				status = protocol.SuccessStatus
			}

			records = append(records, protocol.Record{
				Req:            req,
				Resp:           resp,
				ResponseStatus: status,
			})
			reqIdx++
			respIdx++
			continue
		}
		break
	}

	// Remaining requests (NMEA sentences or unmatched requests)
	for i := reqIdx; i < len(reqMsgs); i++ {
		records = append(records, protocol.Record{Req: reqMsgs[i]})
	}

	// Remaining responses (RTCM frames or unmatched responses)
	for i := respIdx; i < len(respMsgs); i++ {
		records = append(records, protocol.Record{Resp: respMsgs[i]})
	}

	if q, ok := reqStreams[0]; ok {
		*q = (*q)[len(reqMsgs):]
	}
	if q, ok := respStreams[0]; ok {
		*q = (*q)[len(respMsgs):]
	}

	return records
}

// --------------------------------------------------------------------------
// Registration
// --------------------------------------------------------------------------

func init() {
	protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolNTRIP] = func() protocol.ProtocolStreamParser {
		return &NTRIPStreamParser{}
	}
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// normalizePath extracts the mountpoint name from a URL path.
func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	// Strip protocol suffix if accidentally included (e.g., "HTTP/1.1")
	if idx := strings.Index(path, " HTTP/"); idx > 0 {
		path = path[:idx]
	}
	if path == "" || path == "/" {
		return "/"
	}
	// Remove leading slash for mountpoint name
	return strings.TrimPrefix(path, "/")
}

// extractHTTPStatusCode parses the status code from an HTTP status line.
func extractHTTPStatusCode(line string) int {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) >= 2 {
		code, err := strconv.Atoi(parts[1])
		if err == nil {
			return code
		}
	}
	return 0
}

// parseBasicAuth extracts username and password from an HTTP Basic auth header.
// Input: "Basic dXNlcjpwYXNz" → ("user", "pass", true)
func parseBasicAuth(header string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	encoded := strings.TrimSpace(header[len(prefix):])
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// parseGGASentence parses GGA-specific fields from an NMEA GGA sentence.
//
// GGA sentence format:
//
//	$GPGGA,hhmmss.ss,ddmm.mmmm,N,dddmm.mmmm,E,q,nn,d.d,alt,M,sep,M,age,id*cs
//
// Fields (0-indexed after splitting by comma):
//
//	 0: UTC time (hhmmss.ss)
//	 1: Latitude (ddmm.mmmm)
//	 2: N/S indicator
//	 3: Longitude (dddmm.mmmm)
//	 4: E/W indicator
//	 5: GPS fix quality (0-8)
//	 6: Number of satellites in use
//	 7: HDOP
//	 8: Altitude above MSL
//	 9: Altitude units (M)
//	10: Geoid separation
//	11: Geoid units
//	12: Age of differential GPS data (seconds)
//	13: Differential reference station ID
func parseGGASentence(sentence string, nmea *NTRIPNMEASentence) {
	// Strip checksum part for field parsing
	raw := sentence
	if starIdx := strings.LastIndex(raw, "*"); starIdx >= 0 {
		raw = raw[:starIdx]
	}
	// Strip leading '$' + talker+sentence type
	if commaIdx := strings.Index(raw, ","); commaIdx >= 0 {
		raw = raw[commaIdx+1:]
	} else {
		return
	}

	fields := strings.Split(raw, ",")
	if len(fields) < 10 {
		return
	}

	nmea.GGAParsed = true
	nmea.UTCTime = fields[0]
	nmea.DiffAge = -1 // default: not present

	// Parse latitude: ddmm.mmmm
	if lat, err := parseNMEACoord(fields[1], fields[2]); err == nil {
		nmea.Latitude = lat
	}

	// Parse longitude: dddmm.mmmm
	if lon, err := parseNMEACoord(fields[3], fields[4]); err == nil {
		nmea.Longitude = lon
	}

	// Fix quality
	if q, err := strconv.Atoi(fields[5]); err == nil {
		nmea.FixQuality = q
	}

	// Number of satellites
	if n, err := strconv.Atoi(fields[6]); err == nil {
		nmea.NumSatellites = n
	}

	// HDOP
	if h, err := strconv.ParseFloat(fields[7], 64); err == nil {
		nmea.HDOP = h
	}

	// Altitude
	if fields[8] != "" {
		if alt, err := strconv.ParseFloat(fields[8], 64); err == nil {
			nmea.Altitude = alt
		}
	}

	// Age of differential GPS data (field 12, optional)
	if len(fields) > 12 && fields[12] != "" {
		if age, err := strconv.ParseFloat(fields[12], 64); err == nil {
			nmea.DiffAge = age
		}
	}

	// Differential reference station ID (field 13, optional)
	if len(fields) > 13 && strings.TrimSpace(fields[13]) != "" {
		nmea.DiffStationID = strings.TrimSpace(fields[13])
	}
}

// parseNMEACoord converts NMEA coordinate format to decimal degrees.
// coord: "ddmm.mmmm" or "dddmm.mmmm", dir: "N"/"S"/"E"/"W"
func parseNMEACoord(coord, dir string) (float64, error) {
	if coord == "" {
		return 0, fmt.Errorf("empty coordinate")
	}

	// Find the decimal point position
	dotIdx := strings.Index(coord, ".")
	if dotIdx < 0 {
		return 0, fmt.Errorf("invalid coordinate format: %s", coord)
	}

	// Degrees are everything before (dd or ddd), minutes start at dotIdx-2
	degEnd := dotIdx - 2
	if degEnd < 1 {
		return 0, fmt.Errorf("invalid coordinate format: %s", coord)
	}

	deg, err := strconv.ParseFloat(coord[:degEnd], 64)
	if err != nil {
		return 0, err
	}

	minutes, err := strconv.ParseFloat(coord[degEnd:], 64)
	if err != nil {
		return 0, err
	}

	decimal := deg + minutes/60.0

	// Apply hemisphere sign
	switch dir {
	case "S", "W":
		decimal = -decimal
	}

	return decimal, nil
}
