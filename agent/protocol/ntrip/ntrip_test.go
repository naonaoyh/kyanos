package ntrip

import (
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/rtcm"
	"kyanos/bpf"
	"strings"
	"testing"
)

// ==========================================================================
// Helper: build a StreamBuffer from raw bytes with a timestamp
// ==========================================================================

func makeStreamBuffer(data []byte) *buffer.StreamBuffer {
	sb := buffer.New(65536)
	sb.Add(0, data, 1000000000)
	return sb
}

// ==========================================================================
// Sourcetable parsing tests
// ==========================================================================

func TestParseSourcetable(t *testing.T) {
	raw := `CAS;ntrip.example.com;2101;ExampleCaster;Example Org;0;DEU;50.0;8.0;;
NET;ExampleNet;Example Org;N;N;http://example.com;;
STR;MOUNT01;Mount01;RTCM 3.2;1005(1),1074(1),1124(1);2;GPS+GLO+BDS;ExampleNet;DEU;50.1;8.1;0;1;ExampleGen;None;N;N;1200;
STR;MOUNT02;Mount02;RTCM 3.2;1005(1),1077(1);2;GPS;ExampleNet;DEU;50.2;8.2;0;1;ExampleGen;None;N;N;800;
ENDSOURCETABLE`

	st := ParseSourcetable(raw)

	if len(st.Casters) != 1 {
		t.Errorf("expected 1 caster, got %d", len(st.Casters))
	}
	if len(st.Networks) != 1 {
		t.Errorf("expected 1 network, got %d", len(st.Networks))
	}
	if len(st.Mounts) != 2 {
		t.Errorf("expected 2 mountpoints, got %d", len(st.Mounts))
	}

	// Verify caster
	if st.Casters[0].Host != "ntrip.example.com" {
		t.Errorf("caster host = %q, want %q", st.Casters[0].Host, "ntrip.example.com")
	}
	if st.Casters[0].Port != 2101 {
		t.Errorf("caster port = %d, want %d", st.Casters[0].Port, 2101)
	}

	// Verify mountpoint
	if st.Mounts[0].MountPoint != "MOUNT01" {
		t.Errorf("mount[0] name = %q, want %q", st.Mounts[0].MountPoint, "MOUNT01")
	}
	if st.Mounts[0].Format != "RTCM 3.2" {
		t.Errorf("mount[0] format = %q, want %q", st.Mounts[0].Format, "RTCM 3.2")
	}
	if st.Mounts[1].MountPoint != "MOUNT02" {
		t.Errorf("mount[1] name = %q, want %q", st.Mounts[1].MountPoint, "MOUNT02")
	}
}

func TestParseSourcetableEmpty(t *testing.T) {
	st := ParseSourcetable("ENDSOURCETABLE\r\n")
	if len(st.Casters) != 0 || len(st.Networks) != 0 || len(st.Mounts) != 0 {
		t.Error("expected empty sourcetable")
	}
}

func TestGetMountPointNames(t *testing.T) {
	st := &Sourcetable{
		Mounts: []StreamEntry{
			{MountPoint: "M1"},
			{MountPoint: "M2"},
			{MountPoint: "M3"},
		},
	}
	names := st.GetMountPointNames()
	if len(names) != 3 {
		t.Errorf("expected 3 names, got %d", len(names))
	}
	if names[0] != "M1" || names[1] != "M2" || names[2] != "M3" {
		t.Errorf("names = %v, want [M1 M2 M3]", names)
	}
}

func TestFormatToString(t *testing.T) {
	st := &Sourcetable{
		Mounts: []StreamEntry{
			{MountPoint: "M1", Identifier: "ID1", Format: "RTCM 3.2", Latitude: 50.0, Longitude: 8.0},
		},
	}
	result := st.FormatToString()
	if !strings.Contains(result, "M1") {
		t.Errorf("FormatToString() missing mountpoint name")
	}
}

// ==========================================================================
// NTRIP version and session type tests
// ==========================================================================

func TestNTRIPVersionString(t *testing.T) {
	tests := []struct {
		v        NTRIPVersion
		expected string
	}{
		{NTRIPv1, "NTRIPv1"},
		{NTRIPv2, "NTRIPv2"},
		{NTRIPVersionUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.v.String() != tt.expected {
				t.Errorf("NTRIPVersion(%d).String() = %q, want %q", tt.v, tt.v.String(), tt.expected)
			}
		})
	}
}

func TestNTRIPSessionTypeString(t *testing.T) {
	tests := []struct {
		st       NTRIPSessionType
		expected string
	}{
		{SessionTypeDataStream, "DataStream"},
		{SessionTypeSourcePush, "SourcePush"},
		{SessionTypeSourcetable, "Sourcetable"},
		{SessionTypeUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.st.String() != tt.expected {
				t.Errorf("NTRIPSessionType(%d).String() = %q, want %q", tt.st, tt.st.String(), tt.expected)
			}
		})
	}
}

// ==========================================================================
// Message formatting tests
// ==========================================================================

func TestNTRIPRequestFormatToString(t *testing.T) {
	req := &NTRIPRequest{
		Method:      "GET",
		Path:        "/MOUNT01",
		Version:     NTRIPv2,
		SessionType: SessionTypeDataStream,
		MountPoint:  "MOUNT01",
		HasAuth:     true,
		UserAgent:   "NTRIP client/1.0",
	}

	result := req.FormatToString()
	if !strings.Contains(result, "GET") {
		t.Errorf("FormatToString() missing method")
	}
	if !strings.Contains(result, "MOUNT01") {
		t.Errorf("FormatToString() missing mountpoint")
	}
	if !strings.Contains(result, "NTRIPv2") {
		t.Errorf("FormatToString() missing version")
	}
}

func TestNTRIPRequestFormatToSummaryString(t *testing.T) {
	tests := []struct {
		name     string
		req      *NTRIPRequest
		contains string
	}{
		{
			name: "sourcetable",
			req: &NTRIPRequest{
				Method:      "GET",
				SessionType: SessionTypeSourcetable,
				Version:     NTRIPv1,
			},
			contains: "sourcetable",
		},
		{
			name: "source push",
			req: &NTRIPRequest{
				Method:      "SOURCE",
				SessionType: SessionTypeSourcePush,
				MountPoint:  "M1",
				Version:     NTRIPv1,
			},
			contains: "SOURCE",
		},
		{
			name: "data stream",
			req: &NTRIPRequest{
				Method:      "GET",
				SessionType: SessionTypeDataStream,
				MountPoint:  "M1",
				Version:     NTRIPv2,
			},
			contains: "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.req.FormatToSummaryString()
			if !strings.Contains(result, tt.contains) {
				t.Errorf("FormatToSummaryString() = %q, missing %q", result, tt.contains)
			}
		})
	}
}

func TestNTRIPResponseFormatToString(t *testing.T) {
	resp := &NTRIPResponse{
		StatusLine:  "ICY 200 OK",
		StatusCode:  200,
		Version:     NTRIPv1,
		SessionType: SessionTypeDataStream,
		IsICY:       true,
	}

	result := resp.FormatToString()
	if !strings.Contains(result, "ICY 200 OK") {
		t.Errorf("FormatToString() missing status line")
	}
}

func TestNTRIPResponseFormatToSummaryString(t *testing.T) {
	tests := []struct {
		name     string
		resp     *NTRIPResponse
		contains string
	}{
		{
			name: "ICY response",
			resp: &NTRIPResponse{
				IsICY:       true,
				StatusCode:  200,
				SessionType: SessionTypeDataStream,
			},
			contains: "ICY",
		},
		{
			name: "sourcetable response",
			resp: &NTRIPResponse{
				HasSourcetable: true,
				Sourcetable:    &Sourcetable{Mounts: []StreamEntry{{MountPoint: "M1"}}},
				StatusCode:     200,
			},
			contains: "SOURCETABLE",
		},
		{
			name: "standard HTTP response",
			resp: &NTRIPResponse{
				StatusCode:  200,
				SessionType: SessionTypeDataStream,
				Version:     NTRIPv2,
			},
			contains: "200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resp.FormatToSummaryString()
			if !strings.Contains(result, tt.contains) {
				t.Errorf("FormatToSummaryString() = %q, missing %q", result, tt.contains)
			}
		})
	}
}

func TestNTRIPRequestIsReq(t *testing.T) {
	req := &NTRIPRequest{}
	if !req.IsReq() {
		t.Error("NTRIPRequest.IsReq() = false, want true")
	}
}

func TestNTRIPResponseIsReq(t *testing.T) {
	resp := &NTRIPResponse{}
	if resp.IsReq() {
		t.Error("NTRIPResponse.IsReq() = true, want false")
	}
}

func TestNTRIPRequestStreamId(t *testing.T) {
	req := &NTRIPRequest{}
	if req.StreamId() != 0 {
		t.Errorf("NTRIPRequest.StreamId() = %d, want 0", req.StreamId())
	}
}

// ==========================================================================
// NMEA message tests
// ==========================================================================

func TestNTRIPNMEASentenceFormatToString(t *testing.T) {
	nmea := &NTRIPNMEASentence{
		SentenceType: "GGA",
		Raw:          "$GPGGA,123456.00,5000.0000,N,00800.0000,E,1,12,1.0,100.0,M,0.0,M,,*XX",
	}

	result := nmea.FormatToString()
	if !strings.Contains(result, "GGA") {
		t.Errorf("FormatToString() missing sentence type")
	}
}

func TestNTRIPNMEASentenceIsReq(t *testing.T) {
	nmea := &NTRIPNMEASentence{}
	if !nmea.IsReq() {
		t.Error("NTRIPNMEASentence.IsReq() = false, want true (client backchannel)")
	}
}

// ==========================================================================
// NTRIPRTCMFrame tests
// ==========================================================================

func TestNTRIPRTCMFrameIsReq(t *testing.T) {
	frame := &NTRIPRTCMFrame{}
	if !frame.IsReq() {
		t.Error("NTRIPRTCMFrame.IsReq() = false, want true")
	}
}

// ==========================================================================
// NTRIPFilter tests
// ==========================================================================

func TestNTRIPFilterProtocol(t *testing.T) {
	f := NTRIPFilter{}
	if f.Protocol() != bpf.AgentTrafficProtocolTKProtocolNTRIP {
		t.Errorf("Protocol() = %d, want NTRIP (%d)",
			f.Protocol(), bpf.AgentTrafficProtocolTKProtocolNTRIP)
	}
}

func TestNTRIPFilterByProtocol(t *testing.T) {
	f := NTRIPFilter{}
	if !f.FilterByProtocol(bpf.AgentTrafficProtocolTKProtocolNTRIP) {
		t.Error("FilterByProtocol(NTRIP) = false, want true")
	}
	if f.FilterByProtocol(bpf.AgentTrafficProtocolTKProtocolHTTP) {
		t.Error("FilterByProtocol(HTTP) = true, want false")
	}
}

func TestNTRIPFilterByRequest(t *testing.T) {
	// No filters set
	f1 := NTRIPFilter{}
	if f1.FilterByRequest() {
		t.Error("FilterByRequest() with no filters = true, want false")
	}

	// Version filter set
	f2 := NTRIPFilter{TargetVersions: []NTRIPVersion{NTRIPv2}}
	if !f2.FilterByRequest() {
		t.Error("FilterByRequest() with version filter = false, want true")
	}

	// Mount filter set
	f3 := NTRIPFilter{TargetMountPoints: []string{"M1"}}
	if !f3.FilterByRequest() {
		t.Error("FilterByRequest() with mount filter = false, want true")
	}
}

func TestNTRIPFilterByResponse(t *testing.T) {
	// No filters set
	f1 := NTRIPFilter{}
	if f1.FilterByResponse() {
		t.Error("FilterByResponse() with no filters = true, want false")
	}

	// Status code filter set
	f2 := NTRIPFilter{StatusCodes: []int{200}}
	if !f2.FilterByResponse() {
		t.Error("FilterByResponse() with status filter = false, want true")
	}

	// ErrorsOnly set
	f3 := NTRIPFilter{ErrorsOnly: true}
	if !f3.FilterByResponse() {
		t.Error("FilterByResponse() with ErrorsOnly = false, want true")
	}
}

func TestNTRIPFilterVersion(t *testing.T) {
	f := NTRIPFilter{TargetVersions: []NTRIPVersion{NTRIPv2}}

	reqV1 := &NTRIPRequest{Version: NTRIPv1, Method: "GET"}
	reqV2 := &NTRIPRequest{Version: NTRIPv2, Method: "GET"}

	if f.Filter(reqV1, nil) {
		t.Error("v1 request should be filtered out when targeting v2")
	}
	if !f.Filter(reqV2, nil) {
		t.Error("v2 request should pass when targeting v2")
	}
}

func TestNTRIPFilterMountPoint(t *testing.T) {
	f := NTRIPFilter{TargetMountPoints: []string{"MOUNT01"}}

	reqMatch := &NTRIPRequest{Method: "GET", MountPoint: "MOUNT01"}
	reqNoMatch := &NTRIPRequest{Method: "GET", MountPoint: "MOUNT02"}

	if !f.Filter(reqMatch, nil) {
		t.Error("MOUNT01 request should pass filter")
	}
	if f.Filter(reqNoMatch, nil) {
		t.Error("MOUNT02 request should be filtered out")
	}
}

func TestNTRIPFilterErrorsOnly(t *testing.T) {
	f := NTRIPFilter{ErrorsOnly: true}

	// Normal request should be filtered out
	req := &NTRIPRequest{Method: "GET", Version: NTRIPv1}
	if f.Filter(req, nil) {
		t.Error("normal request should be filtered out with ErrorsOnly")
	}

	// Error response should pass
	resp := &NTRIPResponse{StatusCode: 401, Version: NTRIPv1}
	if !f.Filter(nil, resp) {
		t.Error("401 response should pass ErrorsOnly filter")
	}

	// Success response should be filtered out
	resp200 := &NTRIPResponse{StatusCode: 200, Version: NTRIPv1}
	if f.Filter(nil, resp200) {
		t.Error("200 response should be filtered out with ErrorsOnly")
	}
}

// ==========================================================================
// Helper function tests
// ==========================================================================

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/MOUNT01", "MOUNT01"},
		{"/MOUNT01 HTTP/1.1", "MOUNT01"},
		{"/", "/"},
		{"", "/"},
		{"  /MOUNT02  ", "MOUNT02"},
		{"/path/to/mount", "path/to/mount"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizePath(tt.input)
			if result != tt.expected {
				t.Errorf("normalizePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractHTTPStatusCode(t *testing.T) {
	tests := []struct {
		line     string
		expected int
	}{
		{"HTTP/1.1 200 OK", 200},
		{"HTTP/1.0 401 Unauthorized", 401},
		{"HTTP/1.1 404 Not Found", 404},
		{"ICY 200 OK", 200},
		{"SOURCETABLE 200 OK", 200},
		{"INVALID", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			result := extractHTTPStatusCode(tt.line)
			if result != tt.expected {
				t.Errorf("extractHTTPStatusCode(%q) = %d, want %d", tt.line, result, tt.expected)
			}
		})
	}
}

// ==========================================================================
// Parser mode detection tests
// ==========================================================================

func TestDetectMode(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		expected parserMode
	}{
		{
			name:     "GET request",
			buf:      []byte("GET /MOUNT01 HTTP/1.1\r\n"),
			expected: modeRequestSide,
		},
		{
			name:     "POST request",
			buf:      []byte("POST /MOUNT01 HTTP/1.1\r\n"),
			expected: modeRequestSide,
		},
		{
			name:     "SOURCE request",
			buf:      []byte("SOURCE secret /MOUNT01\r\n"),
			expected: modeRequestSide,
		},
		{
			name:     "HTTP response",
			buf:      []byte("HTTP/1.1 200 OK\r\n"),
			expected: modeResponseSide,
		},
		{
			name:     "ICY response",
			buf:      []byte("ICY 200 OK\r\n"),
			expected: modeResponseSide,
		},
		{
			name:     "SOURCETABLE response",
			buf:      []byte("SOURCETABLE 200 OK\r\n"),
			expected: modeResponseSide,
		},
		{
			name:     "ERROR response",
			buf:      []byte("ERROR - Bad Password\r\n"),
			expected: modeResponseSide,
		},
		{
			name:     "NMEA sentence",
			buf:      []byte("$GPGGA,123456*XX\r\n"),
			expected: modeRequestSide,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &NTRIPStreamParser{mode: modeAutoDetect}
			p.detectMode(tt.buf)
			if p.mode != tt.expected {
				t.Errorf("detectMode(%q) = %d, want %d", tt.buf, p.mode, tt.expected)
			}
		})
	}
}

// ==========================================================================
// ParsersMap registration test
// ==========================================================================

func TestParsersMapRegistration(t *testing.T) {
	creator, ok := protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolNTRIP]
	if !ok {
		t.Fatal("NTRIP parser not registered in ParsersMap")
	}

	parser := creator()
	if parser == nil {
		t.Fatal("ParsersMap creator returned nil")
	}

	// Verify it implements ProtocolStreamParser
	if _, ok := parser.(protocol.ProtocolStreamParser); !ok {
		t.Error("registered parser does not implement ProtocolStreamParser")
	}
}

// ==========================================================================
// SafeGet helper test (from sourcetable.go)
// ==========================================================================

func TestSafeGet(t *testing.T) {
	parts := []string{"a", "b", "c"}

	if safeGet(parts, 0) != "a" {
		t.Error("safeGet(parts, 0) should be 'a'")
	}
	if safeGet(parts, 2) != "c" {
		t.Error("safeGet(parts, 2) should be 'c'")
	}
	if safeGet(parts, 5) != "" {
		t.Error("safeGet(parts, 5) should be empty for out-of-bounds")
	}
}

// ==========================================================================
// parseRequest tests (via ParseStream)
// ==========================================================================

func TestParseStreamGETRequest(t *testing.T) {
	data := "GET /MOUNT01 HTTP/1.1\r\nHost: ntrip.example.com\r\nUser-Agent: NTRIP client/2.0\r\nNtrip-Version: Ntrip/2.0\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	req := result.ParsedMessages[0].(*NTRIPRequest)
	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	if req.MountPoint != "MOUNT01" {
		t.Errorf("MountPoint = %q, want MOUNT01", req.MountPoint)
	}
	if req.Version != NTRIPv2 {
		t.Errorf("Version = %v, want NTRIPv2", req.Version)
	}
	if req.SessionType != SessionTypeDataStream {
		t.Errorf("SessionType = %v, want DataStream", req.SessionType)
	}
	if !req.HasAuth {
		t.Error("HasAuth = false, want true")
	}
	if req.Username != "user" {
		t.Errorf("Username = %q, want 'user'", req.Username)
	}
	if req.Password != "pass" {
		t.Errorf("Password = %q, want 'pass'", req.Password)
	}
	if req.UserAgent != "NTRIP client/2.0" {
		t.Errorf("UserAgent = %q, want 'NTRIP client/2.0'", req.UserAgent)
	}
	if result.ReadBytes != len(data) {
		t.Errorf("ReadBytes = %d, want %d", result.ReadBytes, len(data))
	}
}

func TestParseStreamSOURCERequest(t *testing.T) {
	data := "SOURCE mypassword /TESTMOUNT\r\nSource-Agent: NTRIP test\r\n\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	req := result.ParsedMessages[0].(*NTRIPRequest)
	if req.Method != "SOURCE" {
		t.Errorf("Method = %q, want SOURCE", req.Method)
	}
	if req.SessionType != SessionTypeSourcePush {
		t.Errorf("SessionType = %v, want SourcePush", req.SessionType)
	}
	if req.Version != NTRIPv1 {
		t.Errorf("Version = %v, want NTRIPv1 (SOURCE is always v1)", req.Version)
	}
	if req.Password != "mypassword" {
		t.Errorf("Password = %q, want 'mypassword'", req.Password)
	}
	if req.MountPoint != "TESTMOUNT" {
		t.Errorf("MountPoint = %q, want 'TESTMOUNT'", req.MountPoint)
	}
}

func TestParseStreamSourcetableRequest(t *testing.T) {
	data := "GET / HTTP/1.1\r\nHost: ntrip.example.com\r\n\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	req := result.ParsedMessages[0].(*NTRIPRequest)
	if req.SessionType != SessionTypeSourcetable {
		t.Errorf("SessionType = %v, want Sourcetable", req.SessionType)
	}
}

func TestParseStreamRequestNeedsMoreData(t *testing.T) {
	// Incomplete request line (no CRLF)
	data := "GET /MOUNT01 HTTP"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.NeedsMoreData {
		t.Errorf("expected NeedsMoreData, got %v", result.ParseState)
	}
}

// ==========================================================================
// parseICYResponse tests
// ==========================================================================

func TestParseStreamICYResponse(t *testing.T) {
	data := "ICY 200 OK\r\n\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Response)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	resp := result.ParsedMessages[0].(*NTRIPResponse)
	if !resp.IsICY {
		t.Error("IsICY = false, want true")
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.SessionType != SessionTypeDataStream {
		t.Errorf("SessionType = %v, want DataStream", resp.SessionType)
	}
}

func TestParseStreamICYResponseNoBlankLine(t *testing.T) {
	// Some implementations send just "ICY 200 OK\r\n" without the blank line
	data := "ICY 200 OK\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Response)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
}

// ==========================================================================
// parseSourcetableResponse tests
// ==========================================================================

func TestParseStreamSourcetableResponse(t *testing.T) {
	data := "SOURCETABLE 200 OK\r\nContent-Type: text/plain\r\n\r\n" +
		"STR;MOUNT01;Test;RTCM 3.2;;2;GPS;NET;DEU;50.0;8.0;0;1;Gen;None;N;N;1200;\n" +
		"ENDSOURCETABLE\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Response)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	resp := result.ParsedMessages[0].(*NTRIPResponse)
	if !resp.HasSourcetable {
		t.Error("HasSourcetable = false, want true")
	}
	if resp.Sourcetable == nil {
		t.Fatal("Sourcetable is nil")
	}
	if len(resp.Sourcetable.Mounts) != 1 {
		t.Errorf("mounts = %d, want 1", len(resp.Sourcetable.Mounts))
	}
	if resp.SessionType != SessionTypeSourcetable {
		t.Errorf("SessionType = %v, want Sourcetable", resp.SessionType)
	}
}

func TestParseStreamSourcetableIncomplete(t *testing.T) {
	// Missing ENDSOURCETABLE
	data := "SOURCETABLE 200 OK\r\nContent-Type: text/plain\r\n\r\nSTR;M1;Test;\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Response)
	if result.ParseState != protocol.NeedsMoreData {
		t.Errorf("expected NeedsMoreData for incomplete sourcetable, got %v", result.ParseState)
	}
}

// ==========================================================================
// parseErrorResponse tests
// ==========================================================================

func TestParseStreamErrorResponse(t *testing.T) {
	data := "ERROR - Bad Password\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Response)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	resp := result.ParsedMessages[0].(*NTRIPResponse)
	if resp.StatusCode != 0 {
		t.Errorf("StatusCode = %d, want 0 for ERROR response", resp.StatusCode)
	}
	if !strings.Contains(resp.StatusLine, "Bad Password") {
		t.Errorf("StatusLine = %q, should contain 'Bad Password'", resp.StatusLine)
	}
}

// ==========================================================================
// parseHTTPResponse tests
// ==========================================================================

func TestParseStreamHTTPResponseV2(t *testing.T) {
	data := "HTTP/1.1 200 OK\r\nNtrip-Version: Ntrip/2.0\r\nContent-Type: gnss/data\r\n\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Response)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	resp := result.ParsedMessages[0].(*NTRIPResponse)
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestParseStreamHTTPResponse401(t *testing.T) {
	data := "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"/MOUNT\"\r\nContent-Length: 0\r\n\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Response)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	resp := result.ParsedMessages[0].(*NTRIPResponse)
	if resp.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
}

// ==========================================================================
// parseNMEA tests
// ==========================================================================

func TestParseStreamNMEASentence(t *testing.T) {
	data := "$GPGGA,123456.00,5000.0000,N,00800.0000,E,1,12,1.0,100.0,M,0.0,M,,*6A\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}
	p.mode = modeRequestSide // Force request-side mode

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	nmea := result.ParsedMessages[0].(*NTRIPNMEASentence)
	if nmea.SentenceType != "GGA" {
		t.Errorf("SentenceType = %q, want GGA", nmea.SentenceType)
	}
	if !strings.Contains(nmea.Raw, "GPGGA") {
		t.Errorf("Raw = %q, should contain GPGGA", nmea.Raw)
	}
	// GGA-specific parsed fields
	if !nmea.GGAParsed {
		t.Fatal("GGAParsed = false, want true")
	}
	if nmea.UTCTime != "123456.00" {
		t.Errorf("UTCTime = %q, want '123456.00'", nmea.UTCTime)
	}
	// 5000.0000 N → 50 + 0/60 = 50.0
	if nmea.Latitude < 49.99 || nmea.Latitude > 50.01 {
		t.Errorf("Latitude = %.6f, want ~50.0", nmea.Latitude)
	}
	// 00800.0000 E → 8 + 0/60 = 8.0
	if nmea.Longitude < 7.99 || nmea.Longitude > 8.01 {
		t.Errorf("Longitude = %.6f, want ~8.0", nmea.Longitude)
	}
	if nmea.FixQuality != 1 {
		t.Errorf("FixQuality = %d, want 1 (GPS)", nmea.FixQuality)
	}
	if nmea.NumSatellites != 12 {
		t.Errorf("NumSatellites = %d, want 12", nmea.NumSatellites)
	}
	if nmea.HDOP != 1.0 {
		t.Errorf("HDOP = %.1f, want 1.0", nmea.HDOP)
	}
	if nmea.Altitude != 100.0 {
		t.Errorf("Altitude = %.1f, want 100.0", nmea.Altitude)
	}
}

func TestParseStreamNMEAInvalidNoChecksum(t *testing.T) {
	// Missing '*' checksum marker
	data := "$GPGGA,123456,no_checksum\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}
	p.mode = modeRequestSide

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Invalid {
		t.Errorf("expected Invalid for NMEA without checksum, got %v", result.ParseState)
	}
}

// ==========================================================================
// RTCM frame delegation test
// ==========================================================================

func TestParseStreamRTCMFrameInNTRIP(t *testing.T) {
	// Build a valid RTCM frame
	frame := make([]byte, 3+10+3)
	frame[0] = 0xD3
	frame[1] = 0x00
	frame[2] = 10 // length=10
	frame[3] = byte(1074 >> 4)
	frame[4] = byte((1074 & 0x0F) << 4)
	crc := rtcm.CRC24Q(frame[:13])
	frame[13] = byte(crc >> 16)
	frame[14] = byte(crc >> 8)
	frame[15] = byte(crc)

	sb := makeStreamBuffer(frame)
	p := &NTRIPStreamParser{}
	p.mode = modeResponseSide // Force response-side mode

	result := p.ParseStream(sb, protocol.Response)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	ntripFrame := result.ParsedMessages[0].(*NTRIPRTCMFrame)
	if ntripFrame.Inner.MessageType != 1074 {
		t.Errorf("Inner.MessageType = %d, want 1074", ntripFrame.Inner.MessageType)
	}
}

// ==========================================================================
// Match tests
// ==========================================================================

func TestNTRIPMatchHandshakePairing(t *testing.T) {
	p := &NTRIPStreamParser{}

	req := &NTRIPRequest{Method: "GET", MountPoint: "M1", Version: NTRIPv2}
	resp := &NTRIPResponse{StatusCode: 200, StatusLine: "HTTP/1.1 200 OK", Version: NTRIPv2}

	reqQueue := protocol.ParsedMessageQueue{req}
	respQueue := protocol.ParsedMessageQueue{resp}
	reqStreams := map[protocol.StreamId]*protocol.ParsedMessageQueue{0: &reqQueue}
	respStreams := map[protocol.StreamId]*protocol.ParsedMessageQueue{0: &respQueue}

	records := p.Match(reqStreams, respStreams)
	if len(records) != 1 {
		t.Fatalf("expected 1 paired record, got %d", len(records))
	}
	if records[0].Req == nil || records[0].Resp == nil {
		t.Error("paired record should have both Req and Resp")
	}
	if records[0].ResponseStatus != protocol.SuccessStatus {
		t.Errorf("ResponseStatus = %v, want SuccessStatus", records[0].ResponseStatus)
	}
}

func TestNTRIPMatchICYResponseStatus(t *testing.T) {
	p := &NTRIPStreamParser{}

	req := &NTRIPRequest{Method: "GET", MountPoint: "M1", Version: NTRIPv1}
	resp := &NTRIPResponse{StatusCode: 200, StatusLine: "ICY 200 OK", IsICY: true, Version: NTRIPv1}

	reqQueue := protocol.ParsedMessageQueue{req}
	respQueue := protocol.ParsedMessageQueue{resp}
	reqStreams := map[protocol.StreamId]*protocol.ParsedMessageQueue{0: &reqQueue}
	respStreams := map[protocol.StreamId]*protocol.ParsedMessageQueue{0: &respQueue}

	records := p.Match(reqStreams, respStreams)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].ResponseStatus != protocol.SuccessStatus {
		t.Errorf("ICY response should produce SuccessStatus, got %v", records[0].ResponseStatus)
	}
}

func TestNTRIPMatchUnpairedRTCMFrames(t *testing.T) {
	p := &NTRIPStreamParser{}

	// Handshake + remaining RTCM frames
	req := &NTRIPRequest{Method: "GET", MountPoint: "M1"}
	resp := &NTRIPResponse{StatusCode: 200, IsICY: true}
	rtcmFrame := &NTRIPRTCMFrame{Inner: &rtcm.RTCMFrame{MessageType: 1074}}

	reqQueue := protocol.ParsedMessageQueue{req}
	respQueue := protocol.ParsedMessageQueue{resp, rtcmFrame}
	reqStreams := map[protocol.StreamId]*protocol.ParsedMessageQueue{0: &reqQueue}
	respStreams := map[protocol.StreamId]*protocol.ParsedMessageQueue{0: &respQueue}

	records := p.Match(reqStreams, respStreams)
	// 1 paired (req+resp) + 1 unpaired (rtcm frame)
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	// Second record should be the unpaired RTCM frame
	if records[1].Resp == nil {
		t.Error("unpaired RTCM frame should be in Req field")
	}
}

func TestNTRIPMatchEmptyQueues(t *testing.T) {
	p := &NTRIPStreamParser{}
	reqStreams := map[protocol.StreamId]*protocol.ParsedMessageQueue{}
	respStreams := map[protocol.StreamId]*protocol.ParsedMessageQueue{}

	records := p.Match(reqStreams, respStreams)
	if len(records) != 0 {
		t.Errorf("expected 0 records for empty queues, got %d", len(records))
	}
}

// ==========================================================================
// Additional NTRIPFilter tests
// ==========================================================================

func TestNTRIPFilterSessionType(t *testing.T) {
	f := NTRIPFilter{TargetSessionTypes: []NTRIPSessionType{SessionTypeDataStream}}

	dataReq := &NTRIPRequest{Method: "GET", SessionType: SessionTypeDataStream, Version: NTRIPv1}
	tableReq := &NTRIPRequest{Method: "GET", SessionType: SessionTypeSourcetable, Version: NTRIPv1}

	if !f.Filter(dataReq, nil) {
		t.Error("DataStream request should pass")
	}
	if f.Filter(tableReq, nil) {
		t.Error("Sourcetable request should be rejected")
	}
}

func TestNTRIPFilterMethod(t *testing.T) {
	f := NTRIPFilter{TargetMethods: []string{"SOURCE"}}

	sourceReq := &NTRIPRequest{Method: "SOURCE", Version: NTRIPv1}
	getReq := &NTRIPRequest{Method: "GET", Version: NTRIPv1}

	if !f.Filter(sourceReq, nil) {
		t.Error("SOURCE request should pass method filter")
	}
	if f.Filter(getReq, nil) {
		t.Error("GET request should be rejected by SOURCE-only filter")
	}
}

func TestNTRIPFilterCRCErrorsOnly(t *testing.T) {
	f := NTRIPFilter{CRCErrorsOnly: true}

	validFrame := &NTRIPRTCMFrame{Inner: &rtcm.RTCMFrame{MessageType: 1074, CRCValid: true}}
	invalidFrame := &NTRIPRTCMFrame{Inner: &rtcm.RTCMFrame{MessageType: 1074, CRCValid: false}}

	if f.Filter(validFrame, nil) {
		t.Error("CRC-valid frame should be rejected with CRCErrorsOnly")
	}
	if !f.Filter(invalidFrame, nil) {
		t.Error("CRC-invalid frame should pass with CRCErrorsOnly")
	}
}

func TestNTRIPFilterNMEASentence(t *testing.T) {
	nmea := &NTRIPNMEASentence{SentenceType: "GGA", Raw: "$GPGGA*XX"}

	// Without ErrorsOnly, NMEA should pass
	f1 := NTRIPFilter{}
	if !f1.Filter(nmea, nil) {
		t.Error("NMEA should pass without ErrorsOnly")
	}

	// With ErrorsOnly, NMEA should be rejected
	f2 := NTRIPFilter{ErrorsOnly: true}
	if f2.Filter(nmea, nil) {
		t.Error("NMEA should be rejected with ErrorsOnly")
	}
}

func TestNTRIPFilterStatusCodes(t *testing.T) {
	f := NTRIPFilter{StatusCodes: []int{401}}

	resp401 := &NTRIPResponse{StatusCode: 401, Version: NTRIPv1}
	resp200 := &NTRIPResponse{StatusCode: 200, Version: NTRIPv1}

	if !f.Filter(nil, resp401) {
		t.Error("401 response should pass StatusCodes filter")
	}
	if f.Filter(nil, resp200) {
		t.Error("200 response should be rejected by 401-only filter")
	}
}

// ==========================================================================
// parseBasicAuth tests
// ==========================================================================

func TestParseBasicAuth_Valid(t *testing.T) {
	// base64("admin:secret123") = "YWRtaW46c2VjcmV0MTIz"
	u, p, ok := parseBasicAuth("Basic YWRtaW46c2VjcmV0MTIz")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if u != "admin" {
		t.Errorf("username = %q, want 'admin'", u)
	}
	if p != "secret123" {
		t.Errorf("password = %q, want 'secret123'", p)
	}
}

func TestParseBasicAuth_EmptyPassword(t *testing.T) {
	// base64("user:") = "dXNlcjo="
	u, p, ok := parseBasicAuth("Basic dXNlcjo=")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if u != "user" {
		t.Errorf("username = %q, want 'user'", u)
	}
	if p != "" {
		t.Errorf("password = %q, want empty", p)
	}
}

func TestParseBasicAuth_SpecialChars(t *testing.T) {
	// base64("user@host:p@ss:w0rd") = "dXNlckBob3N0OnBAc3M6dzByZA=="
	u, p, ok := parseBasicAuth("Basic dXNlckBob3N0OnBAc3M6dzByZA==")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if u != "user@host" {
		t.Errorf("username = %q, want 'user@host'", u)
	}
	if p != "p@ss:w0rd" {
		t.Errorf("password = %q, want 'p@ss:w0rd'", p)
	}
}

func TestParseBasicAuth_NotBasic(t *testing.T) {
	_, _, ok := parseBasicAuth("Bearer token123")
	if ok {
		t.Error("expected ok=false for non-Basic auth")
	}
}

func TestParseBasicAuth_InvalidBase64(t *testing.T) {
	_, _, ok := parseBasicAuth("Basic !!!invalid!!!")
	if ok {
		t.Error("expected ok=false for invalid base64")
	}
}

func TestParseBasicAuth_NoColon(t *testing.T) {
	// base64("nopasswordhere") = "bm9wYXNzd29yZGhlcmU="
	_, _, ok := parseBasicAuth("Basic bm9wYXNzd29yZGhlcmU=")
	if ok {
		t.Error("expected ok=false when no colon in decoded string")
	}
}

// ==========================================================================
// Auth extraction in parseRequest
// ==========================================================================

func TestParseStreamGETRequestNoAuth(t *testing.T) {
	data := "GET /MOUNT01 HTTP/1.1\r\nHost: ntrip.example.com\r\n\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	req := result.ParsedMessages[0].(*NTRIPRequest)
	if req.HasAuth {
		t.Error("HasAuth = true, want false (no Authorization header)")
	}
	if req.Username != "" {
		t.Errorf("Username = %q, want empty", req.Username)
	}
	if req.Password != "" {
		t.Errorf("Password = %q, want empty", req.Password)
	}
}

func TestParseStreamSOURCERequestPasswordOnly(t *testing.T) {
	// SOURCE method: password in request line, no Authorization header
	data := "SOURCE s3cret /MOUNT01\r\nSource-Agent: NTRIP NTRIPSourceAgentV1.0\r\n\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	req := result.ParsedMessages[0].(*NTRIPRequest)
	if req.Password != "s3cret" {
		t.Errorf("Password = %q, want 's3cret'", req.Password)
	}
	if req.Username != "" {
		t.Errorf("Username = %q, want empty (SOURCE has no username in request line)", req.Username)
	}
}

func TestParseStreamGETRequestWithBasicAuthChinese(t *testing.T) {
	// base64("用户:密码") = "55So5oi3OuWtpuS5oA=="
	data := "GET /RTK HTTP/1.1\r\nHost: caster.example.com\r\nAuthorization: Basic 55So5oi3OuWtpuS5oA==\r\n\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	req := result.ParsedMessages[0].(*NTRIPRequest)
	if req.Username != "用户" {
		t.Errorf("Username = %q, want '用户'", req.Username)
	}
	if req.Password != "密码" {
		t.Errorf("Password = %q, want '密码'", req.Password)
	}
}

// ==========================================================================
// GGA parsing tests
// ==========================================================================

func TestParseGGASentence_SouthernHemisphere(t *testing.T) {
	// GGA in southern hemisphere (S) and western hemisphere (W)
	data := "$GNGGA,083015.00,3730.5000,S,14500.2500,W,4,18,0.8,50.5,M,-10.0,M,1.0,0003*4F\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}
	p.mode = modeRequestSide

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	nmea := result.ParsedMessages[0].(*NTRIPNMEASentence)
	if !nmea.GGAParsed {
		t.Fatal("GGAParsed = false, want true")
	}
	// 3730.5000 S → -(37 + 30.5/60) = -37.508333...
	if nmea.Latitude > 0 {
		t.Errorf("Latitude = %.6f, should be negative (Southern hemisphere)", nmea.Latitude)
	}
	if nmea.Latitude < -37.52 || nmea.Latitude > -37.50 {
		t.Errorf("Latitude = %.6f, want ~-37.508", nmea.Latitude)
	}
	// 14500.2500 W → -(145 + 0.25/60) = -145.004166...
	if nmea.Longitude > 0 {
		t.Errorf("Longitude = %.6f, should be negative (Western hemisphere)", nmea.Longitude)
	}
	if nmea.Longitude < -145.01 || nmea.Longitude > -145.00 {
		t.Errorf("Longitude = %.6f, want ~-145.004", nmea.Longitude)
	}
	if nmea.FixQuality != 4 {
		t.Errorf("FixQuality = %d, want 4 (RTK-Fixed)", nmea.FixQuality)
	}
	if nmea.NumSatellites != 18 {
		t.Errorf("NumSatellites = %d, want 18", nmea.NumSatellites)
	}
	if nmea.Altitude != 50.5 {
		t.Errorf("Altitude = %.1f, want 50.5", nmea.Altitude)
	}
	// DiffAge = 1.0 (field 12 in the sentence)
	if nmea.DiffAge != 1.0 {
		t.Errorf("DiffAge = %f, want 1.0", nmea.DiffAge)
	}
	// DiffStationID = "0003" (field 13 in the sentence)
	if nmea.DiffStationID != "0003" {
		t.Errorf("DiffStationID = %q, want 0003", nmea.DiffStationID)
	}
}

func TestParseGGASentence_NoFix(t *testing.T) {
	// GGA with fix quality 0 (no fix) and empty coordinate fields
	data := "$GPGGA,000000.00,,,,,0,00,,,,,,, *65\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}
	p.mode = modeRequestSide

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	nmea := result.ParsedMessages[0].(*NTRIPNMEASentence)
	if !nmea.GGAParsed {
		t.Fatal("GGAParsed = false, want true")
	}
	if nmea.FixQuality != 0 {
		t.Errorf("FixQuality = %d, want 0 (Invalid/No fix)", nmea.FixQuality)
	}
	if nmea.NumSatellites != 0 {
		t.Errorf("NumSatellites = %d, want 0", nmea.NumSatellites)
	}
	// DiffAge should be -1 (not present in this sentence)
	if nmea.DiffAge != -1 {
		t.Errorf("DiffAge = %f, want -1 (not present)", nmea.DiffAge)
	}
	if nmea.DiffStationID != "" {
		t.Errorf("DiffStationID = %q, want empty", nmea.DiffStationID)
	}
}

func TestParseNMEANonGGA_NoGGAParsing(t *testing.T) {
	// RMC sentence should not have GGA fields parsed
	data := "$GPRMC,123456.00,A,5000.0000,N,00800.0000,E,1.0,90.0,010124,,*2A\r\n"
	sb := makeStreamBuffer([]byte(data))
	p := &NTRIPStreamParser{}
	p.mode = modeRequestSide

	result := p.ParseStream(sb, protocol.Request)
	if result.ParseState != protocol.Success {
		t.Fatalf("expected Success, got %v", result.ParseState)
	}
	nmea := result.ParsedMessages[0].(*NTRIPNMEASentence)
	if nmea.SentenceType != "RMC" {
		t.Errorf("SentenceType = %q, want RMC", nmea.SentenceType)
	}
	if nmea.GGAParsed {
		t.Error("GGAParsed = true for RMC sentence, want false")
	}
}

// ==========================================================================
// parseNMEACoord tests
// ==========================================================================

func TestParseNMEACoord(t *testing.T) {
	tests := []struct {
		coord    string
		dir      string
		expected float64
	}{
		{"5000.0000", "N", 50.0},
		{"5000.0000", "S", -50.0},
		{"00800.0000", "E", 8.0},
		{"00800.0000", "W", -8.0},
		{"3730.5000", "N", 37.508333},
		{"12130.0000", "E", 121.5},
	}

	for _, tt := range tests {
		result, err := parseNMEACoord(tt.coord, tt.dir)
		if err != nil {
			t.Errorf("parseNMEACoord(%q, %q) error: %v", tt.coord, tt.dir, err)
			continue
		}
		diff := result - tt.expected
		if diff < -0.001 || diff > 0.001 {
			t.Errorf("parseNMEACoord(%q, %q) = %.6f, want ~%.6f",
				tt.coord, tt.dir, result, tt.expected)
		}
	}
}

func TestParseNMEACoord_Empty(t *testing.T) {
	_, err := parseNMEACoord("", "N")
	if err == nil {
		t.Error("expected error for empty coordinate")
	}
}

func TestParseNMEACoord_NoDot(t *testing.T) {
	_, err := parseNMEACoord("50000000", "N")
	if err == nil {
		t.Error("expected error for coordinate without decimal point")
	}
}

// ==========================================================================
// fixQualityName tests
// ==========================================================================

func TestFixQualityName(t *testing.T) {
	tests := []struct {
		q    int
		name string
	}{
		{0, "Invalid"},
		{1, "GPS"},
		{2, "DGPS"},
		{3, "PPS"},
		{4, "RTK-Fixed"},
		{5, "RTK-Float"},
		{6, "Estimated"},
		{7, "Manual"},
		{8, "Simulation"},
		{99, "Unknown"},
	}
	for _, tt := range tests {
		got := fixQualityName(tt.q)
		if got != tt.name {
			t.Errorf("fixQualityName(%d) = %q, want %q", tt.q, got, tt.name)
		}
	}
}

// ==========================================================================
// NTRIPNMEASentence FormatToString with GGA data
// ==========================================================================

func TestNMEASentenceFormatToString_GGA(t *testing.T) {
	nmea := &NTRIPNMEASentence{
		FrameBase:     protocol.NewFrameBase(1000, 80, 0),
		SentenceType:  "GGA",
		Raw:           "$GPGGA,123456.00,5000.0000,N,00800.0000,E,1,12,1.0,100.0,M,0.0,M,,*6A",
		GGAParsed:     true,
		UTCTime:       "123456.00",
		Latitude:      50.0,
		Longitude:     8.0,
		FixQuality:    4,
		NumSatellites: 18,
		HDOP:          0.8,
		Altitude:      50.5,
	}

	s := nmea.FormatToString()
	if !strings.Contains(s, "Position:") {
		t.Error("FormatToString should contain 'Position:' for GGA")
	}
	if !strings.Contains(s, "RTK-Fixed") {
		t.Error("FormatToString should contain fix quality name 'RTK-Fixed'")
	}
	if !strings.Contains(s, "Satellites:") {
		t.Error("FormatToString should contain 'Satellites:'")
	}
}

func TestNMEASentenceFormatToString_NonGGA(t *testing.T) {
	nmea := &NTRIPNMEASentence{
		FrameBase:    protocol.NewFrameBase(1000, 60, 0),
		SentenceType: "RMC",
		Raw:          "$GPRMC,123456.00,A,...",
	}

	s := nmea.FormatToString()
	if strings.Contains(s, "Position:") {
		t.Error("FormatToString should NOT contain 'Position:' for non-GGA")
	}
}

func TestNMEASentenceFormatToSummaryString_GGA(t *testing.T) {
	nmea := &NTRIPNMEASentence{
		FrameBase:     protocol.NewFrameBase(1000, 80, 0),
		SentenceType:  "GGA",
		Raw:           "$GPGGA,...",
		GGAParsed:     true,
		Latitude:      50.0083,
		Longitude:     8.0042,
		FixQuality:    4,
		NumSatellites: 18,
	}

	s := nmea.FormatToSummaryString()
	if !strings.Contains(s, "GGA") {
		t.Error("SummaryString should contain 'GGA'")
	}
	if !strings.Contains(s, "fix=4") {
		t.Error("SummaryString should contain 'fix=4'")
	}
	if !strings.Contains(s, "sats=18") {
		t.Error("SummaryString should contain 'sats=18'")
	}
}

// ==========================================================================
// NTRIPFilter: TargetUsernames
// ==========================================================================

func TestNTRIPFilterUsernames(t *testing.T) {
	f := NTRIPFilter{TargetUsernames: []string{"admin", "operator"}}

	reqAdmin := &NTRIPRequest{Username: "admin", SessionType: SessionTypeDataStream}
	reqOperator := &NTRIPRequest{Username: "operator", SessionType: SessionTypeDataStream}
	reqOther := &NTRIPRequest{Username: "guest", SessionType: SessionTypeDataStream}
	reqNoAuth := &NTRIPRequest{SessionType: SessionTypeDataStream}

	if !f.Filter(reqAdmin, nil) {
		t.Error("admin request should pass username filter")
	}
	if !f.Filter(reqOperator, nil) {
		t.Error("operator request should pass username filter")
	}
	if f.Filter(reqOther, nil) {
		t.Error("guest request should be rejected by admin/operator filter")
	}
	if f.Filter(reqNoAuth, nil) {
		t.Error("no-auth request should be rejected by username filter")
	}
}

// ==========================================================================
// NTRIPFilter: GGAOnly
// ==========================================================================

func TestNTRIPFilterGGAOnly(t *testing.T) {
	f := NTRIPFilter{GGAOnly: true}

	gga := &NTRIPNMEASentence{SentenceType: "GGA", Raw: "$GPGGA,..."}
	rmc := &NTRIPNMEASentence{SentenceType: "RMC", Raw: "$GPRMC,..."}
	req := &NTRIPRequest{SessionType: SessionTypeDataStream}

	if !f.Filter(gga, nil) {
		t.Error("GGA sentence should pass GGAOnly filter")
	}
	if f.Filter(rmc, nil) {
		t.Error("RMC sentence should be rejected by GGAOnly filter")
	}
	// Non-NMEA messages: GGAOnly doesn't affect RTCM frames or handshake
	if !f.Filter(req, nil) {
		t.Error("NTRIPRequest should not be affected by GGAOnly")
	}
}

func TestNTRIPFilterGGAOnly_FilterByRequest(t *testing.T) {
	f := NTRIPFilter{GGAOnly: true}
	if !f.FilterByRequest() {
		t.Error("GGAOnly should make FilterByRequest return true")
	}
}
