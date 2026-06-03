package analysis

import (
	"net"
	"testing"

	anc "kyanos/agent/analysis/common"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/ntrip"
	"kyanos/agent/protocol/rtcm"
	"kyanos/bpf"
	"kyanos/common"
)

// --- test helpers ---

func makeConnDesc(proto uint32) common.ConnDesc {
	return common.ConnDesc{
		LocalAddr:  net.IPv4(127, 0, 0, 1),
		LocalPort:  8080,
		RemoteAddr: net.IPv4(10, 0, 0, 1),
		RemotePort: 2101,
		Pid:        1234,
		Protocol:   proto,
		Side:       common.ClientSide,
	}
}

func makeRecord(req protocol.ParsedMessage, resp protocol.ParsedMessage) *protocol.Record {
	return protocol.NewRecord(req, resp)
}

func makeAnnotatedRecord(req protocol.ParsedMessage, resp protocol.ParsedMessage, proto uint32) *anc.AnnotatedRecord {
	return &anc.AnnotatedRecord{
		ConnDesc: makeConnDesc(proto),
		Record:   *makeRecord(req, resp),
	}
}

// --- stub non-GNSS message for fallback tests ---

type stubMessage struct {
	protocol.FrameBase
	isReq bool
}

func (s *stubMessage) IsReq() bool                   { return s.isReq }
func (s *stubMessage) StreamId() protocol.StreamId   { return 0 }
func (s *stubMessage) FormatToString() string        { return "stub" }
func (s *stubMessage) FormatToSummaryString() string { return "stub" }

// --- RTCM Message Type classifier ---

func TestClassfier_RTCMMessageType_DirectFrame(t *testing.T) {
	frame := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 30, 0),
		Preamble:      0xD3,
		MessageType:   1077,
		Constellation: rtcm.ConstellationGPS,
		MSMClass:      rtcm.MSM7,
		CRCValid:      true,
		TotalLen:      30,
	}
	ar := makeAnnotatedRecord(frame, nil, uint32(bpf.AgentTrafficProtocolTKProtocolRTCM))

	c, ok := classfierMap[anc.RTCMMessageType]
	if !ok {
		t.Fatal("RTCMMessageType classifier not registered")
	}
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "1077" {
		t.Errorf("expected classId '1077', got '%s'", id)
	}
}

func TestClassfier_RTCMMessageType_NTRIPWrapped(t *testing.T) {
	inner := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 20, 0),
		MessageType:   1005,
		Constellation: rtcm.ConstellationUnknown,
		CRCValid:      true,
		TotalLen:      20,
	}
	wrapped := &ntrip.NTRIPRTCMFrame{
		FrameBase: protocol.NewFrameBase(1000, 20, 0),
		Inner:     inner,
	}
	ar := makeAnnotatedRecord(wrapped, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	c := classfierMap[anc.RTCMMessageType]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "1005" {
		t.Errorf("expected classId '1005', got '%s'", id)
	}
}

func TestClassfier_RTCMMessageType_NotRTCM(t *testing.T) {
	stub := &stubMessage{isReq: true}
	ar := makeAnnotatedRecord(stub, nil, 0)

	c := classfierMap[anc.RTCMMessageType]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "_not_a_rtcm_frame_" {
		t.Errorf("expected '_not_a_rtcm_frame_', got '%s'", id)
	}
}

// --- RTCM Constellation classifier ---

func TestClassfier_RTCMConstellation_DirectFrame(t *testing.T) {
	frame := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 30, 0),
		MessageType:   1085,
		Constellation: rtcm.ConstellationGLONASS,
		MSMClass:      rtcm.MSM5,
		CRCValid:      true,
		TotalLen:      30,
	}
	ar := makeAnnotatedRecord(frame, nil, uint32(bpf.AgentTrafficProtocolTKProtocolRTCM))

	c := classfierMap[anc.RTCMConstellation]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "GLONASS" {
		t.Errorf("expected 'GLONASS', got '%s'", id)
	}
}

func TestClassfier_RTCMConstellation_NTRIPWrapped(t *testing.T) {
	inner := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 20, 0),
		MessageType:   1094,
		Constellation: rtcm.ConstellationGalileo,
		CRCValid:      true,
		TotalLen:      20,
	}
	wrapped := &ntrip.NTRIPRTCMFrame{
		FrameBase: protocol.NewFrameBase(1000, 20, 0),
		Inner:     inner,
	}
	ar := makeAnnotatedRecord(wrapped, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	c := classfierMap[anc.RTCMConstellation]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "Galileo" {
		t.Errorf("expected 'Galileo', got '%s'", id)
	}
}

func TestClassfier_RTCMConstellation_NotRTCM(t *testing.T) {
	stub := &stubMessage{isReq: true}
	ar := makeAnnotatedRecord(stub, nil, 0)

	c := classfierMap[anc.RTCMConstellation]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "_not_a_rtcm_frame_" {
		t.Errorf("expected '_not_a_rtcm_frame_', got '%s'", id)
	}
}

// --- NTRIP MountPoint classifier ---

func TestClassfier_NTRIPMountPoint(t *testing.T) {
	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 100, 0),
		Method:      "GET",
		Path:        "/RTK_DATA",
		Version:     ntrip.NTRIPv2,
		SessionType: ntrip.SessionTypeDataStream,
		MountPoint:  "RTK_DATA",
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	c := classfierMap[anc.NTRIPMountPoint]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "RTK_DATA" {
		t.Errorf("expected 'RTK_DATA', got '%s'", id)
	}
}

func TestClassfier_NTRIPMountPoint_NotNTRIP(t *testing.T) {
	stub := &stubMessage{isReq: true}
	ar := makeAnnotatedRecord(stub, nil, 0)

	c := classfierMap[anc.NTRIPMountPoint]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "_not_a_ntrip_req_" {
		t.Errorf("expected '_not_a_ntrip_req_', got '%s'", id)
	}
}

// --- NTRIP SessionType classifier ---

func TestClassfier_NTRIPSessionType_DataStream(t *testing.T) {
	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 100, 0),
		Method:      "GET",
		Path:        "/BASE01",
		Version:     ntrip.NTRIPv1,
		SessionType: ntrip.SessionTypeDataStream,
		MountPoint:  "BASE01",
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	c := classfierMap[anc.NTRIPSessionType]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "DataStream" {
		t.Errorf("expected 'DataStream', got '%s'", id)
	}
}

func TestClassfier_NTRIPSessionType_SourcePush(t *testing.T) {
	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 80, 0),
		Method:      "SOURCE",
		Path:        "/PUSH01",
		Version:     ntrip.NTRIPv1,
		SessionType: ntrip.SessionTypeSourcePush,
		MountPoint:  "PUSH01",
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	c := classfierMap[anc.NTRIPSessionType]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "SourcePush" {
		t.Errorf("expected 'SourcePush', got '%s'", id)
	}
}

func TestClassfier_NTRIPSessionType_Sourcetable(t *testing.T) {
	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 50, 0),
		Method:      "GET",
		Path:        "/",
		Version:     ntrip.NTRIPv2,
		SessionType: ntrip.SessionTypeSourcetable,
		MountPoint:  "",
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	c := classfierMap[anc.NTRIPSessionType]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "Sourcetable" {
		t.Errorf("expected 'Sourcetable', got '%s'", id)
	}
}

func TestClassfier_NTRIPSessionType_NotNTRIP(t *testing.T) {
	stub := &stubMessage{isReq: true}
	ar := makeAnnotatedRecord(stub, nil, 0)

	c := classfierMap[anc.NTRIPSessionType]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "_not_a_ntrip_req_" {
		t.Errorf("expected '_not_a_ntrip_req_', got '%s'", id)
	}
}

// --- Human-readable classifier tests ---

func TestHumanReadable_RTCMMessageType_Direct(t *testing.T) {
	frame := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 30, 0),
		MessageType:   1077,
		Constellation: rtcm.ConstellationGPS,
		CRCValid:      true,
		TotalLen:      30,
	}
	ar := makeAnnotatedRecord(frame, nil, uint32(bpf.AgentTrafficProtocolTKProtocolRTCM))

	f, ok := classIdHumanReadableMap[anc.RTCMMessageType]
	if !ok {
		t.Fatal("RTCMMessageType human-readable func not registered")
	}
	result := f(ar)
	expected := "1077 (GPS MSM7)"
	if result != expected {
		t.Errorf("expected '%s', got '%s'", expected, result)
	}
}

func TestHumanReadable_RTCMMessageType_NTRIPWrapped(t *testing.T) {
	inner := &rtcm.RTCMFrame{
		FrameBase:   protocol.NewFrameBase(1000, 20, 0),
		MessageType: 1005,
		CRCValid:    true,
		TotalLen:    20,
	}
	wrapped := &ntrip.NTRIPRTCMFrame{
		FrameBase: protocol.NewFrameBase(1000, 20, 0),
		Inner:     inner,
	}
	ar := makeAnnotatedRecord(wrapped, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	f := classIdHumanReadableMap[anc.RTCMMessageType]
	result := f(ar)
	expected := "1005 (Station ARP Coords)"
	if result != expected {
		t.Errorf("expected '%s', got '%s'", expected, result)
	}
}

func TestHumanReadable_RTCMMessageType_NotRTCM(t *testing.T) {
	stub := &stubMessage{isReq: true}
	ar := makeAnnotatedRecord(stub, nil, 0)

	f := classIdHumanReadableMap[anc.RTCMMessageType]
	result := f(ar)
	if result != "_not_a_rtcm_frame_" {
		t.Errorf("expected '_not_a_rtcm_frame_', got '%s'", result)
	}
}

func TestHumanReadable_RTCMConstellation_Direct(t *testing.T) {
	frame := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 30, 0),
		MessageType:   1124,
		Constellation: rtcm.ConstellationBeiDou,
		CRCValid:      true,
		TotalLen:      30,
	}
	ar := makeAnnotatedRecord(frame, nil, uint32(bpf.AgentTrafficProtocolTKProtocolRTCM))

	f := classIdHumanReadableMap[anc.RTCMConstellation]
	result := f(ar)
	if result != "BeiDou" {
		t.Errorf("expected 'BeiDou', got '%s'", result)
	}
}

func TestHumanReadable_RTCMConstellation_NTRIPWrapped(t *testing.T) {
	inner := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 20, 0),
		MessageType:   1137,
		Constellation: rtcm.ConstellationNavIC,
		CRCValid:      true,
		TotalLen:      20,
	}
	wrapped := &ntrip.NTRIPRTCMFrame{
		FrameBase: protocol.NewFrameBase(1000, 20, 0),
		Inner:     inner,
	}
	ar := makeAnnotatedRecord(wrapped, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	f := classIdHumanReadableMap[anc.RTCMConstellation]
	result := f(ar)
	if result != "NavIC" {
		t.Errorf("expected 'NavIC', got '%s'", result)
	}
}

func TestHumanReadable_RTCMConstellation_NotRTCM(t *testing.T) {
	stub := &stubMessage{isReq: true}
	ar := makeAnnotatedRecord(stub, nil, 0)

	f := classIdHumanReadableMap[anc.RTCMConstellation]
	result := f(ar)
	if result != "_not_a_rtcm_frame_" {
		t.Errorf("expected '_not_a_rtcm_frame_', got '%s'", result)
	}
}

func TestHumanReadable_NTRIPMountPoint(t *testing.T) {
	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 100, 0),
		Method:      "GET",
		Path:        "/CORS01",
		Version:     ntrip.NTRIPv2,
		SessionType: ntrip.SessionTypeDataStream,
		MountPoint:  "CORS01",
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	f := classIdHumanReadableMap[anc.NTRIPMountPoint]
	result := f(ar)
	if result != "CORS01" {
		t.Errorf("expected 'CORS01', got '%s'", result)
	}
}

func TestHumanReadable_NTRIPMountPoint_NotNTRIP(t *testing.T) {
	stub := &stubMessage{isReq: true}
	ar := makeAnnotatedRecord(stub, nil, 0)

	f := classIdHumanReadableMap[anc.NTRIPMountPoint]
	result := f(ar)
	if result != "_not_a_ntrip_req_" {
		t.Errorf("expected '_not_a_ntrip_req_', got '%s'", result)
	}
}

func TestHumanReadable_NTRIPSessionType(t *testing.T) {
	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 100, 0),
		Method:      "GET",
		Path:        "/TEST",
		Version:     ntrip.NTRIPv1,
		SessionType: ntrip.SessionTypeDataStream,
		MountPoint:  "TEST",
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	f := classIdHumanReadableMap[anc.NTRIPSessionType]
	result := f(ar)
	if result != "DataStream" {
		t.Errorf("expected 'DataStream', got '%s'", result)
	}
}

func TestHumanReadable_NTRIPSessionType_NotNTRIP(t *testing.T) {
	stub := &stubMessage{isReq: true}
	ar := makeAnnotatedRecord(stub, nil, 0)

	f := classIdHumanReadableMap[anc.NTRIPSessionType]
	result := f(ar)
	if result != "_not_a_ntrip_req_" {
		t.Errorf("expected '_not_a_ntrip_req_', got '%s'", result)
	}
}

// --- GetClassfierType (exported) ---

func TestGetClassfierType_ProtocolAdaptive_RTCM(t *testing.T) {
	opts := anc.AnalysisOptions{}
	opts.ProtocolSpecificClassfiers = make(map[bpf.AgentTrafficProtocolT]anc.ClassfierType)
	opts.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolTKProtocolRTCM] = anc.RTCMMessageType

	frame := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 30, 0),
		MessageType:   1074,
		Constellation: rtcm.ConstellationGPS,
		CRCValid:      true,
		TotalLen:      30,
	}
	ar := makeAnnotatedRecord(frame, nil, uint32(bpf.AgentTrafficProtocolTKProtocolRTCM))

	ct := GetClassfierType(anc.ProtocolAdaptive, opts, ar)
	if ct != anc.RTCMMessageType {
		t.Errorf("expected RTCMMessageType, got %v", ct)
	}
}

func TestGetClassfierType_ProtocolAdaptive_NTRIP(t *testing.T) {
	opts := anc.AnalysisOptions{}
	opts.ProtocolSpecificClassfiers = make(map[bpf.AgentTrafficProtocolT]anc.ClassfierType)
	opts.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolTKProtocolNTRIP] = anc.NTRIPMountPoint

	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 100, 0),
		Method:      "GET",
		Path:        "/BASE01",
		MountPoint:  "BASE01",
		SessionType: ntrip.SessionTypeDataStream,
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	ct := GetClassfierType(anc.ProtocolAdaptive, opts, ar)
	if ct != anc.NTRIPMountPoint {
		t.Errorf("expected NTRIPMountPoint, got %v", ct)
	}
}

func TestGetClassfierType_ProtocolAdaptive_Fallback(t *testing.T) {
	opts := anc.AnalysisOptions{}
	opts.ProtocolSpecificClassfiers = make(map[bpf.AgentTrafficProtocolT]anc.ClassfierType)
	// No protocol-specific classifier registered for this protocol
	ar := makeAnnotatedRecord(&stubMessage{isReq: true}, nil, 0)

	ct := GetClassfierType(anc.ProtocolAdaptive, opts, ar)
	if ct != anc.RemoteIp {
		t.Errorf("expected RemoteIp fallback, got %v", ct)
	}
}

func TestGetClassfierType_NonAdaptive(t *testing.T) {
	opts := anc.AnalysisOptions{}
	ar := makeAnnotatedRecord(&stubMessage{isReq: true}, nil, 0)

	ct := GetClassfierType(anc.RTCMMessageType, opts, ar)
	if ct != anc.RTCMMessageType {
		t.Errorf("expected RTCMMessageType passthrough, got %v", ct)
	}
}

// --- getClassfier with ProtocolAdaptive ---

func TestGetClassfier_ProtocolAdaptive_RTCM(t *testing.T) {
	opts := anc.AnalysisOptions{}
	opts.ProtocolSpecificClassfiers = make(map[bpf.AgentTrafficProtocolT]anc.ClassfierType)
	opts.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolTKProtocolRTCM] = anc.RTCMMessageType

	frame := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 30, 0),
		MessageType:   1077,
		Constellation: rtcm.ConstellationGPS,
		CRCValid:      true,
		TotalLen:      30,
	}
	ar := makeAnnotatedRecord(frame, nil, uint32(bpf.AgentTrafficProtocolTKProtocolRTCM))

	c := getClassfier(anc.ProtocolAdaptive, opts)
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "1077" {
		t.Errorf("expected '1077', got '%s'", id)
	}
}

func TestGetClassfier_ProtocolAdaptive_NTRIP(t *testing.T) {
	opts := anc.AnalysisOptions{}
	opts.ProtocolSpecificClassfiers = make(map[bpf.AgentTrafficProtocolT]anc.ClassfierType)
	opts.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolTKProtocolNTRIP] = anc.NTRIPSessionType

	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 100, 0),
		Method:      "SOURCE",
		Path:        "/PUSH01",
		SessionType: ntrip.SessionTypeSourcePush,
		MountPoint:  "PUSH01",
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	c := getClassfier(anc.ProtocolAdaptive, opts)
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "SourcePush" {
		t.Errorf("expected 'SourcePush', got '%s'", id)
	}
}

func TestGetClassfier_ProtocolAdaptive_Fallback(t *testing.T) {
	opts := anc.AnalysisOptions{}
	opts.ProtocolSpecificClassfiers = make(map[bpf.AgentTrafficProtocolT]anc.ClassfierType)
	// No mapping, should fall back to RemoteIp classifier
	ar := makeAnnotatedRecord(&stubMessage{isReq: true}, nil, 0)

	c := getClassfier(anc.ProtocolAdaptive, opts)
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "10.0.0.1" {
		t.Errorf("expected '10.0.0.1', got '%s'", id)
	}
}

func TestGetClassfier_NonAdaptive(t *testing.T) {
	opts := anc.AnalysisOptions{}
	frame := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 30, 0),
		MessageType:   1097,
		Constellation: rtcm.ConstellationGalileo,
		CRCValid:      true,
		TotalLen:      30,
	}
	ar := makeAnnotatedRecord(frame, nil, uint32(bpf.AgentTrafficProtocolTKProtocolRTCM))

	// Direct RTCMConstellation classifier, not adaptive
	c := getClassfier(anc.RTCMConstellation, opts)
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "Galileo" {
		t.Errorf("expected 'Galileo', got '%s'", id)
	}
}

// --- getClassIdHumanReadableFunc with ProtocolAdaptive ---

func TestGetClassIdHumanReadable_ProtocolAdaptive_RTCM(t *testing.T) {
	opts := anc.AnalysisOptions{}
	opts.ProtocolSpecificClassfiers = make(map[bpf.AgentTrafficProtocolT]anc.ClassfierType)
	opts.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolTKProtocolRTCM] = anc.RTCMMessageType

	frame := &rtcm.RTCMFrame{
		FrameBase:   protocol.NewFrameBase(1000, 30, 0),
		MessageType: 1005,
		CRCValid:    true,
		TotalLen:    30,
	}
	ar := makeAnnotatedRecord(frame, nil, uint32(bpf.AgentTrafficProtocolTKProtocolRTCM))

	f, ok := getClassIdHumanReadableFunc(anc.ProtocolAdaptive, opts)
	if !ok {
		t.Fatal("expected ok=true for ProtocolAdaptive")
	}
	result := f(ar)
	expected := "1005 (Station ARP Coords)"
	if result != expected {
		t.Errorf("expected '%s', got '%s'", expected, result)
	}
}

func TestGetClassIdHumanReadable_ProtocolAdaptive_NTRIP(t *testing.T) {
	opts := anc.AnalysisOptions{}
	opts.ProtocolSpecificClassfiers = make(map[bpf.AgentTrafficProtocolT]anc.ClassfierType)
	opts.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolTKProtocolNTRIP] = anc.NTRIPMountPoint

	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 100, 0),
		Method:      "GET",
		Path:        "/CORS02",
		MountPoint:  "CORS02",
		SessionType: ntrip.SessionTypeDataStream,
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	f, ok := getClassIdHumanReadableFunc(anc.ProtocolAdaptive, opts)
	if !ok {
		t.Fatal("expected ok=true for ProtocolAdaptive")
	}
	result := f(ar)
	if result != "CORS02" {
		t.Errorf("expected 'CORS02', got '%s'", result)
	}
}

func TestGetClassIdHumanReadable_ProtocolAdaptive_Fallback(t *testing.T) {
	opts := anc.AnalysisOptions{}
	opts.ProtocolSpecificClassfiers = make(map[bpf.AgentTrafficProtocolT]anc.ClassfierType)
	ar := makeAnnotatedRecord(&stubMessage{isReq: true}, nil, 0)

	f, ok := getClassIdHumanReadableFunc(anc.ProtocolAdaptive, opts)
	if !ok {
		t.Fatal("expected ok=true for ProtocolAdaptive")
	}
	result := f(ar)
	if result != "10.0.0.1" {
		t.Errorf("expected '10.0.0.1', got '%s'", result)
	}
}

func TestGetClassIdHumanReadable_NonAdaptive(t *testing.T) {
	opts := anc.AnalysisOptions{}
	f, ok := getClassIdHumanReadableFunc(anc.RTCMConstellation, opts)
	if !ok {
		t.Fatal("expected ok=true for RTCMConstellation")
	}
	frame := &rtcm.RTCMFrame{
		FrameBase:     protocol.NewFrameBase(1000, 30, 0),
		MessageType:   1071,
		Constellation: rtcm.ConstellationGPS,
		CRCValid:      true,
		TotalLen:      30,
	}
	ar := makeAnnotatedRecord(frame, nil, uint32(bpf.AgentTrafficProtocolTKProtocolRTCM))
	result := f(ar)
	if result != "GPS" {
		t.Errorf("expected 'GPS', got '%s'", result)
	}
}

// --- ClassfierTypeNames registration ---

func TestClassfierTypeNames_Registered(t *testing.T) {
	tests := []struct {
		ct   anc.ClassfierType
		name string
	}{
		{anc.RTCMMessageType, "rtcm-msg-type"},
		{anc.RTCMConstellation, "rtcm-constellation"},
		{anc.NTRIPMountPoint, "ntrip-mount"},
		{anc.NTRIPSessionType, "ntrip-session"},
	}
	for _, tt := range tests {
		got, ok := anc.ClassfierTypeNames[tt.ct]
		if !ok {
			t.Errorf("ClassfierType %v not registered in ClassfierTypeNames", tt.ct)
			continue
		}
		if got != tt.name {
			t.Errorf("ClassfierTypeNames[%v] = '%s', want '%s'", tt.ct, got, tt.name)
		}
	}
}

// --- NTRIP User classifier ---

func TestClassfier_NTRIPUser(t *testing.T) {
	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 100, 0),
		Method:      "GET",
		Path:        "/RTK_DATA",
		Version:     ntrip.NTRIPv2,
		SessionType: ntrip.SessionTypeDataStream,
		MountPoint:  "RTK_DATA",
		Username:    "operator01",
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	c := classfierMap[anc.NTRIPUser]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "operator01" {
		t.Errorf("expected 'operator01', got '%s'", id)
	}
}

func TestClassfier_NTRIPUser_Anonymous(t *testing.T) {
	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 100, 0),
		Method:      "GET",
		Path:        "/RTK_DATA",
		Version:     ntrip.NTRIPv2,
		SessionType: ntrip.SessionTypeDataStream,
		MountPoint:  "RTK_DATA",
		Username:    "",
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	c := classfierMap[anc.NTRIPUser]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "_anonymous_" {
		t.Errorf("expected '_anonymous_', got '%s'", id)
	}
}

func TestClassfier_NTRIPUser_NotNTRIP(t *testing.T) {
	stub := &stubMessage{isReq: true}
	ar := makeAnnotatedRecord(stub, nil, 0)

	c := classfierMap[anc.NTRIPUser]
	id, err := c(ar)
	if err != nil {
		t.Fatal(err)
	}
	if id != "_not_a_ntrip_req_" {
		t.Errorf("expected '_not_a_ntrip_req_', got '%s'", id)
	}
}

func TestClassfier_NTRIPUser_HumanReadable(t *testing.T) {
	req := &ntrip.NTRIPRequest{
		FrameBase:   protocol.NewFrameBase(1000, 100, 0),
		Method:      "GET",
		Path:        "/RTK_DATA",
		Version:     ntrip.NTRIPv2,
		SessionType: ntrip.SessionTypeDataStream,
		MountPoint:  "RTK_DATA",
		Username:    "operator01",
	}
	ar := makeAnnotatedRecord(req, nil, uint32(bpf.AgentTrafficProtocolTKProtocolNTRIP))

	f := classIdHumanReadableMap[anc.NTRIPUser]
	if got := f(ar); got != "operator01" {
		t.Errorf("expected 'operator01', got '%s'", got)
	}
}

func TestClassfierTypeName_NTRIPUser(t *testing.T) {
	if name, ok := anc.ClassfierTypeNames[anc.NTRIPUser]; !ok || name != "ntrip-user" {
		t.Errorf("expected ClassfierTypeNames[NTRIPUser]='ntrip-user', got '%s' (ok=%v)", name, ok)
	}
}
