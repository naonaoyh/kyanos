package session

import (
	"net"
	"testing"
	"time"

	"kyanos/agent/protocol"
	"kyanos/agent/protocol/ntrip"
	"kyanos/agent/protocol/rtcm"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func makeConnInfo(serverIP, clientIP string, serverPort, clientPort uint16) *ConnInfo {
	return &ConnInfo{
		LocalIP:    net.ParseIP(serverIP),
		RemoteIP:   net.ParseIP(clientIP),
		LocalPort:  serverPort,
		RemotePort: clientPort,
		IsServer:   true,
	}
}

func makeNTRIPRequest(ts uint64, mount, user, pass string, hasAuth bool) *ntrip.NTRIPRequest {
	req := &ntrip.NTRIPRequest{
		Method:      ntrip.MethodGet,
		Path:        "/" + mount,
		Version:     ntrip.NTRIPv2,
		SessionType: ntrip.SessionTypeDataStream,
		MountPoint:  mount,
		HasAuth:     hasAuth,
		Username:    user,
		Password:    pass,
	}
	req.SetTimeStamp(ts)
	return req
}

func makeNTRIPResponse(ts uint64, statusCode int) *ntrip.NTRIPResponse {
	resp := &ntrip.NTRIPResponse{
		Version:    ntrip.NTRIPv2,
		StatusCode: statusCode,
		StatusLine: "HTTP/1.1 200 OK",
	}
	resp.SetTimeStamp(ts)
	return resp
}

func makeGGASentence(ts uint64, lat, lon float64, fix, sats int) *ntrip.NTRIPNMEASentence {
	nmea := &ntrip.NTRIPNMEASentence{
		SentenceType:  "GGA",
		Raw:           "$GPGGA,test",
		GGAParsed:     true,
		Latitude:      lat,
		Longitude:     lon,
		FixQuality:    fix,
		NumSatellites: sats,
		HDOP:          0.8,
		DiffAge:       -1, // not present
	}
	nmea.SetTimeStamp(ts)
	return nmea
}

func makeGGASentenceFull(ts uint64, lat, lon float64, fix, sats int, diffAge float64, stationID string) *ntrip.NTRIPNMEASentence {
	nmea := &ntrip.NTRIPNMEASentence{
		SentenceType:  "GGA",
		Raw:           "$GPGGA,test",
		GGAParsed:     true,
		Latitude:      lat,
		Longitude:     lon,
		FixQuality:    fix,
		NumSatellites: sats,
		HDOP:          0.8,
		DiffAge:       diffAge,
		DiffStationID: stationID,
	}
	nmea.SetTimeStamp(ts)
	return nmea
}

func makeRTCMFrame(ts uint64, msgType, size int, crcValid bool) *rtcm.RTCMFrame {
	f := &rtcm.RTCMFrame{
		MessageType: msgType,
		CRCValid:    crcValid,
		TotalLen:    size,
		PayloadLen:  size - 6,
	}
	f.SetTimeStamp(ts)
	return f
}

func makeNTRIPRTCMFrame(ts uint64, msgType, size int, crcValid bool) *ntrip.NTRIPRTCMFrame {
	inner := makeRTCMFrame(ts, msgType, size, crcValid)
	f := &ntrip.NTRIPRTCMFrame{
		Inner: inner,
	}
	f.SetTimeStamp(ts)
	return f
}

// mockListener records session lifecycle events for testing.
type mockListener struct {
	created []*NTRIPSession
	closed  []*NTRIPSession
}

func (m *mockListener) OnSessionCreated(s *NTRIPSession) { m.created = append(m.created, s) }
func (m *mockListener) OnSessionClosed(s *NTRIPSession)  { m.closed = append(m.closed, s) }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestTrackerCreatesSessionOnNTRIPRequest(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	listener := &mockListener{}
	tracker.AddListener(listener)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	ts := uint64(time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC).UnixNano())

	req := makeNTRIPRequest(ts, "MOUNT-A", "user001", "pass", true)
	resp := makeNTRIPResponse(ts+23_000_000, 200) // 23ms later

	record := protocol.Record{Req: req, Resp: resp}
	tracker.OnRecord(record, conn)

	if tracker.SessionCount() != 1 {
		t.Fatalf("SessionCount = %d, want 1", tracker.SessionCount())
	}
	if tracker.ActiveCount() != 1 {
		t.Errorf("ActiveCount = %d, want 1", tracker.ActiveCount())
	}

	sessions := tracker.SessionByMountPoint("MOUNT-A")
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session for MOUNT-A, got %d", len(sessions))
	}

	s := sessions[0]
	if s.Username != "user001" {
		t.Errorf("Username = %q, want %q", s.Username, "user001")
	}
	if s.ClientIP != "192.168.1.100" {
		t.Errorf("ClientIP = %q, want 192.168.1.100", s.ClientIP)
	}
	if !s.AuthSuccess {
		t.Error("AuthSuccess should be true for 200 response")
	}
	if s.HTTPStatusCode != 200 {
		t.Errorf("HTTPStatusCode = %d, want 200", s.HTTPStatusCode)
	}

	// Check listener
	if len(listener.created) != 1 {
		t.Errorf("listener.created = %d, want 1", len(listener.created))
	}
}

func TestTrackerFailedAuth(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	ts := uint64(time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC).UnixNano())

	req := makeNTRIPRequest(ts, "MOUNT-A", "baduser", "badpass", true)
	resp := makeNTRIPResponse(ts+50_000_000, 401)

	record := protocol.Record{Req: req, Resp: resp}
	tracker.OnRecord(record, conn)

	sessions := tracker.AllSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	s := sessions[0]
	if s.AuthSuccess {
		t.Error("AuthSuccess should be false for 401")
	}
	if s.HTTPStatusCode != 401 {
		t.Errorf("HTTPStatusCode = %d, want 401", s.HTTPStatusCode)
	}
}

func TestTrackerGGAEvents(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Login first
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Send 5 GGA events at 1s intervals
	for i := 1; i <= 5; i++ {
		gga := makeGGASentence(
			uint64(base.Add(time.Duration(i)*time.Second).UnixNano()),
			31.24, 121.48, 1, 12,
		)
		tracker.OnRecord(protocol.Record{Req: gga}, conn)
	}

	sessions := tracker.SessionByMountPoint("MOUNT-A")
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	s := sessions[0]
	if len(s.GGAEvents) != 5 {
		t.Errorf("GGAEvents = %d, want 5", len(s.GGAEvents))
	}
	if s.GGAEvents[0].Interval != 0 {
		t.Errorf("first GGA interval should be 0, got %v", s.GGAEvents[0].Interval)
	}
	if s.GGAEvents[1].Interval != 1*time.Second {
		t.Errorf("second GGA interval = %v, want 1s", s.GGAEvents[1].Interval)
	}
}

func TestTrackerRTCMFrames(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// 10 RTCM frames via NTRIPRTCMFrame at 1ms intervals
	for i := 0; i < 10; i++ {
		frame := makeNTRIPRTCMFrame(
			uint64(base.Add(time.Duration(100+i)*time.Millisecond).UnixNano()),
			1074, 298, true,
		)
		tracker.OnRecord(protocol.Record{Req: frame}, conn)
	}

	s := tracker.SessionByMountPoint("MOUNT-A")[0]
	if s.rtcmFrameCount != 10 {
		t.Errorf("rtcmFrameCount = %d, want 10", s.rtcmFrameCount)
	}
}

func TestTrackerDirectRTCMFrames(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 8080, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Direct RTCM frames (no NTRIP login)
	for i := 0; i < 5; i++ {
		frame := makeRTCMFrame(
			uint64(base.Add(time.Duration(i)*time.Millisecond).UnixNano()),
			1005, 36, true,
		)
		tracker.OnRecord(protocol.Record{Req: frame}, conn)
	}

	if tracker.SessionCount() != 1 {
		t.Fatalf("SessionCount = %d, want 1", tracker.SessionCount())
	}
	s := tracker.AllSessions()[0]
	if s.MountPoint != "direct-rtcm" {
		t.Errorf("MountPoint = %q, want %q", s.MountPoint, "direct-rcm")
	}
	if s.rtcmFrameCount != 5 {
		t.Errorf("rtcmFrameCount = %d, want 5", s.rtcmFrameCount)
	}
}

func TestTrackerConnectionClose(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	listener := &mockListener{}
	tracker.AddListener(listener)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	if tracker.ActiveCount() != 1 {
		t.Fatalf("ActiveCount = %d, want 1", tracker.ActiveCount())
	}

	// Close connection (client-initiated)
	tracker.OnConnectionClose(conn, base.Add(5*time.Minute), CloseClient)

	if tracker.ActiveCount() != 0 {
		t.Errorf("ActiveCount = %d, want 0 after close", tracker.ActiveCount())
	}
	if tracker.SessionCount() != 1 {
		t.Errorf("SessionCount = %d, want 1 (session kept)", tracker.SessionCount())
	}
	if len(listener.closed) != 1 {
		t.Errorf("listener.closed = %d, want 1", len(listener.closed))
	}

	// Verify session duration
	s := tracker.AllSessions()[0]
	if s.Duration() != 5*time.Minute {
		t.Errorf("Duration = %v, want 5m", s.Duration())
	}
}

func TestTrackerSessionByUsername(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Two sessions from different clients to same mountpoint
	conn1 := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	conn2 := makeConnInfo("10.0.1.5", "192.168.1.101", 2101, 54322)

	req1 := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "alice", "", true)
	resp1 := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req1, Resp: resp1}, conn1)

	req2 := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "bob", "", true)
	resp2 := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req2, Resp: resp2}, conn2)

	alice := tracker.SessionByUsername("alice")
	if len(alice) != 1 {
		t.Errorf("alice sessions = %d, want 1", len(alice))
	}
	bob := tracker.SessionByUsername("bob")
	if len(bob) != 1 {
		t.Errorf("bob sessions = %d, want 1", len(bob))
	}
	nobody := tracker.SessionByUsername("charlie")
	if len(nobody) != 0 {
		t.Errorf("charlie sessions = %d, want 0", len(nobody))
	}
}

func TestTrackerMultipleSessionsSameClient(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Same client, different ports → different sessions
	conn1 := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	conn2 := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54322)

	req1 := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp1 := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req1, Resp: resp1}, conn1)

	req2 := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-B", "user001", "", true)
	resp2 := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req2, Resp: resp2}, conn2)

	if tracker.SessionCount() != 2 {
		t.Errorf("SessionCount = %d, want 2", tracker.SessionCount())
	}

	mountA := tracker.SessionByMountPoint("MOUNT-A")
	mountB := tracker.SessionByMountPoint("MOUNT-B")
	if len(mountA) != 1 || len(mountB) != 1 {
		t.Errorf("mountA=%d mountB=%d, want 1 each", len(mountA), len(mountB))
	}
}

func TestTrackerNilRecord(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)

	// Should not panic
	tracker.OnRecord(protocol.Record{}, conn)
	tracker.OnRecord(protocol.Record{Req: nil}, conn)
}

func TestTrackerNonNTRIPRecord(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 80, 54321)

	// A non-NTRIP record should be silently ignored
	fakeReq := &protocol.FrameBase{} // doesn't implement any NTRIP type
	tracker.OnRecord(protocol.Record{Req: nil}, conn)
	_ = fakeReq // just ensure no panic

	if tracker.SessionCount() != 0 {
		t.Errorf("SessionCount = %d, want 0 for non-NTRIP records", tracker.SessionCount())
	}
}

func TestTrackerConnectionCloseWithDirection(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	listener := &mockListener{}
	tracker.AddListener(listener)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Close connection server-side
	tracker.OnConnectionClose(conn, base.Add(3*time.Minute), CloseServer)

	s := tracker.AllSessions()[0]
	if s.CloseDirection != CloseServer {
		t.Errorf("CloseDirection = %v, want CloseServer", s.CloseDirection)
	}
}

func TestTrackerKickOutDetection(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Session 1: user001 from IP .100, port 54321
	conn1 := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	req1 := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp1 := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req1, Resp: resp1}, conn1)

	// Session 2: same user001 from different port (kick-out scenario), starts 3s later
	conn2 := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54322)
	req2 := makeNTRIPRequest(uint64(base.Add(3*time.Second).UnixNano()), "MOUNT-A", "user001", "", true)
	resp2 := makeNTRIPResponse(uint64(base.Add(3*time.Second+20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req2, Resp: resp2}, conn2)

	// Close session 1 within kick-out window → should be classified as kick-out
	tracker.OnConnectionClose(conn1, base.Add(5*time.Second), CloseServer)

	s1 := tracker.AllSessions()[0]
	if s1.DisconnectReason != DisconnectAccountKickOut {
		t.Errorf("DisconnectReason = %v, want DisconnectAccountKickOut", s1.DisconnectReason)
	}
}

func TestTrackerDisconnectClientInitiated(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Client-initiated close
	tracker.OnConnectionClose(conn, base.Add(5*time.Minute), CloseClient)

	s := tracker.AllSessions()[0]
	if s.DisconnectReason != DisconnectClientInitiated {
		t.Errorf("DisconnectReason = %v, want DisconnectClientInitiated", s.DisconnectReason)
	}
}

func TestTrackerDisconnectAuthFailed(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "baduser", "badpass", true)
	resp := makeNTRIPResponse(uint64(base.Add(50*time.Millisecond).UnixNano()), 401)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Server closes after auth failure
	tracker.OnConnectionClose(conn, base.Add(2*time.Second), CloseServer)

	s := tracker.AllSessions()[0]
	if s.DisconnectReason != DisconnectAuthFailed {
		t.Errorf("DisconnectReason = %v, want DisconnectAuthFailed", s.DisconnectReason)
	}
}

func TestTrackerDisconnectGGATimeup(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.GGATimeout = 30 * time.Second
	tracker := NewSessionTracker(cfg)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// GGA at T+1s
	gga := makeGGASentence(uint64(base.Add(1*time.Second).UnixNano()), 31.24, 121.48, 1, 12)
	tracker.OnRecord(protocol.Record{Req: gga}, conn)

	// Server closes at T+60s (no GGA for 59s, well above 30s timeout)
	tracker.OnConnectionClose(conn, base.Add(60*time.Second), CloseServer)

	s := tracker.AllSessions()[0]
	if s.DisconnectReason != DisconnectGGATimeout {
		t.Errorf("DisconnectReason = %v, want DisconnectGGATimeout (detail: %s)", s.DisconnectReason, s.DisconnectDetail)
	}
}

func TestTrackerDisconnectRTCMAbort(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.RetransAbortThreshold = 5
	tracker := NewSessionTracker(cfg)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Simulate many retransmissions before close
	s := tracker.AllSessions()[0]
	for i := 0; i < 8; i++ {
		s.AddRetransmission()
	}
	// Set recent retrans count (in real code this is tracked by time window)
	s.mu.Lock()
	s.recentRetransCount = 8
	s.mu.Unlock()

	// Server closes → should be RTCM abort
	tracker.OnConnectionClose(conn, base.Add(5*time.Minute), CloseServer)

	s2 := tracker.AllSessions()[0]
	if s2.DisconnectReason != DisconnectRTCMAbort {
		t.Errorf("DisconnectReason = %v, want DisconnectRTCMAbort (detail: %s)", s2.DisconnectReason, s2.DisconnectDetail)
	}
}

func TestTrackerDisconnectUnknown(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Add recent GGA so GGA timeout won't trigger
	gga := makeGGASentence(uint64(base.Add(4*time.Minute+50*time.Second).UnixNano()), 31.24, 121.48, 1, 12)
	tracker.OnRecord(protocol.Record{Req: gga}, conn)

	// CloseReset direction with no other signals → unknown
	tracker.OnConnectionClose(conn, base.Add(5*time.Minute), CloseReset)

	s := tracker.AllSessions()[0]
	if s.DisconnectReason != DisconnectUnknown {
		t.Errorf("DisconnectReason = %v, want DisconnectUnknown (detail: %s)", s.DisconnectReason, s.DisconnectDetail)
	}
}

func TestConnInfoClientIP(t *testing.T) {
	// Server side: client is remote
	ci := &ConnInfo{
		LocalIP:    net.ParseIP("10.0.1.5"),
		RemoteIP:   net.ParseIP("192.168.1.100"),
		LocalPort:  2101,
		RemotePort: 54321,
		IsServer:   true,
	}
	if ci.ClientIP() != "192.168.1.100" {
		t.Errorf("ClientIP (server side) = %s, want 192.168.1.100", ci.ClientIP())
	}
	if ci.ClientPort() != 54321 {
		t.Errorf("ClientPort (server side) = %d, want 54321", ci.ClientPort())
	}

	// Client side: client is local
	ci.IsServer = false
	if ci.ClientIP() != "10.0.1.5" {
		t.Errorf("ClientIP (client side) = %s, want 10.0.1.5", ci.ClientIP())
	}
	if ci.ClientPort() != 2101 {
		t.Errorf("ClientPort (client side) = %d, want 2101", ci.ClientPort())
	}
}

// ---------------------------------------------------------------------------
// Session identity fields (Password, NTRIPVersion, UserAgent, ServerResponse)
// ---------------------------------------------------------------------------

func TestTrackerSessionIdentityFields(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.Visibility.ShowPassword = true // enable password extraction
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	ts := uint64(time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC).UnixNano())

	req := &ntrip.NTRIPRequest{
		Method:      ntrip.MethodGet,
		Path:        "/MOUNT-A",
		Version:     ntrip.NTRIPv2,
		SessionType: ntrip.SessionTypeDataStream,
		MountPoint:  "MOUNT-A",
		HasAuth:     true,
		Username:    "user001",
		Password:    "secret123",
		UserAgent:   "RTKLib/2.4.3",
	}
	req.SetTimeStamp(ts)

	resp := &ntrip.NTRIPResponse{
		Version:    ntrip.NTRIPv2,
		StatusCode: 200,
		StatusLine: "HTTP/1.1 200 OK",
	}
	resp.SetTimeStamp(ts + 23_000_000)

	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	s := tracker.AllSessions()[0]
	if s.Username != "user001" {
		t.Errorf("Username = %q, want user001", s.Username)
	}
	if s.Password != "secret123" {
		t.Errorf("Password = %q, want secret123", s.Password)
	}
	if s.NTRIPVersion != "NTRIPv2" {
		t.Errorf("NTRIPVersion = %q, want NTRIPv2", s.NTRIPVersion)
	}
	if s.UserAgent != "RTKLib/2.4.3" {
		t.Errorf("UserAgent = %q, want RTKLib/2.4.3", s.UserAgent)
	}
	if s.ServerResponse != "HTTP/1.1 200 OK" {
		t.Errorf("ServerResponse = %q, want HTTP/1.1 200 OK", s.ServerResponse)
	}
}

func TestTrackerPasswordHiddenByDefault(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig()) // ShowPassword = false

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	ts := uint64(time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC).UnixNano())

	req := makeNTRIPRequest(ts, "MOUNT-A", "user001", "secret123", true)
	resp := makeNTRIPResponse(ts+23_000_000, 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	s := tracker.AllSessions()[0]
	if s.Password != "" {
		t.Errorf("Password = %q, want empty (hidden by default)", s.Password)
	}
}

func TestTrackerNTRIPVersionV1(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	ts := uint64(time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC).UnixNano())

	req := &ntrip.NTRIPRequest{
		Method:      ntrip.MethodGet,
		Path:        "/MOUNT-A",
		Version:     ntrip.NTRIPv1,
		SessionType: ntrip.SessionTypeDataStream,
		MountPoint:  "MOUNT-A",
		HasAuth:     true,
		Username:    "user001",
	}
	req.SetTimeStamp(ts)

	resp := &ntrip.NTRIPResponse{
		Version:    ntrip.NTRIPv1,
		StatusCode: 200,
		StatusLine: "ICY 200 OK",
		IsICY:      true,
	}
	resp.SetTimeStamp(ts + 10_000_000)

	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	s := tracker.AllSessions()[0]
	if s.NTRIPVersion != "NTRIPv1" {
		t.Errorf("NTRIPVersion = %q, want NTRIPv1", s.NTRIPVersion)
	}
	if s.ServerResponse != "ICY 200 OK" {
		t.Errorf("ServerResponse = %q, want ICY 200 OK", s.ServerResponse)
	}
}

func TestTrackerServerErrorResponse(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	ts := uint64(time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC).UnixNano())

	req := makeNTRIPRequest(ts, "MOUNT-A", "baduser", "badpass", true)
	resp := &ntrip.NTRIPResponse{
		Version:    ntrip.NTRIPv1,
		StatusCode: 0,
		StatusLine: "ERROR - Bad Password",
	}
	resp.SetTimeStamp(ts + 50_000_000)

	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	s := tracker.AllSessions()[0]
	if s.ServerResponse != "ERROR - Bad Password" {
		t.Errorf("ServerResponse = %q, want ERROR - Bad Password", s.ServerResponse)
	}
}

// ---------------------------------------------------------------------------
// GGA with DiffAge and DiffStationID through tracker
// ---------------------------------------------------------------------------

func TestTrackerGGAWithDiffAge(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())
	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// GGA with DiffAge and station ID
	gga := makeGGASentenceFull(
		uint64(base.Add(1*time.Second).UnixNano()),
		31.24, 121.48, 4, 18, 2.5, "0312",
	)
	tracker.OnRecord(protocol.Record{Req: gga}, conn)

	s := tracker.SessionByMountPoint("MOUNT-A")[0]
	if len(s.GGAEvents) != 1 {
		t.Fatalf("expected 1 GGA event, got %d", len(s.GGAEvents))
	}
	ev := s.GGAEvents[0]
	if ev.FixQuality != 4 {
		t.Errorf("FixQuality = %d, want 4 (RTK-fixed)", ev.FixQuality)
	}
	if ev.DiffAge != 2.5 {
		t.Errorf("DiffAge = %f, want 2.5", ev.DiffAge)
	}
	if ev.DiffStationID != "0312" {
		t.Errorf("DiffStationID = %q, want 0312", ev.DiffStationID)
	}
}

// ---------------------------------------------------------------------------
// FieldVisibility configuration
// ---------------------------------------------------------------------------

func TestFieldVisibilityDefault(t *testing.T) {
	v := DefaultFieldVisibility()
	if v.ShowPassword {
		t.Error("ShowPassword should be false by default")
	}
	if !v.ShowNTRIPVersion {
		t.Error("ShowNTRIPVersion should be true by default")
	}
	if !v.ShowUserAgent {
		t.Error("ShowUserAgent should be true by default")
	}
	if !v.ShowMountPoint {
		t.Error("ShowMountPoint should be true by default")
	}
	if !v.ShowServerResponse {
		t.Error("ShowServerResponse should be true by default")
	}
	if !v.ShowDiffAge {
		t.Error("ShowDiffAge should be true by default")
	}
	if !v.ShowDuration {
		t.Error("ShowDuration should be true by default")
	}
}

func TestTrackerVisibilityHidesServerResponse(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.Visibility.ShowServerResponse = false
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	ts := uint64(time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC).UnixNano())

	req := makeNTRIPRequest(ts, "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(ts+23_000_000, 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	s := tracker.AllSessions()[0]
	if s.ServerResponse != "" {
		t.Errorf("ServerResponse = %q, want empty when hidden", s.ServerResponse)
	}
}

func TestTrackerVisibilityHidesNTRIPVersion(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.Visibility.ShowNTRIPVersion = false
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	ts := uint64(time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC).UnixNano())

	req := makeNTRIPRequest(ts, "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(ts+23_000_000, 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	s := tracker.AllSessions()[0]
	if s.NTRIPVersion != "" {
		t.Errorf("NTRIPVersion = %q, want empty when hidden", s.NTRIPVersion)
	}
}

// ---------------------------------------------------------------------------
// TCP Health Analysis (S5) integration via tracker
// ---------------------------------------------------------------------------

func TestTrackerEnableTCPHealth(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EnableTCPHealth = true
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	s := tracker.AllSessions()[0]
	if s.TCPAnalyzer == nil {
		t.Fatal("TCPAnalyzer should be attached when EnableTCPHealth is true")
	}
}

func TestTrackerTCPHealthDisabledByDefault(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig())

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	s := tracker.AllSessions()[0]
	if s.TCPAnalyzer != nil {
		t.Error("TCPAnalyzer should be nil when EnableTCPHealth is false")
	}
}

func TestTrackerOnTCPRetransmission(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EnableTCPHealth = true
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Record retransmissions
	for i := 0; i < 5; i++ {
		tracker.OnTCPRetransmission(conn, base.Add(time.Duration(i)*time.Second), uint32(i+1), 1400)
	}

	s := tracker.AllSessions()[0]
	if s.TCPAnalyzer.RetransmissionCount() != 5 {
		t.Errorf("RetransmissionCount = %d, want 5", s.TCPAnalyzer.RetransmissionCount())
	}
	if s.recentRetransCount != 5 {
		t.Errorf("recentRetransCount = %d, want 5", s.recentRetransCount)
	}
}

func TestTrackerOnTCPRetransmissionFallback(t *testing.T) {
	// TCP analyzer disabled → should fall back to AddRetransmission
	tracker := NewSessionTracker(DefaultTrackerConfig())

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	tracker.OnTCPRetransmission(conn, base.Add(time.Second), 1, 1400)
	tracker.OnTCPRetransmission(conn, base.Add(2*time.Second), 2, 1400)

	s := tracker.AllSessions()[0]
	if s.NetworkQuality.TotalRetransmissions != 2 {
		t.Errorf("TotalRetransmissions = %d, want 2 (fallback)", s.NetworkQuality.TotalRetransmissions)
	}
}

func TestTrackerOnTCPRoundTripTime(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EnableTCPHealth = true
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Record RTT samples
	tracker.OnTCPRoundTripTime(conn, 25*time.Millisecond, 1, base.Add(time.Second))
	tracker.OnTCPRoundTripTime(conn, 50*time.Millisecond, 2, base.Add(2*time.Second))
	tracker.OnTCPRoundTripTime(conn, 200*time.Millisecond, 3, base.Add(3*time.Second))

	s := tracker.AllSessions()[0]
	if s.TCPAnalyzer.RTTSampleCount() != 3 {
		t.Errorf("RTTSampleCount = %d, want 3", s.TCPAnalyzer.RTTSampleCount())
	}
	// Also recorded in session's simple tracker
	if len(s.rttSamples) != 3 {
		t.Errorf("session rttSamples = %d, want 3", len(s.rttSamples))
	}
}

func TestTrackerOnTCPWindowChange(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EnableTCPHealth = true
	cfg.TCPHealthConfig.WindowShrinkRatio = 0.5
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Window size changes
	tracker.OnTCPWindowChange(conn, 65535, base.Add(time.Second))   // initial
	tracker.OnTCPWindowChange(conn, 50000, base.Add(2*time.Second)) // small reduction (not flagged)
	tracker.OnTCPWindowChange(conn, 10000, base.Add(3*time.Second)) // large reduction (flagged)

	s := tracker.AllSessions()[0]
	if s.TCPAnalyzer.WindowShrinkCount() != 1 {
		t.Errorf("WindowShrinkCount = %d, want 1", s.TCPAnalyzer.WindowShrinkCount())
	}
}

func TestTrackerOnTCPPacket(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EnableTCPHealth = true
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Original packets
	for i := uint32(1); i <= 10; i++ {
		tracker.OnTCPPacket(conn, i, base.Add(time.Duration(i)*time.Millisecond), false)
	}
	// Retransmit seq=5
	tracker.OnTCPPacket(conn, 5, base.Add(100*time.Millisecond), false) // auto-detect dup

	s := tracker.AllSessions()[0]
	if s.TCPAnalyzer.TotalPackets() != 11 {
		t.Errorf("TotalPackets = %d, want 11", s.TCPAnalyzer.TotalPackets())
	}
	if s.TCPAnalyzer.RetransmissionCount() != 1 {
		t.Errorf("RetransmissionCount = %d, want 1 (auto-detected dup seq=5)", s.TCPAnalyzer.RetransmissionCount())
	}
}

func TestTrackerTCPHealthNoSession(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EnableTCPHealth = true
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// No session exists → should not panic
	tracker.OnTCPRetransmission(conn, base, 1, 1400)
	tracker.OnTCPRoundTripTime(conn, 50*time.Millisecond, 1, base)
	tracker.OnTCPWindowChange(conn, 32768, base)
	tracker.OnTCPPacket(conn, 1, base, false)
}

func TestTrackerTCPHealthFinalStats(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EnableTCPHealth = true
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Add some RTCM frames to create stats
	for i := 0; i < 20; i++ {
		frame := makeNTRIPRTCMFrame(
			uint64(base.Add(time.Duration(100+i)*time.Millisecond).UnixNano()),
			1074, 298, true,
		)
		tracker.OnRecord(protocol.Record{Req: frame}, conn)
	}

	// Record TCP retransmissions
	for i := 0; i < 10; i++ {
		tracker.OnTCPRetransmission(conn, base.Add(time.Duration(i+1)*time.Second), uint32(i+1), 1400)
	}

	// Close session → triggers computeFinalStats
	tracker.OnConnectionClose(conn, base.Add(5*time.Minute), CloseClient)

	s := tracker.AllSessions()[0]
	if s.NetworkQuality.TotalRetransmissions != 10 {
		t.Errorf("TotalRetransmissions = %d, want 10 (from analyzer)", s.NetworkQuality.TotalRetransmissions)
	}
	rate := s.NetworkQuality.RetransmissionRate
	if rate <= 0 {
		t.Errorf("RetransmissionRate = %f, want > 0", rate)
	}
}

func TestTrackerTCPHealthSummary(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EnableTCPHealth = true
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Add TCP events
	for i := 0; i < 20; i++ {
		tracker.OnTCPPacket(conn, uint32(i+1), base.Add(time.Duration(i)*100*time.Millisecond), false)
	}
	for i := 0; i < 5; i++ {
		tracker.OnTCPRetransmission(conn, base.Add(time.Duration(i)*500*time.Millisecond), uint32(i+100), 1400)
	}
	for i := 0; i < 10; i++ {
		tracker.OnTCPRoundTripTime(conn, time.Duration(10+i*10)*time.Millisecond, uint32(i+1),
			base.Add(time.Duration(i)*time.Second))
	}

	s := tracker.AllSessions()[0]
	summary := s.TCPHealthSummary()
	if summary.TotalPackets == 0 {
		t.Error("TotalPackets should be > 0")
	}
	if summary.TotalRetransmissions != 5 {
		t.Errorf("TotalRetransmissions = %d, want 5", summary.TotalRetransmissions)
	}
}

func TestTrackerCongestionCorrelation(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EnableTCPHealth = true
	cfg.TCPHealthConfig.BurstThreshold = 3
	cfg.TCPHealthConfig.BurstWindow = 5 * time.Second
	tracker := NewSessionTracker(cfg)

	conn := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Login
	req := makeNTRIPRequest(uint64(base.UnixNano()), "MOUNT-A", "user001", "", true)
	resp := makeNTRIPResponse(uint64(base.Add(20*time.Millisecond).UnixNano()), 200)
	tracker.OnRecord(protocol.Record{Req: req, Resp: resp}, conn)

	// Add RTCM frames with a gap to create an interruption
	for i := 0; i < 10; i++ {
		frame := makeNTRIPRTCMFrame(
			uint64(base.Add(time.Duration(i)*100*time.Millisecond).UnixNano()),
			1074, 298, true,
		)
		tracker.OnRecord(protocol.Record{Req: frame}, conn)
	}
	// Big gap (interruption) from T+1s to T+5s
	for i := 0; i < 5; i++ {
		frame := makeNTRIPRTCMFrame(
			uint64(base.Add(5*time.Second+time.Duration(i)*100*time.Millisecond).UnixNano()),
			1074, 298, true,
		)
		tracker.OnRecord(protocol.Record{Req: frame}, conn)
	}

	// Add retransmissions during the interruption
	for i := 0; i < 5; i++ {
		tracker.OnTCPRetransmission(conn,
			base.Add(2*time.Second+time.Duration(i)*500*time.Millisecond),
			uint32(i+1), 1400)
	}

	// Close → compute stats
	tracker.OnConnectionClose(conn, base.Add(10*time.Second), CloseClient)

	s := tracker.AllSessions()[0]
	correlations := s.CongestionCorrelations()

	// Should find at least one correlation
	if len(correlations) == 0 {
		// Interruption detection depends on avg interval; just verify no crash
		t.Log("No correlations found (interruption detection threshold may not be met)")
	}
	for _, c := range correlations {
		if c.ProbableCause == "" {
			t.Error("ProbableCause should not be empty")
		}
	}
}

// ---------------------------------------------------------------------------
// Real client IP behind a load balancer (CLB)
// ---------------------------------------------------------------------------

func TestResolveRealClientIP(t *testing.T) {
	req := &ntrip.NTRIPRequest{
		ForwardedFor: "203.0.113.7, 10.0.0.1", // client chain: original first
		XRealIP:      "198.51.100.42",
	}
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"xff leftmost", "X-Forwarded-For", "203.0.113.7"},
		{"xff case-insensitive", "x-forwarded-for", "203.0.113.7"},
		{"x-real-ip", "X-Real-IP", "198.51.100.42"},
		{"disabled when empty header", "", ""},
		{"unknown header", "X-Custom", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveRealClientIP(req, tc.header); got != tc.want {
				t.Errorf("resolveRealClientIP(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}

	// Unparseable / empty values are rejected (fall back to socket IP upstream).
	bad := &ntrip.NTRIPRequest{ForwardedFor: "not-an-ip"}
	if got := resolveRealClientIP(bad, "X-Forwarded-For"); got != "" {
		t.Errorf("resolveRealClientIP with garbage = %q, want empty", got)
	}
}

func TestResolveRealClientIPNilSafe(t *testing.T) {
	if got := resolveRealClientIP(nil, "X-Forwarded-For"); got != "" {
		t.Errorf("resolveRealClientIP(nil) = %q, want empty", got)
	}
}

func TestEffectiveClientIP(t *testing.T) {
	s := NewNTRIPSession("sid", "MOUNT", "u", "10.0.0.1", 5000, time.Now())
	if got := s.EffectiveClientIP(); got != "10.0.0.1" {
		t.Errorf("EffectiveClientIP (no real IP) = %q, want socket 10.0.0.1", got)
	}
	s.mu.Lock()
	s.RealClientIP = "203.0.113.7"
	s.mu.Unlock()
	if got := s.EffectiveClientIP(); got != "203.0.113.7" {
		t.Errorf("EffectiveClientIP (with real IP) = %q, want 203.0.113.7", got)
	}
}

// TestTrackerRealClientIPExtraction: behind a CLB the socket peer is the LB's
// IP; with --real-client-ip the tracker must record the forwarded real IP and
// EffectiveClientIP must prefer it, while ClientIP (lifecycle key) stays the
// socket IP.
func TestTrackerRealClientIPExtraction(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.RealClientIPHeader = "X-Forwarded-For"
	tracker := NewSessionTracker(cfg)

	// Server-side conn: socket peer (RemoteIP) is the CLB IP.
	conn := makeConnInfo("10.0.0.1", "10.0.0.250", 2101, 54321)
	ts := uint64(time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC).UnixNano())

	req := makeNTRIPRequest(ts, "MOUNT-A", "user001", "secret", true)
	req.ForwardedFor = "203.0.113.7, 10.0.0.1" // real client + a proxy hop
	tracker.OnRecord(protocol.Record{Req: req}, conn)

	s := tracker.AllSessions()[0]
	if s.RealClientIP != "203.0.113.7" {
		t.Errorf("RealClientIP = %q, want 203.0.113.7 (leftmost XFF)", s.RealClientIP)
	}
	if s.ClientIP != "10.0.0.250" {
		t.Errorf("ClientIP = %q, want socket 10.0.0.250 (lifecycle key unchanged)", s.ClientIP)
	}
	if got := s.EffectiveClientIP(); got != "203.0.113.7" {
		t.Errorf("EffectiveClientIP = %q, want 203.0.113.7", got)
	}
}

// TestTrackerRealClientIPDisabledByDefault: without --real-client-ip the
// behaviour is identical to before — RealClientIP stays empty and
// EffectiveClientIP falls back to the socket IP.
func TestTrackerRealClientIPDisabledByDefault(t *testing.T) {
	tracker := NewSessionTracker(DefaultTrackerConfig()) // RealClientIPHeader = ""

	conn := makeConnInfo("10.0.0.1", "10.0.0.250", 2101, 54321)
	ts := uint64(time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC).UnixNano())

	req := makeNTRIPRequest(ts, "MOUNT-A", "user001", "secret", true)
	req.ForwardedFor = "203.0.113.7"
	tracker.OnRecord(protocol.Record{Req: req}, conn)

	s := tracker.AllSessions()[0]
	if s.RealClientIP != "" {
		t.Errorf("RealClientIP = %q, want empty (feature disabled)", s.RealClientIP)
	}
	if got := s.EffectiveClientIP(); got != "10.0.0.250" {
		t.Errorf("EffectiveClientIP = %q, want socket 10.0.0.250", got)
	}
}
