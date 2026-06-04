package session

import (
	"fmt"
	"net"
	"sync"
	"time"

	"kyanos/agent/protocol"
	"kyanos/agent/protocol/ntrip"
	"kyanos/agent/protocol/rtcm"
)

// ---------------------------------------------------------------------------
// SessionTracker: aggregates per-record events into NTRIP sessions
// ---------------------------------------------------------------------------

// SessionTracker is the central session-level aggregator. It receives parsed
// protocol records from the Kyanos pipeline and maintains a map of active
// NTRIP sessions, updating them with GGA, RTCM, and network quality events.
//
// Install it via InstallHook() which wires into conn.RecordExportFunc.
type SessionTracker struct {
	mu       sync.RWMutex
	sessions map[string]*NTRIPSession // sessionID → session
	config   TrackerConfig

	// Listeners notified on session lifecycle events.
	listeners []SessionListener

	// eventListeners receive granular, real-time diagnostic events (Phase 7).
	// Additive: the existing listeners slice is left untouched; the tracker
	// fires BOTH the lifecycle SessionListener callbacks and these granular
	// SessionEventListener callbacks.
	eventListeners []SessionEventListener
}

// TrackerConfig tunes the tracker behaviour.
type TrackerConfig struct {
	// GGAWarnInterval is the GGA interval threshold for anomaly detection.
	GGAWarnInterval time.Duration
	// RTCMWarnInterval is the RTCM frame gap threshold.
	RTCMWarnInterval time.Duration
	// GGATimeout is the max expected gap between GGA uploads before the server
	// would close the connection. Used for disconnect reason classification.
	GGATimeout time.Duration
	// RetransAbortThreshold is the minimum retransmission count in the window
	// before close to classify as DisconnectRTCMAbort.
	RetransAbortThreshold int
	// RetransAbortWindow is the time window before connection close over which
	// retransmissions are counted for the RTCMAbort heuristic. Only used when a
	// TCPHealthAnalyzer is attached (it has per-event timestamps). When zero,
	// the analyzer's full retransmission history is used.
	RetransAbortWindow time.Duration
	// KickOutWindow is the max time between a new same-username session starting
	// and the old session closing to classify as DisconnectAccountKickOut.
	KickOutWindow time.Duration
	// GGADistanceThreshold is the max expected distance (metres) between two
	// consecutive GGA positions. Exceeding this flags a distance anomaly.
	GGADistanceThreshold float64
	// Correlator configures cross-session reconnection detection.
	Correlator CorrelatorConfig
	// Visibility controls which fields are extracted and displayed.
	Visibility FieldVisibility
	// EnableTCPHealth enables per-session TCP health analysis (S5).
	// When true, each new session gets a TCPHealthAnalyzer attached.
	EnableTCPHealth bool
	// TCPHealthConfig tunes the TCP health analyzer (used when EnableTCPHealth is true).
	TCPHealthConfig TCPHealthConfig
}

// DefaultTrackerConfig returns sensible defaults.
func DefaultTrackerConfig() TrackerConfig {
	return TrackerConfig{
		GGAWarnInterval:       5 * time.Second,
		RTCMWarnInterval:      2 * time.Second,
		GGATimeout:            60 * time.Second,
		RetransAbortThreshold: 5,
		RetransAbortWindow:    30 * time.Second,
		KickOutWindow:         10 * time.Second,
		GGADistanceThreshold:  500.0, // metres
		Correlator:            DefaultCorrelatorConfig(),
		Visibility:            DefaultFieldVisibility(),
		EnableTCPHealth:       false, // opt-in: enable for deep network analysis
		TCPHealthConfig:       DefaultTCPHealthConfig(),
	}
}

// SessionListener receives callbacks on session lifecycle events.
type SessionListener interface {
	OnSessionCreated(s *NTRIPSession)
	OnSessionClosed(s *NTRIPSession)
}

// NewSessionTracker creates a new tracker with the given config.
func NewSessionTracker(cfg TrackerConfig) *SessionTracker {
	return &SessionTracker{
		sessions: make(map[string]*NTRIPSession),
		config:   cfg,
	}
}

// AddListener registers a lifecycle listener.
func (t *SessionTracker) AddListener(l SessionListener) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.listeners = append(t.listeners, l)
}

// AddEventListener registers a granular, real-time event listener (Phase 7).
// This is additive to AddListener: a registered SessionEventListener receives
// per-event auth/GGA/RTCM/network/close callbacks, while existing
// SessionListeners continue to receive only the lifecycle callbacks.
func (t *SessionTracker) AddEventListener(l SessionEventListener) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.eventListeners = append(t.eventListeners, l)
}

// ---------------------------------------------------------------------------
// Record processing
// ---------------------------------------------------------------------------

// ConnInfo holds the minimal connection metadata the tracker needs.
// This decouples the tracker from the full conn.Connection4 type.
type ConnInfo struct {
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  uint16
	RemotePort uint16
	IsServer   bool // true if this agent runs on the server (DS) side
}

// ClientIP returns the client's IP address based on the connection role.
func (c *ConnInfo) ClientIP() string {
	if c.IsServer {
		return c.RemoteIP.String()
	}
	return c.LocalIP.String()
}

// ClientPort returns the client's port.
func (c *ConnInfo) ClientPort() uint16 {
	if c.IsServer {
		return c.RemotePort
	}
	return c.LocalPort
}

// ServerIP returns the server-side IP address based on the connection role.
// On the server (DS) side this is the local IP; on the client side it is the
// remote IP. Used by PodLoadAnalyzer as a fallback aggregation key when no
// K8s Pod name is available.
func (c *ConnInfo) ServerIP() string {
	if c.IsServer {
		return c.LocalIP.String()
	}
	return c.RemoteIP.String()
}

// OnRecord processes a single protocol record, routing it to the appropriate
// NTRIP session based on message type and connection info.
func (t *SessionTracker) OnRecord(record protocol.Record, conn *ConnInfo) {
	if record.Request() == nil {
		return
	}

	req := record.Request()
	resp := record.Response()

	switch msg := req.(type) {
	case *ntrip.NTRIPRequest:
		t.handleNTRIPRequest(msg, resp, conn, record)

	case *ntrip.NTRIPNMEASentence:
		t.handleNMEASentence(msg, conn)

	case *ntrip.NTRIPRTCMFrame:
		t.handleRTCMFrame(msg.Inner, conn)

	case *rtcm.RTCMFrame:
		t.handleRTCMFrame(msg, conn)
	}
}

// OnConnectionClose is called when a tracked connection closes.
// It determines the disconnect reason and notifies listeners.
func (t *SessionTracker) OnConnectionClose(conn *ConnInfo, closeTime time.Time, direction CloseDirection) {
	clientIP := conn.ClientIP()
	clientPort := conn.ClientPort()

	t.mu.Lock()
	var toClose []*NTRIPSession
	for _, s := range t.sessions {
		if s.ClientIP == clientIP && s.ClientPort == clientPort && s.IsActive() {
			toClose = append(toClose, s)
		}
	}
	t.mu.Unlock()

	for _, s := range toClose {
		// Set close direction
		s.mu.Lock()
		s.CloseDirection = direction
		s.mu.Unlock()

		// Refine recentRetransCount to a time-windowed count when a TCP health
		// analyzer is attached (it carries per-event timestamps). This replaces
		// the naive lifetime counter for the RTCMAbort heuristic, so a session
		// that had old retransmissions but a calm final window isn't misclassified.
		s.mu.RLock()
		analyzer := s.TCPAnalyzer
		s.mu.RUnlock()
		if analyzer != nil {
			windowed := analyzer.RetransmissionsInWindow(closeTime, t.config.RetransAbortWindow)
			s.mu.Lock()
			s.recentRetransCount = windowed
			s.mu.Unlock()
		}

		// Check for account kick-out: same username, another active session
		kickout := t.detectKickOut(s, closeTime)

		// Close the session (triggers computeFinalStats)
		s.Close(closeTime)

		// Analyze disconnect reason
		s.AnalyzeDisconnect(
			t.config.GGATimeout,
			t.config.RetransAbortThreshold,
			kickout,
		)

		t.notifyClosed(s)

		// Fire granular session-close event to real-time listeners (Phase 7).
		// This fires regardless of whether the session had any prior auth/GGA/RTCM/
		// network events, satisfying Requirement 4.6.
		t.notifyEventClose(s)
	}
}

// detectKickOut checks whether another session with the same username
// started within the kick-out window around the close time.
func (t *SessionTracker) detectKickOut(closing *NTRIPSession, closeTime time.Time) bool {
	closing.mu.RLock()
	username := closing.Username
	closing.mu.RUnlock()

	if username == "" {
		return false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, s := range t.sessions {
		s.mu.RLock()
		sUser := s.Username
		sStartTime := s.ConnStartTime
		s.mu.RUnlock()
		sActive := s.IsActive()

		if s == closing {
			continue
		}
		if sUser != username {
			continue
		}
		// Another session with the same username exists.
		// If it started shortly before this one closed → kick-out.
		gap := closeTime.Sub(sStartTime)
		if gap >= -t.config.KickOutWindow && gap <= t.config.KickOutWindow {
			return true
		}
		// Also: if this session started while the closing one was still active
		if sActive && sStartTime.After(closing.ConnStartTime) {
			timeDiff := sStartTime.Sub(closing.ConnStartTime)
			if timeDiff <= t.config.KickOutWindow {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Session lookup and creation
// ---------------------------------------------------------------------------

func (t *SessionTracker) sessionKey(clientIP string, clientPort uint16, mountPoint string) string {
	return fmt.Sprintf("%s_%d_%s", clientIP, clientPort, mountPoint)
}

// getOrCreateSession returns the active session for the given key, or creates one.
func (t *SessionTracker) getOrCreateSession(clientIP string, clientPort uint16, mountPoint, username, serverIP string, ts time.Time) *NTRIPSession {
	key := t.sessionKey(clientIP, clientPort, mountPoint)

	t.mu.RLock()
	s, ok := t.sessions[key]
	t.mu.RUnlock()
	if ok && s.IsActive() {
		// Update username if it was empty (first record might not have auth)
		if s.Username == "" && username != "" {
			s.mu.Lock()
			s.Username = username
			s.mu.Unlock()
		}
		return s
	}

	// Create new session
	sessionID := fmt.Sprintf("%s_%s_%d_%s_%d",
		"", // podName placeholder (filled in K8s mode)
		clientIP, clientPort, mountPoint, ts.UnixMilli())

	s = NewNTRIPSession(sessionID, mountPoint, username, clientIP, clientPort, ts)
	s.ServerIP = serverIP

	// Attach TCP health analyzer if enabled
	if t.config.EnableTCPHealth {
		s.TCPAnalyzer = NewTCPHealthAnalyzer(t.config.TCPHealthConfig)
	}

	t.mu.Lock()
	t.sessions[key] = s
	t.mu.Unlock()

	t.notifyCreated(s)
	return s
}

// ---------------------------------------------------------------------------
// Message handlers
// ---------------------------------------------------------------------------

func (t *SessionTracker) handleNTRIPRequest(req *ntrip.NTRIPRequest, resp protocol.ParsedMessage, conn *ConnInfo, record protocol.Record) {
	clientIP := conn.ClientIP()
	clientPort := conn.ClientPort()
	mountPoint := req.MountPoint
	if mountPoint == "" {
		mountPoint = "_unknown_"
	}

	reqTime := time.Unix(0, int64(req.TimestampNs()))
	s := t.getOrCreateSession(clientIP, clientPort, mountPoint, req.Username, conn.ServerIP(), reqTime)

	s.mu.Lock()

	// 识别并标记 NTRIP 会话中各端角色身份
	if req.Method == ntrip.MethodSource || req.Method == ntrip.MethodPost {
		s.ClientRole = "Source"
		s.ServerRole = "Caster"
	} else if req.Method == ntrip.MethodGet {
		s.ClientRole = "Rover"
		s.ServerRole = "Caster"
	}

	// Track last activity
	s.LastActivityTime = reqTime
	s.LastActivityType = "auth"

	// Session identity fields (respecting visibility config)
	if t.config.Visibility.ShowPassword && req.Password != "" {
		s.Password = req.Password
	}
	if t.config.Visibility.ShowNTRIPVersion {
		s.NTRIPVersion = req.Version.String()
	}
	if t.config.Visibility.ShowUserAgent && req.UserAgent != "" {
		s.UserAgent = req.UserAgent
	}

	// Auth info
	if req.HasAuth || req.Method == ntrip.MethodSource {
		s.AuthMethod = authMethodString(req)
	}

	// If we have a response, check auth success/failure
	if resp != nil {
		if ntripResp, ok := resp.(*ntrip.NTRIPResponse); ok {
			s.HTTPStatusCode = ntripResp.StatusCode
			s.AuthChecked = true
			s.AuthSuccess = ntripResp.StatusCode == 200

			// Server response line (e.g. "ICY 200 OK", "ERROR - Bad Password")
			if t.config.Visibility.ShowServerResponse {
				s.ServerResponse = ntripResp.StatusLine
			}

			// Login latency = time from connection start to auth response
			if s.LoginLatency == 0 {
				s.LoginLatency = time.Duration(ntripResp.TimestampNs()-req.TimestampNs()) * time.Nanosecond
			}
		}
	}

	s.mu.Unlock()

	// Fire granular auth event to real-time listeners (Phase 7).
	t.notifyAuthEvent(s)
}

func (t *SessionTracker) handleNMEASentence(nmea *ntrip.NTRIPNMEASentence, conn *ConnInfo) {
	if nmea.SentenceType != "GGA" || !nmea.GGAParsed {
		return
	}

	clientIP := conn.ClientIP()
	clientPort := conn.ClientPort()
	ts := time.Unix(0, int64(nmea.TimestampNs()))

	// Find the session for this client
	s := t.findSessionByClient(clientIP, clientPort)
	if s == nil {
		// GGA before login? Create a session anyway
		s = t.getOrCreateSession(clientIP, clientPort, "_unknown_", "", conn.ServerIP(), ts)
	}

	ggaEvent := s.AddGGAEvent(ts, nmea.Latitude, nmea.Longitude,
		nmea.FixQuality, nmea.NumSatellites, nmea.HDOP,
		nmea.DiffAge, nmea.DiffStationID, nmea.UTCTime)

	// Fire granular GGA event to real-time listeners (Phase 7).
	t.notifyGGAEvent(s, ggaEvent)
}

func (t *SessionTracker) handleRTCMFrame(frame *rtcm.RTCMFrame, conn *ConnInfo) {
	clientIP := conn.ClientIP()
	clientPort := conn.ClientPort()
	ts := time.Unix(0, int64(frame.TimestampNs()))

	s := t.findSessionByClient(clientIP, clientPort)
	if s == nil {
		// RTCM without a known session (e.g., direct RTCM stream)
		s = t.getOrCreateSession(clientIP, clientPort, "direct-rtcm", "", conn.ServerIP(), ts)
	}

	// Extract epoch time from RTCM payload for latency tracking
	var epochTime time.Time
	if epochMs, ok := rtcm.ExtractEpochMs(frame); ok {
		epochTime = rtcm.EpochToUTC(epochMs, frame.MessageType, ts)
	}

	rtcmEvent := s.AddRTCMFrame(ts, frame.MessageType, frame.TotalLen, frame.CRCValid, epochTime)

	// Fire granular RTCM event to real-time listeners (Phase 7).
	t.notifyRTCMEvent(s, rtcmEvent)
}

// ---------------------------------------------------------------------------
// TCP health event handlers (S5)
// ---------------------------------------------------------------------------

// OnTCPRetransmission records a TCP retransmission event for the session
// identified by the client IP/port. This is typically called from the BPF
// kernel event handler when a retransmission is detected.
func (t *SessionTracker) OnTCPRetransmission(conn *ConnInfo, ts time.Time, seq uint32, size int) {
	clientIP := conn.ClientIP()
	clientPort := conn.ClientPort()

	s := t.findSessionByClient(clientIP, clientPort)
	if s == nil {
		return
	}

	s.mu.RLock()
	analyzer := s.TCPAnalyzer
	s.mu.RUnlock()

	if analyzer == nil {
		// Fall back to simple counter
		s.AddRetransmission()
	} else {
		analyzer.RecordRetransmission(ts, seq, size)

		// Also update recent retrans count for disconnect classification
		s.mu.Lock()
		s.recentRetransCount++
		s.mu.Unlock()
	}

	// Fire granular network event to real-time listeners (Phase 7).
	t.notifyNetworkEvent(s, NetworkEventRetransmission)
}

// OnTCPRoundTripTime records an RTT observation for the session.
// seq can be 0 if sequence numbers are not tracked.
func (t *SessionTracker) OnTCPRoundTripTime(conn *ConnInfo, rtt time.Duration, seq uint32, ts time.Time) {
	clientIP := conn.ClientIP()
	clientPort := conn.ClientPort()

	s := t.findSessionByClient(clientIP, clientPort)
	if s == nil {
		return
	}

	s.mu.RLock()
	analyzer := s.TCPAnalyzer
	s.mu.RUnlock()

	if analyzer != nil {
		analyzer.RecordRTTAt(rtt, seq, ts)
	}
	// Also record in session's simple RTT tracker
	s.AddRTT(rtt)

	// Fire granular network event to real-time listeners (Phase 7).
	t.notifyNetworkEvent(s, NetworkEventRTTSample)
}

// OnTCPWindowChange records a TCP window size change for the session.
// If the window shrinks significantly, it is automatically flagged.
func (t *SessionTracker) OnTCPWindowChange(conn *ConnInfo, windowSize int, ts time.Time) {
	clientIP := conn.ClientIP()
	clientPort := conn.ClientPort()

	s := t.findSessionByClient(clientIP, clientPort)
	if s == nil {
		return
	}

	s.mu.RLock()
	analyzer := s.TCPAnalyzer
	s.mu.RUnlock()

	if analyzer != nil {
		analyzer.UpdateWindow(windowSize, ts)
	}

	// Fire granular network event to real-time listeners (Phase 7).
	t.notifyNetworkEvent(s, NetworkEventWindowChange)
}

// OnTCPRetansmitWithPacket records a packet observation using the sequence
// number-based auto-detection. If the same seq is seen again, it is
// automatically counted as a retransmission.
func (t *SessionTracker) OnTCPPacket(conn *ConnInfo, seq uint32, ts time.Time, isRetransmit bool) {
	clientIP := conn.ClientIP()
	clientPort := conn.ClientPort()

	s := t.findSessionByClient(clientIP, clientPort)
	if s == nil {
		return
	}

	s.mu.RLock()
	analyzer := s.TCPAnalyzer
	s.mu.RUnlock()

	if analyzer != nil {
		analyzer.RecordPacket(seq, ts, isRetransmit)
	}
}

// findSessionByClient returns the first active session matching the client IP/port.
func (t *SessionTracker) findSessionByClient(clientIP string, clientPort uint16) *NTRIPSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, s := range t.sessions {
		if s.ClientIP == clientIP && s.ClientPort == clientPort && s.IsActive() {
			return s
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Session queries
// ---------------------------------------------------------------------------

// ActiveSessions returns a snapshot of all active sessions.
func (t *SessionTracker) ActiveSessions() []*NTRIPSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var result []*NTRIPSession
	for _, s := range t.sessions {
		if s.IsActive() {
			result = append(result, s)
		}
	}
	return result
}

// AllSessions returns all sessions (active and closed).
func (t *SessionTracker) AllSessions() []*NTRIPSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]*NTRIPSession, 0, len(t.sessions))
	for _, s := range t.sessions {
		result = append(result, s)
	}
	return result
}

// SessionByMountPoint returns all active sessions for a given mountpoint.
func (t *SessionTracker) SessionByMountPoint(mount string) []*NTRIPSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var result []*NTRIPSession
	for _, s := range t.sessions {
		if s.MountPoint == mount && s.IsActive() {
			result = append(result, s)
		}
	}
	return result
}

// SessionByUsername returns all active sessions for a given username.
func (t *SessionTracker) SessionByUsername(username string) []*NTRIPSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var result []*NTRIPSession
	for _, s := range t.sessions {
		if s.Username == username && s.IsActive() {
			result = append(result, s)
		}
	}
	return result
}

// SessionCount returns the total number of tracked sessions.
func (t *SessionTracker) SessionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// ActiveCount returns the number of active sessions.
func (t *SessionTracker) ActiveCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	count := 0
	for _, s := range t.sessions {
		if s.IsActive() {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Notification helpers
// ---------------------------------------------------------------------------

func (t *SessionTracker) notifyCreated(s *NTRIPSession) {
	t.mu.RLock()
	listeners := make([]SessionListener, len(t.listeners))
	copy(listeners, t.listeners)
	t.mu.RUnlock()
	for _, l := range listeners {
		l.OnSessionCreated(s)
	}
}

func (t *SessionTracker) notifyClosed(s *NTRIPSession) {
	t.mu.RLock()
	listeners := make([]SessionListener, len(t.listeners))
	copy(listeners, t.listeners)
	t.mu.RUnlock()
	for _, l := range listeners {
		l.OnSessionClosed(s)
	}
}

// ---------------------------------------------------------------------------
// Granular event listener notification helpers (Phase 7)
// ---------------------------------------------------------------------------

func (t *SessionTracker) notifyAuthEvent(s *NTRIPSession) {
	t.mu.RLock()
	els := make([]SessionEventListener, len(t.eventListeners))
	copy(els, t.eventListeners)
	t.mu.RUnlock()
	for _, l := range els {
		l.OnAuthEvent(s)
	}
}

func (t *SessionTracker) notifyGGAEvent(s *NTRIPSession, e GGAEvent) {
	t.mu.RLock()
	els := make([]SessionEventListener, len(t.eventListeners))
	copy(els, t.eventListeners)
	t.mu.RUnlock()
	for _, l := range els {
		l.OnGGAEvent(s, e)
	}
}

func (t *SessionTracker) notifyRTCMEvent(s *NTRIPSession, e RTCMEvent) {
	t.mu.RLock()
	els := make([]SessionEventListener, len(t.eventListeners))
	copy(els, t.eventListeners)
	t.mu.RUnlock()
	for _, l := range els {
		l.OnRTCMEvent(s, e)
	}
}

func (t *SessionTracker) notifyNetworkEvent(s *NTRIPSession, kind NetworkEventKind) {
	t.mu.RLock()
	els := make([]SessionEventListener, len(t.eventListeners))
	copy(els, t.eventListeners)
	t.mu.RUnlock()
	for _, l := range els {
		l.OnNetworkEvent(s, kind)
	}
}

func (t *SessionTracker) notifyEventClose(s *NTRIPSession) {
	t.mu.RLock()
	els := make([]SessionEventListener, len(t.eventListeners))
	copy(els, t.eventListeners)
	t.mu.RUnlock()
	for _, l := range els {
		l.OnSessionClose(s)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func authMethodString(req *ntrip.NTRIPRequest) string {
	if req.HasAuth {
		return "basic_auth"
	}
	if req.Method == ntrip.MethodSource {
		return "source_method"
	}
	return "none"
}

// FindActiveSession searches for an active session matching the given client IP and port.
// It is safe for concurrent use.
func (t *SessionTracker) FindActiveSession(clientIP string, clientPort uint16) (*NTRIPSession, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, s := range t.sessions {
		if s.ClientIP == clientIP && s.ClientPort == clientPort && s.IsActive() {
			return s, true
		}
	}
	return nil, false
}

