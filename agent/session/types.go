// Package session provides NTRIP session-level tracking and diagnostics,
// built on top of Kyanos's per-record protocol parsing pipeline.
package session

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Core session type
// ---------------------------------------------------------------------------

// NTRIPSession represents a single NTRIP client session lifecycle:
// from TCP connection establishment through authentication, data streaming,
// and eventual disconnection.
type NTRIPSession struct {
	mu sync.RWMutex

	// Identity
	SessionID    string // podName_clientIP_clientPort_mountpoint_startTime
	MountPoint   string
	Username     string
	Password     string // NTRIP account password (from auth header)
	NTRIPVersion string // "NTRIPv1" or "NTRIPv2"
	UserAgent    string // Client User-Agent string
	ClientIP     string
	ClientPort   uint16
	// RealClientIP is the load-balancer-forwarded real client IP (extracted
	// from X-Forwarded-For / X-Real-IP), when --real-client-ip is enabled.
	// Empty means: feature disabled, or no forwarding header was observed.
	// ClientIP above stays the socket peer IP (used for connection lifecycle
	// matching) — see EffectiveClientIP().
	RealClientIP string
	ServerPod    string // DS Pod handling this connection (empty if not in K8s mode)
	ServerNode   string // Node where DS Pod runs
	ServerIP     string // Server-side IP; used as pod-load fallback key when ServerPod is empty
	ClientRole   string // "Rover" | "Source" | "Unknown"
	ServerRole   string // "Caster" | "Unknown"

	// Connection timing
	ConnStartTime time.Time
	ConnCloseTime *time.Time // nil while active

	// Authentication analysis (S1)
	AuthMethod     string // "basic_auth", "source_method", "none"
	AuthSuccess    bool
	AuthChecked    bool // whether we've seen a response to the auth request
	HTTPStatusCode int
	ServerResponse string        // raw server status line (e.g. "ICY 200 OK", "ERROR - Bad Password")
	LoginLatency   time.Duration // TCP connect → auth response

	// GGA upload analysis (S2)
	GGAEvents    []GGAEvent
	GGAFrequency float64 // avg uploads/sec (computed on close or periodically)

	// RTCM delivery analysis (S3)
	RTCMStats  RTCMDeliveryStats
	RTCMEvents []RTCMEvent // optional per-frame log (bounded ring buffer)

	// Network quality analysis (S5)
	NetworkQuality NetworkQualityStats
	TCPAnalyzer    *TCPHealthAnalyzer // optional TCP health analyzer for deep analysis

	// Disconnect analysis (S4)
	DisconnectReason DisconnectReason
	DisconnectDetail string         // human-readable explanation
	LastActivityTime time.Time      // timestamp of last observed activity
	LastActivityType string         // "gga", "rtcm", "auth", "other"
	CloseDirection   CloseDirection // who initiated the close

	// Internal bookkeeping
	lastGGATimestamp   time.Time
	lastGGALat         float64
	lastGGALon         float64
	lastRTCMTime       time.Time
	rtcmFrameCount     int
	rtcmTotalBytes     int64
	rtcmCRCErrors      int
	rtcmMsgTypes       map[int]int
	rtcmIntervals      []time.Duration // for percentile computation
	rttSamples         []time.Duration // raw RTT observations for stats
	rtcmLatencySamples []time.Duration // RTCM epoch-to-capture latency samples
	recentRetransCount int             // retransmissions in last N seconds before close
}

// NewNTRIPSession creates a session with sensible defaults.
func NewNTRIPSession(id, mountPoint, username, clientIP string, clientPort uint16, startTime time.Time) *NTRIPSession {
	return &NTRIPSession{
		SessionID:     id,
		MountPoint:    mountPoint,
		Username:      username,
		ClientIP:      clientIP,
		ClientPort:    clientPort,
		ConnStartTime: startTime,
		rtcmMsgTypes:  make(map[int]int),
	}
}

// IsActive returns true if the session has not been closed yet.
func (s *NTRIPSession) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ConnCloseTime == nil
}

// Duration returns the session duration so far (or total if closed).
func (s *NTRIPSession) Duration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.durationLocked()
}

// durationLocked returns the session duration. The caller MUST hold s.mu
// (read or write). Extracted so callers already holding the lock (e.g. Score)
// don't re-acquire it — RWMutex read locks are not reentrant and re-acquiring
// while a writer is queued can deadlock.
func (s *NTRIPSession) durationLocked() time.Duration {
	if s.ConnCloseTime != nil {
		return s.ConnCloseTime.Sub(s.ConnStartTime)
	}
	return time.Since(s.ConnStartTime)
}

// RTCMFrameCount returns the number of RTCM frames observed so far. Unlike
// RTCMStats.TotalFrames (which is only finalized on Close), this live counter
// is valid for active sessions too, so aggregators such as PodLoadAnalyzer can
// compute frame rates while sessions are still running.
func (s *NTRIPSession) RTCMFrameCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rtcmFrameCount
}

// RTCMTotalBytes returns the total RTCM payload bytes observed so far (live).
func (s *NTRIPSession) RTCMTotalBytes() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rtcmTotalBytes
}

// GGAEventCount returns the number of GGA events observed so far.
func (s *NTRIPSession) GGAEventCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.GGAEvents)
}

// EffectiveClientIP returns the client IP to use for semantic identity
// (cross-session correlation, unique-client aggregation, display, export).
// Behind a load balancer (CLB), ClientIP is the LB's socket IP and identical
// across all real clients, so we prefer the forwarded RealClientIP when it is
// set. Callers that already hold s.mu should read the fields directly.
//
// ClientIP (the socket peer) is NOT changed and remains the key for connection
// lifecycle matching (getOrCreateSession / OnConnectionClose / findSessionByClient).
func (s *NTRIPSession) EffectiveClientIP() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return effectiveIP(s.RealClientIP, s.ClientIP)
}

// effectiveIP returns realIP when non-empty, otherwise socketIP. It is a
// lock-free helper for callers that already hold the session's mutex; use
// EffectiveClientIP() when not holding the lock.
func effectiveIP(realIP, socketIP string) string {
	if realIP != "" {
		return realIP
	}
	return socketIP
}

// RTCMFrameRate returns the average RTCM frames-per-second over the session's
// duration so far. Returns 0 when the duration is non-positive or no frames
// have been seen.
func (s *NTRIPSession) RTCMFrameRate() float64 {
	s.mu.RLock()
	count := s.rtcmFrameCount
	start := s.ConnStartTime
	closeTime := s.ConnCloseTime
	s.mu.RUnlock()

	if count == 0 {
		return 0
	}
	var span time.Duration
	if closeTime != nil {
		span = closeTime.Sub(start)
	} else {
		span = time.Since(start)
	}
	if span <= 0 {
		return 0
	}
	return float64(count) / span.Seconds()
}

// Close marks the session as closed.
func (s *NTRIPSession) Close(closeTime time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ConnCloseTime = &closeTime
	s.computeFinalStats()
}

// computeFinalStats is called when the session closes to compute summary metrics.
// Must be called with s.mu held.
func (s *NTRIPSession) computeFinalStats() {
	s.computeGGAFrequency()
	s.computeRTCMStats()
	s.computeNetworkStats()
	// If a TCP health analyzer is attached, use it to refine network stats
	if s.TCPAnalyzer != nil {
		s.TCPAnalyzer.ComputeFinalStats(&s.NetworkQuality)
	}
}

// ---------------------------------------------------------------------------
// GGA event types (S2)
// ---------------------------------------------------------------------------

// GGAEvent records a single GGA position upload from the NTRIP client.
type GGAEvent struct {
	Timestamp     time.Time     // eBPF capture time (system clock)
	GGAUtcTime    time.Time     // parsed UTC time from GGA sentence (zero if not parsed)
	Latency       time.Duration // capture_time - gga_utc_time (positive = system clock ahead)
	Latitude      float64
	Longitude     float64
	FixQuality    int // 0=invalid, 1=GPS, 2=DGPS, 4=RTK-fixed, 5=RTK-float
	NumSatellites int
	HDOP          float64
	DiffAge       float64       // age of differential GPS data in seconds (-1 if not present)
	DiffStationID string        // differential reference station ID (empty if not present)
	Interval      time.Duration // time since previous GGA (0 for first)
	Distance      float64       // metres from previous GGA position (0 for first)
}

// AddGGAEvent appends a GGA event and computes the interval and distance from
// the previous one. ggaUtcStr is the raw UTC time string from the GGA sentence
// (format "hhmmss.ss"); pass "" if not available.
//
// It returns the GGAEvent that was appended so callers (e.g. the SessionTracker)
// can forward the exact event to real-time listeners without re-reading the
// session under lock. Existing callers that ignore the return value continue to
// compile unchanged.
func (s *NTRIPSession) AddGGAEvent(ts time.Time, lat, lon float64, fix, sats int, hdop float64, diffAge float64, diffStationID string, ggaUtcStr string) GGAEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	interval := time.Duration(0)
	distance := 0.0
	if !s.lastGGATimestamp.IsZero() {
		interval = ts.Sub(s.lastGGATimestamp)
		distance = Haversine(s.lastGGALat, s.lastGGALon, lat, lon)
	}

	// Parse GGA UTC time and compute latency
	var ggaUtc time.Time
	var ggaLatency time.Duration
	if ggaUtcStr != "" {
		ggaUtc = ParseGGAUtcTime(ggaUtcStr, ts)
		if !ggaUtc.IsZero() {
			ggaLatency = ts.Sub(ggaUtc)
		}
	}

	s.GGAEvents = append(s.GGAEvents, GGAEvent{
		Timestamp:     ts,
		GGAUtcTime:    ggaUtc,
		Latency:       ggaLatency,
		Latitude:      lat,
		Longitude:     lon,
		FixQuality:    fix,
		NumSatellites: sats,
		HDOP:          hdop,
		DiffAge:       diffAge,
		DiffStationID: diffStationID,
		Interval:      interval,
		Distance:      distance,
	})
	s.lastGGATimestamp = ts
	s.lastGGALat = lat
	s.lastGGALon = lon
	s.LastActivityTime = ts
	s.LastActivityType = "gga"

	return s.GGAEvents[len(s.GGAEvents)-1]
}

// GGAIntervalAnomalies returns GGA events where the interval exceeds the threshold.
func (s *NTRIPSession) GGAIntervalAnomalies(threshold time.Duration) []GGAEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var anomalies []GGAEvent
	for _, e := range s.GGAEvents {
		if e.Interval > threshold {
			anomalies = append(anomalies, e)
		}
	}
	return anomalies
}

// computeGGAFrequency sets GGAFrequency based on total events and duration.
// Must be called with s.mu held.
func (s *NTRIPSession) computeGGAFrequency() {
	n := len(s.GGAEvents)
	if n < 2 {
		s.GGAFrequency = 0
		return
	}
	span := s.GGAEvents[n-1].Timestamp.Sub(s.GGAEvents[0].Timestamp)
	if span <= 0 {
		s.GGAFrequency = 0
		return
	}
	s.GGAFrequency = float64(n-1) / span.Seconds()
}

// ---------------------------------------------------------------------------
// RTCM event types (S3)
// ---------------------------------------------------------------------------

// RTCMEvent records a single RTCM frame delivery (optional detailed log).
type RTCMEvent struct {
	Timestamp   time.Time     // eBPF capture time (system clock)
	EpochTime   time.Time     // GNSS epoch time from RTCM payload (zero if not extracted)
	Latency     time.Duration // capture_time - epoch_time (positive = delay)
	MessageType int
	Size        int
	CRCValid    bool
	Interval    time.Duration // time since previous RTCM frame
}

// RTCMDeliveryStats holds aggregated RTCM delivery metrics.
type RTCMDeliveryStats struct {
	TotalFrames   int
	CRCErrors     int
	CRCErrorRate  float64 // 0.0 - 1.0
	TotalBytes    int64
	AvgInterval   time.Duration
	MaxInterval   time.Duration
	MinInterval   time.Duration
	P95Interval   time.Duration
	ThroughputBps float64 // bytes per second
	MessageTypes  map[int]int

	Interruptions []RTCMInterruption
}

// RTCMInterruption represents a gap in RTCM delivery exceeding the threshold.
type RTCMInterruption struct {
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
}

// AddRTCMFrame records a new RTCM frame arrival.
// epochTime is the GNSS epoch time extracted from the RTCM payload (zero if unavailable).
//
// It returns the RTCMEvent describing the frame so callers (e.g. the
// SessionTracker) can forward the exact event to real-time listeners. The event
// is returned even when it is not retained in the bounded RTCMEvents log.
// Existing callers that ignore the return value continue to compile unchanged.
func (s *NTRIPSession) AddRTCMFrame(ts time.Time, msgType, size int, crcValid bool, epochTime time.Time) RTCMEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	interval := time.Duration(0)
	if !s.lastRTCMTime.IsZero() {
		interval = ts.Sub(s.lastRTCMTime)
	}

	// Compute RTCM latency: capture_time - epoch_time
	var latency time.Duration
	if !epochTime.IsZero() {
		latency = ts.Sub(epochTime)
	}

	s.rtcmFrameCount++
	s.rtcmTotalBytes += int64(size)
	if !crcValid {
		s.rtcmCRCErrors++
	}
	s.rtcmMsgTypes[msgType]++

	if interval > 0 {
		s.rtcmIntervals = append(s.rtcmIntervals, interval)
	}

	// Track latency samples
	if latency > 0 {
		s.rtcmLatencySamples = append(s.rtcmLatencySamples, latency)
	}

	event := RTCMEvent{
		Timestamp:   ts,
		EpochTime:   epochTime,
		Latency:     latency,
		MessageType: msgType,
		Size:        size,
		CRCValid:    crcValid,
		Interval:    interval,
	}

	// Optionally keep in RTCMEvents (bounded to prevent memory blowup)
	if len(s.RTCMEvents) < 100000 {
		s.RTCMEvents = append(s.RTCMEvents, event)
	}

	s.lastRTCMTime = ts
	s.LastActivityTime = ts
	s.LastActivityType = "rtcm"

	return event
}

// RTCMInterruptions returns intervals exceeding the given threshold.
func (s *NTRIPSession) RTCMInterruptions(threshold time.Duration) []RTCMInterruption {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []RTCMInterruption
	for _, ev := range s.RTCMEvents {
		if ev.Interval > threshold {
			result = append(result, RTCMInterruption{
				StartTime: ev.Timestamp.Add(-ev.Interval),
				EndTime:   ev.Timestamp,
				Duration:  ev.Interval,
			})
		}
	}
	return result
}

// computeRTCMStats finalizes RTCM delivery statistics.
// Must be called with s.mu held.
func (s *NTRIPSession) computeRTCMStats() {
	stats := &s.RTCMStats
	stats.TotalFrames = s.rtcmFrameCount
	stats.CRCErrors = s.rtcmCRCErrors
	stats.TotalBytes = s.rtcmTotalBytes
	stats.MessageTypes = make(map[int]int, len(s.rtcmMsgTypes))
	for k, v := range s.rtcmMsgTypes {
		stats.MessageTypes[k] = v
	}

	if s.rtcmFrameCount > 0 {
		stats.CRCErrorRate = float64(s.rtcmCRCErrors) / float64(s.rtcmFrameCount)
	}

	n := len(s.rtcmIntervals)
	if n == 0 {
		return
	}

	// Sort intervals for percentile computation
	sortedIntervals := make([]time.Duration, n)
	copy(sortedIntervals, s.rtcmIntervals)
	sortDurations(sortedIntervals)

	var total time.Duration
	stats.MinInterval = sortedIntervals[0]
	stats.MaxInterval = sortedIntervals[n-1]
	for _, d := range sortedIntervals {
		total += d
	}
	stats.AvgInterval = total / time.Duration(n)
	stats.P95Interval = sortedIntervals[int(float64(n)*0.95)]

	// Detect interruptions (intervals > 2× the average)
	threshold := stats.AvgInterval * 2
	if threshold < 500*time.Millisecond {
		threshold = 500 * time.Millisecond
	}
	for _, ev := range s.RTCMEvents {
		if ev.Interval > threshold {
			stats.Interruptions = append(stats.Interruptions, RTCMInterruption{
				StartTime: ev.Timestamp.Add(-ev.Interval),
				EndTime:   ev.Timestamp,
				Duration:  ev.Interval,
			})
		}
	}

	// Throughput
	if s.rtcmFrameCount > 1 && !s.lastRTCMTime.IsZero() {
		firstRTCM := s.RTCMEvents[0].Timestamp
		span := s.lastRTCMTime.Sub(firstRTCM)
		if span > 0 {
			stats.ThroughputBps = float64(s.rtcmTotalBytes) / span.Seconds()
		}
	}
}

// ---------------------------------------------------------------------------
// Network quality types (S5)
// ---------------------------------------------------------------------------

// NetworkQualityStats holds TCP-level quality indicators for a session.
type NetworkQualityStats struct {
	TotalRetransmissions int
	RetransmissionRate   float64 // 0.0 - 1.0
	AvgRTT               time.Duration
	MaxRTT               time.Duration
	P95RTT               time.Duration
	RTTJitter            time.Duration // standard deviation
	WindowSizeMin        int
	TCPResetEvents       []TCPResetEvent
	ConnectionMigrations int // IP changes (same user, different IP)
}

// TCPResetEvent records a TCP RST.
type TCPResetEvent struct {
	Timestamp time.Time
	Direction string // "inbound" or "outbound"
}

// AddRTT records a round-trip time observation.
func (s *NTRIPSession) AddRTT(rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NetworkQuality.MaxRTT = maxDuration(s.NetworkQuality.MaxRTT, rtt)
	// Running average and jitter updated at finalization
	s.rttSamples = append(s.rttSamples, rtt)
}

// AddRetransmission increments the retransmission counter.
func (s *NTRIPSession) AddRetransmission() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NetworkQuality.TotalRetransmissions++
}

// AddTCPReset records a TCP reset event.
func (s *NTRIPSession) AddTCPReset(ts time.Time, direction string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NetworkQuality.TCPResetEvents = append(s.NetworkQuality.TCPResetEvents, TCPResetEvent{
		Timestamp: ts,
		Direction: direction,
	})
}

// computeNetworkStats finalizes network quality statistics.
// Must be called with s.mu held.
func (s *NTRIPSession) computeNetworkStats() {
	nq := &s.NetworkQuality
	n := len(s.rttSamples)
	if n == 0 {
		return
	}

	sorted := make([]time.Duration, n)
	copy(sorted, s.rttSamples)
	sortDurations(sorted)

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	nq.AvgRTT = total / time.Duration(n)
	nq.P95RTT = sorted[int(float64(n)*0.95)]
	nq.MaxRTT = sorted[n-1]

	// Standard deviation (jitter)
	avg := float64(nq.AvgRTT)
	var variance float64
	for _, d := range s.rttSamples {
		diff := float64(d) - avg
		variance += diff * diff
	}
	variance /= float64(n)
	nq.RTTJitter = time.Duration(math.Sqrt(variance))
}

// ---------------------------------------------------------------------------
// Reconnect event types (S4)
// ---------------------------------------------------------------------------

// ReconnectEvent describes a detected reconnection by the same user.
type ReconnectEvent struct {
	OldSessionID string
	NewSessionID string
	OldClientIP  string
	NewClientIP  string
	Disconnect   time.Time
	Reconnect    time.Time
	Downtime     time.Duration
	IPChanged    bool // true → suspected WiFi/4G switch
}

// CorrelatorConfig tunes the session correlation behaviour.
type CorrelatorConfig struct {
	ReconnectWindow   time.Duration // max gap to consider it a "reconnect" (default 60s)
	IPChangeThreshold time.Duration // max gap to correlate IP changes (default 120s)
}

// DefaultCorrelatorConfig returns sensible defaults.
func DefaultCorrelatorConfig() CorrelatorConfig {
	return CorrelatorConfig{
		ReconnectWindow:   60 * time.Second,
		IPChangeThreshold: 120 * time.Second,
	}
}

// ---------------------------------------------------------------------------
// Disconnect reason classification (S4)
// ---------------------------------------------------------------------------

// DisconnectReason classifies why an NTRIP session was terminated.
type DisconnectReason int

const (
	// DisconnectUnknown is the default when no heuristic matches.
	DisconnectUnknown DisconnectReason = iota

	// DisconnectGGATimeout: server-side disconnect because the client failed
	// to upload GGA within the server's timeout window.
	// Heuristic: last activity was a long time ago, last activity type is "gga"
	// or GGA stopped well before disconnect, close was server-initiated.
	DisconnectGGATimeout

	// DisconnectClientInitiated: the client sent TCP FIN to close the connection.
	// Heuristic: CloseDirection == CloseClient.
	DisconnectClientInitiated

	// DisconnectRTCMAbort: server-side disconnect because RTCM retransmissions
	// exceeded a threshold (server gave up on congested link).
	// Heuristic: high retransmission count shortly before disconnect,
	// close was server-initiated.
	DisconnectRTCMAbort

	// DisconnectAccountKickOut: same username connected from another session,
	// causing this session to be forcibly closed by the server.
	// Heuristic: another session with the same username started within a
	// narrow time window, and this session was closed server-side.
	DisconnectAccountKickOut

	// DisconnectAuthFailed: server-side disconnect due to authentication failure
	// (wrong credentials or subscription expired).
	// Heuristic: auth was checked and failed (HTTP 401/403), or session
	// lifetime is very short with an auth failure.
	DisconnectAuthFailed
)

var disconnectReasonNames = map[DisconnectReason]string{
	DisconnectUnknown:         "unknown",
	DisconnectGGATimeout:      "gga_timeout",
	DisconnectClientInitiated: "client_initiated",
	DisconnectRTCMAbort:       "rtcm_retransmission_abort",
	DisconnectAccountKickOut:  "account_kickout",
	DisconnectAuthFailed:      "auth_failed",
}

func (d DisconnectReason) String() string {
	if name, ok := disconnectReasonNames[d]; ok {
		return name
	}
	return "unknown"
}

// CloseDirection indicates which side initiated the TCP close.
type CloseDirection int

const (
	CloseDirectionUnknown CloseDirection = iota
	CloseClient                          // client sent FIN/RST
	CloseServer                          // server sent FIN/RST
	CloseReset                           // connection was reset (direction unclear)
)

func (d CloseDirection) String() string {
	switch d {
	case CloseClient:
		return "client"
	case CloseServer:
		return "server"
	case CloseReset:
		return "reset"
	default:
		return "unknown"
	}
}

// AnalyzeDisconnect applies heuristics to classify the disconnect reason.
// Call this after the session is closed and all data has been collected.
// kickoutDetected should be true if the correlator found a same-username
// session starting within the kick-out window.
func (s *NTRIPSession) AnalyzeDisconnect(ggaTimeout time.Duration, retransThreshold int, kickoutDetected bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Rule 5: Auth failure (strongest signal — only when response was captured)
	if s.AuthChecked && !s.AuthSuccess && s.HTTPStatusCode > 0 {
		s.DisconnectReason = DisconnectAuthFailed
		s.DisconnectDetail = fmt.Sprintf("Auth failed: HTTP %d", s.HTTPStatusCode)
		return
	}

	// Rule 4: Account kick-out (correlator-provided signal)
	if kickoutDetected {
		s.DisconnectReason = DisconnectAccountKickOut
		s.DisconnectDetail = "Same username connected from another session"
		return
	}

	// Rule 2: Client-initiated close
	if s.CloseDirection == CloseClient {
		s.DisconnectReason = DisconnectClientInitiated
		s.DisconnectDetail = "Client sent TCP FIN"
		return
	}

	// Rule 3: RTCM retransmission abort
	if s.CloseDirection == CloseServer && s.recentRetransCount >= retransThreshold {
		s.DisconnectReason = DisconnectRTCMAbort
		s.DisconnectDetail = fmt.Sprintf("Server closed after %d retransmissions", s.recentRetransCount)
		return
	}

	// Rule 1: GGA timeout
	if s.CloseDirection == CloseServer && len(s.GGAEvents) > 0 && s.ConnCloseTime != nil {
		timeSinceLastGGA := s.ConnCloseTime.Sub(s.lastGGATimestamp)
		if timeSinceLastGGA > ggaTimeout {
			s.DisconnectReason = DisconnectGGATimeout
			s.DisconnectDetail = fmt.Sprintf("No GGA for %s before server close (threshold %s)",
				timeSinceLastGGA.Round(time.Second), ggaTimeout)
			return
		}
	}
	// Also check if GGA was expected but never arrived
	if s.CloseDirection == CloseServer && len(s.GGAEvents) == 0 &&
		s.MountPoint != "" && s.MountPoint != "_unknown_" && s.MountPoint != "direct-rtcm" {
		s.DisconnectReason = DisconnectGGATimeout
		s.DisconnectDetail = "No GGA uploaded during entire session, server closed connection"
		return
	}

	// Rule 6: Unknown
	s.DisconnectReason = DisconnectUnknown
	s.DisconnectDetail = fmt.Sprintf("Close direction: %s, last activity: %s at %s",
		s.CloseDirection, s.LastActivityType, s.LastActivityTime.Format(time.RFC3339))
}

// GGADistanceAnomalies returns GGA events where the distance from the previous
// position exceeds the given threshold (in metres).
func (s *NTRIPSession) GGADistanceAnomalies(thresholdMetres float64) []GGAEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var anomalies []GGAEvent
	for _, e := range s.GGAEvents {
		if e.Distance > thresholdMetres {
			anomalies = append(anomalies, e)
		}
	}
	return anomalies
}

// ---------------------------------------------------------------------------
// GGA aggregate summary
// ---------------------------------------------------------------------------

// GGASummary holds aggregated GGA statistics for a session.
type GGASummary struct {
	TotalEvents     int
	FixDistribution map[int]int // FixQuality → count (0=invalid,1=GPS,2=DGPS,4=RTK-fixed,5=RTK-float)
	FixRate         float64     // ratio of RTK-fixed (quality=4) events to total
	AvgSatellites   float64
	MinSatellites   int
	MaxSatellites   int
	AvgDiffAge      float64 // average differential age (seconds, only for valid values ≥0)
	MaxDiffAge      float64
	StationIDs      []string // unique differential reference station IDs observed
}

// ComputeGGASummary returns an aggregated view of all GGA events in this session.
func (s *NTRIPSession) ComputeGGASummary() GGASummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	summary := GGASummary{
		FixDistribution: make(map[int]int),
		MinSatellites:   -1, // sentinel so we can detect first event
	}

	n := len(s.GGAEvents)
	summary.TotalEvents = n
	if n == 0 {
		summary.MinSatellites = 0
		return summary
	}

	var totalSats int
	var diffAgeSum float64
	var diffAgeCount int
	stations := make(map[string]struct{})

	for _, e := range s.GGAEvents {
		summary.FixDistribution[e.FixQuality]++
		if e.FixQuality == 4 {
			// RTK-fixed
		}

		totalSats += e.NumSatellites
		if e.NumSatellites < summary.MinSatellites || summary.MinSatellites == -1 {
			summary.MinSatellites = e.NumSatellites
		}
		if e.NumSatellites > summary.MaxSatellites {
			summary.MaxSatellites = e.NumSatellites
		}

		if e.DiffAge >= 0 {
			diffAgeSum += e.DiffAge
			diffAgeCount++
			if e.DiffAge > summary.MaxDiffAge {
				summary.MaxDiffAge = e.DiffAge
			}
		}

		if e.DiffStationID != "" {
			stations[e.DiffStationID] = struct{}{}
		}
	}

	// Fix rate = RTK-fixed / total
	if fixed, ok := summary.FixDistribution[4]; ok {
		summary.FixRate = float64(fixed) / float64(n)
	}

	summary.AvgSatellites = float64(totalSats) / float64(n)

	if diffAgeCount > 0 {
		summary.AvgDiffAge = diffAgeSum / float64(diffAgeCount)
	}

	summary.StationIDs = make([]string, 0, len(stations))
	for id := range stations {
		summary.StationIDs = append(summary.StationIDs, id)
	}

	return summary
}

// ---------------------------------------------------------------------------
// Field visibility configuration
// ---------------------------------------------------------------------------

// FieldVisibility controls which session fields are extracted and displayed.
// Set a field to false to skip extraction/display for that attribute.
type FieldVisibility struct {
	// Session identity fields
	ShowPassword     bool
	ShowNTRIPVersion bool
	ShowUserAgent    bool
	ShowMountPoint   bool

	// Auth / server response fields
	ShowServerResponse bool
	ShowHTTPStatus     bool

	// GGA detail fields
	ShowFixQuality  bool
	ShowSatellites  bool
	ShowDiffAge     bool
	ShowDiffStation bool
	ShowHDOP        bool
	ShowDistance    bool

	// Duration is always computed; this controls display
	ShowDuration bool
}

// DefaultFieldVisibility returns a configuration that shows all standard fields
// but hides the password (security-sensitive).
func DefaultFieldVisibility() FieldVisibility {
	return FieldVisibility{
		ShowPassword:       false, // hidden by default for security
		ShowNTRIPVersion:   true,
		ShowUserAgent:      true,
		ShowMountPoint:     true,
		ShowServerResponse: true,
		ShowHTTPStatus:     true,
		ShowFixQuality:     true,
		ShowSatellites:     true,
		ShowDiffAge:        true,
		ShowDiffStation:    true,
		ShowHDOP:           true,
		ShowDistance:       true,
		ShowDuration:       true,
	}
}

// ---------------------------------------------------------------------------
// Diagnostic scoring
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Diagnostic scoring
// ---------------------------------------------------------------------------
//
// The scoring types and the Score() method live in scoring.go.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// sortDurations sorts a slice of durations in ascending order. Uses the stdlib
// pattern-defeating quicksort (sort.Slice), which is O(n log n) and well-suited
// to the larger sample sets (RTT/interval histograms) collected over long-lived
// sessions.
func sortDurations(d []time.Duration) {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
}

// Haversine computes the great-circle distance in metres between two
// geographic coordinates (decimal degrees).
func Haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371000.0 // metres

	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadius * c
}

// ---------------------------------------------------------------------------
// GGA UTC time parsing
// ---------------------------------------------------------------------------

// ParseGGAUtcTime parses the GGA UTC time string (format "hhmmss.ss") and
// combines it with the date portion of the capture timestamp to produce a
// full time.Time in UTC.
//
// The GGA sentence only carries time-of-day, so we borrow the date from the
// capture timestamp.  If the parsed time-of-day is more than 12 hours ahead
// of the capture time-of-day we assume the date wrapped backwards (midnight
// crossing) and subtract one day.
func ParseGGAUtcTime(ggaUtcStr string, captureTime time.Time) time.Time {
	if len(ggaUtcStr) < 6 {
		return time.Time{}
	}

	hour, err1 := strconv.Atoi(ggaUtcStr[0:2])
	min, err2 := strconv.Atoi(ggaUtcStr[2:4])
	secStr := ggaUtcStr[4:]
	sec, err3 := strconv.ParseFloat(secStr, 64)
	if err1 != nil || err2 != nil || err3 != nil || hour > 23 || min > 59 || sec >= 60 {
		return time.Time{}
	}

	wholeSec := int(sec)
	nanos := int((sec - float64(wholeSec)) * 1e9)

	captureUTC := captureTime.UTC()
	ggaUtc := time.Date(
		captureUTC.Year(), captureUTC.Month(), captureUTC.Day(),
		hour, min, wholeSec, nanos, time.UTC,
	)

	// Handle midnight wrap: if GGA time is far ahead of capture time-of-day,
	// it likely belongs to the previous day.
	captureTOD := time.Duration(captureUTC.Hour())*time.Hour +
		time.Duration(captureUTC.Minute())*time.Minute +
		time.Duration(captureUTC.Second())*time.Second
	ggaTOD := time.Duration(hour)*time.Hour +
		time.Duration(min)*time.Minute +
		time.Duration(wholeSec)*time.Second

	if ggaTOD-captureTOD > 12*time.Hour {
		ggaUtc = ggaUtc.AddDate(0, 0, -1)
	} else if captureTOD-ggaTOD > 12*time.Hour {
		ggaUtc = ggaUtc.AddDate(0, 0, 1)
	}

	return ggaUtc
}

// ---------------------------------------------------------------------------
// Latency statistics
// ---------------------------------------------------------------------------

// LatencyStats holds aggregated latency measurements.
type LatencyStats struct {
	Count  int
	Avg    time.Duration
	Min    time.Duration
	Max    time.Duration
	P50    time.Duration
	P95    time.Duration
	P99    time.Duration
	Jitter time.Duration // standard deviation
}

// ComputeLatencyStats computes descriptive statistics from a slice of latency
// observations.
func ComputeLatencyStats(samples []time.Duration) LatencyStats {
	n := len(samples)
	stats := LatencyStats{Count: n}
	if n == 0 {
		return stats
	}

	sorted := make([]time.Duration, n)
	copy(sorted, samples)
	sortDurations(sorted)

	stats.Min = sorted[0]
	stats.Max = sorted[n-1]

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	stats.Avg = total / time.Duration(n)

	stats.P50 = sorted[int(float64(n)*0.50)]
	stats.P95 = sorted[int(float64(n)*0.95)]
	if n > 1 {
		stats.P99 = sorted[int(math.Min(float64(n)-1, float64(n)*0.99))]
	} else {
		stats.P99 = sorted[0]
	}

	// Standard deviation (jitter)
	avg := float64(stats.Avg)
	var variance float64
	for _, d := range sorted {
		diff := float64(d) - avg
		variance += diff * diff
	}
	variance /= float64(n)
	stats.Jitter = time.Duration(math.Sqrt(variance))

	return stats
}

// RTCMLatencyStats returns latency statistics for RTCM epoch-to-capture delay.
func (s *NTRIPSession) RTCMLatencyStats() LatencyStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ComputeLatencyStats(s.rtcmLatencySamples)
}

// GGALatencyStats returns latency statistics for GGA UTC-to-capture delay.
func (s *NTRIPSession) GGALatencyStats() LatencyStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	samples := make([]time.Duration, 0, len(s.GGAEvents))
	for _, e := range s.GGAEvents {
		if !e.GGAUtcTime.IsZero() {
			samples = append(samples, e.Latency)
		}
	}
	return ComputeLatencyStats(samples)
}

// ---------------------------------------------------------------------------
// TCP health summary (S5)
// ---------------------------------------------------------------------------

// TCPHealthSummary returns a comprehensive TCP health summary for this
// session, correlated with RTCM interruptions. Returns a zero summary
// if no TCPAnalyzer is attached.
func (s *NTRIPSession) TCPHealthSummary() TCPHealthSummary {
	if s.TCPAnalyzer == nil {
		return TCPHealthSummary{}
	}
	return s.TCPAnalyzer.Summary(s.RTCMStats.Interruptions)
}

// CongestionCorrelations returns congestion correlations between TCP
// retransmissions and RTCM delivery interruptions. Returns nil if no
// TCPAnalyzer is attached.
func (s *NTRIPSession) CongestionCorrelations() []CongestionCorrelation {
	if s.TCPAnalyzer == nil {
		return nil
	}
	return s.TCPAnalyzer.CorrelateWithRTCM(s.RTCMStats.Interruptions)
}
