package ntrip

import (
	"math"
	"net"
	"sync"
	"time"
)

// AttemptRecord records a failed login attempt with the tried password and time.
type AttemptRecord struct {
	Password  string
	Timestamp time.Time
}

// BruteForceState tracks password attempts for a specific username.
type BruteForceState struct {
	Attempts []AttemptRecord
}

// UserCaptureHistory records the last captured session IP and timestamp for a user.
type UserCaptureHistory struct {
	Username string
	LastIP   string
	LastTime time.Time
}

// SessionGGAState tracks the GGA position history for a session.
type SessionGGAState struct {
	LastLat   float64
	LastLon   float64
	HasLast   bool
	Triggered bool
}

// CapturedPoint represents the last known location of an active captured session.
type CapturedPoint struct {
	SessionID string
	Username  string
	Lat       float64
	Lon       float64
	LastSeen  time.Time
}

// NTRIPStateTracker manages the stateful capturing conditions across sessions.
type NTRIPStateTracker struct {
	mu sync.RWMutex

	// capturedConns marks active connections currently being captured (key: "ClientIP:ClientPort")
	capturedConns map[string]bool

	// connUsers caches connection key to username mapping
	connUsers map[string]string

	// capturedUsers stores username capture history (key: username) for reconnects and kicks
	capturedUsers map[string]*UserCaptureHistory

	// bruteForce monitors username password attempts (key: username)
	bruteForce map[string]*BruteForceState

	// sessionGGAs tracks position changes for grid scanning (key: "ClientIP:ClientPort")
	sessionGGAs map[string]*SessionGGAState

	// capturedPoints tracks the locations of currently captured sessions (key: sessionID or "ClientIP:ClientPort")
	capturedPoints map[string]*CapturedPoint
}

// globalTracker is the process-level singleton managing stateful capture contexts.
var globalTracker = NewNTRIPStateTracker()

// NewNTRIPStateTracker initializes a new state tracker.
func NewNTRIPStateTracker() *NTRIPStateTracker {
	return &NTRIPStateTracker{
		capturedConns:  make(map[string]bool),
		connUsers:      make(map[string]string),
		capturedUsers:  make(map[string]*UserCaptureHistory),
		bruteForce:     make(map[string]*BruteForceState),
		sessionGGAs:    make(map[string]*SessionGGAState),
		capturedPoints: make(map[string]*CapturedPoint),
	}
}

// Reset clears all tracked state. Useful for tests.
func (t *NTRIPStateTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.capturedConns = make(map[string]bool)
	t.connUsers = make(map[string]string)
	t.capturedUsers = make(map[string]*UserCaptureHistory)
	t.bruteForce = make(map[string]*BruteForceState)
	t.sessionGGAs = make(map[string]*SessionGGAState)
	t.capturedPoints = make(map[string]*CapturedPoint)
}

// IsCaptured checks if a connection has already been flagged for capture.
func (t *NTRIPStateTracker) IsCaptured(connKey string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.capturedConns[connKey]
}

// MarkCaptured tags a connection as captured.
func (t *NTRIPStateTracker) MarkCaptured(connKey string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.capturedConns[connKey] = true
}

// MarkCapturedWithUser tags a connection as captured and binds a username.
func (t *NTRIPStateTracker) MarkCapturedWithUser(connKey string, username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.capturedConns[connKey] = true
	if username != "" {
		t.connUsers[connKey] = username
	}
}

// GetUsername returns the username associated with a captured connection.
func (t *NTRIPStateTracker) GetUsername(connKey string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connUsers[connKey]
}


// RegisterCapturedUser records that a user is successfully captured.
func (t *NTRIPStateTracker) RegisterCapturedUser(username string, ip string) {
	if username == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.capturedUsers[username] = &UserCaptureHistory{
		Username: username,
		LastIP:   ip,
		LastTime: time.Now(),
	}
}

// CheckReconnectOrKick evaluates reconnect logic and kickout logic.
func (t *NTRIPStateTracker) CheckReconnectOrKick(
	username string,
	newIP string,
	reconnectEnabled bool,
	reconnectSubnet int,
	kickEnabled bool,
	kickSubnet int,
) (isReconnect bool, isKick bool) {
	if username == "" {
		return false, false
	}

	t.mu.RLock()
	history, exists := t.capturedUsers[username]
	t.mu.RUnlock()

	if !exists {
		return false, false
	}

	// 10 minutes timeout window
	if time.Since(history.LastTime) > 10*time.Minute {
		return false, false
	}

	sameSubnet := isSameSubnet(history.LastIP, newIP, reconnectSubnet)

	if sameSubnet && reconnectEnabled {
		isReconnect = true
	}
	if !sameSubnet && kickEnabled {
		isKick = true
	}

	return isReconnect, isKick
}

// RecordLoginAttempt checks brute force scenarios.
func (t *NTRIPStateTracker) RecordLoginAttempt(
	username string,
	password string,
	success bool,
	interval time.Duration,
	passThreshold int,
	failThreshold int,
) bool {
	if username == "" {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.bruteForce[username]
	if !exists {
		state = &BruteForceState{}
		t.bruteForce[username] = state
	}

	now := time.Now()

	// Clean expired records
	cutoff := now.Add(-interval)
	var active []AttemptRecord
	for _, a := range state.Attempts {
		if a.Timestamp.After(cutoff) {
			active = append(active, a)
		}
	}
	state.Attempts = active

	if !success {
		state.Attempts = append(state.Attempts, AttemptRecord{
			Password:  password,
			Timestamp: now,
		})
	}

	if len(state.Attempts) < failThreshold {
		return false
	}

	uniqPasswords := make(map[string]struct{})
	for _, a := range state.Attempts {
		uniqPasswords[a.Password] = struct{}{}
	}

	return len(uniqPasswords) >= passThreshold
}

// CheckGridScan calculates position displacement distance.
func (t *NTRIPStateTracker) CheckGridScan(connKey string, lat, lon float64, threshold float64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.sessionGGAs[connKey]
	if !exists {
		state = &SessionGGAState{}
		t.sessionGGAs[connKey] = state
	}

	if state.Triggered {
		return true
	}

	if !state.HasLast {
		state.LastLat = lat
		state.LastLon = lon
		state.HasLast = true
		return false
	}

	dist := FastDistance(state.LastLat, state.LastLon, lat, lon)
	state.LastLat = lat
	state.LastLon = lon

	if dist > threshold {
		state.Triggered = true
		return true
	}

	return false
}

// UpdateCapturedPoint stores location coordinates of active captured sessions.
func (t *NTRIPStateTracker) UpdateCapturedPoint(sessionID string, username string, lat, lon float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.capturedPoints[sessionID] = &CapturedPoint{
		SessionID: sessionID,
		Username:  username,
		Lat:       lat,
		Lon:       lon,
		LastSeen:  time.Now(),
	}
}

// CheckNearbyCorrelation checks whether a coordinate is close to any captured point of another user.
func (t *NTRIPStateTracker) CheckNearbyCorrelation(
	sessionID string,
	username string,
	lat, lon float64,
	threshold float64,
) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now()
	for _, pt := range t.capturedPoints {
		// exclude same session, same user, and expired updates (5 mins)
		if pt.SessionID != sessionID && pt.Username != username && now.Sub(pt.LastSeen) < 5*time.Minute {
			dist := FastDistance(pt.Lat, pt.Lon, lat, lon)
			if dist <= threshold {
				return true
			}
		}
	}
	return false
}

// FastDistance computes planar flat-earth distance in meters between two coordinates.
func FastDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371000.0
	ky := (math.Pi * R) / 180.0
	avgLat := (lat1 + lat2) / 2.0
	kx := ((math.Pi * R) / 180.0) * math.Cos(avgLat*math.Pi/180.0)

	dy := (lat2 - lat1) * ky
	dx := (lon2 - lon1) * kx
	return math.Sqrt(dx*dx + dy*dy)
}

func isSameSubnet(ip1, ip2 string, maskBits int) bool {
	parsed1 := net.ParseIP(ip1)
	parsed2 := net.ParseIP(ip2)
	if parsed1 == nil || parsed2 == nil {
		return ip1 == ip2
	}

	ip1v4 := parsed1.To4()
	ip2v4 := parsed2.To4()
	if ip1v4 != nil && ip2v4 != nil {
		mask := net.CIDRMask(maskBits, 32)
		return ip1v4.Mask(mask).Equal(ip2v4.Mask(mask))
	}

	mask := net.CIDRMask(maskBits, 128)
	return parsed1.Mask(mask).Equal(parsed2.Mask(mask))
}
