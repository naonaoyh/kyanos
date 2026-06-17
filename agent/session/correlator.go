package session

import (
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// SessionCorrelator: cross-session reconnection and account tracking
// ---------------------------------------------------------------------------

// SessionCorrelator tracks all sessions for each NTRIP account (username),
// detects reconnections, IP changes, and kick-out events.
type SessionCorrelator struct {
	mu        sync.RWMutex
	byUser    map[string][]*NTRIPSession // username → ordered session list
	config    CorrelatorConfig
	listeners []CorrelatorListener
}

// CorrelatorListener receives callbacks on correlation events.
type CorrelatorListener interface {
	OnReconnect(ev ReconnectEvent)
}

// NewSessionCorrelator creates a correlator with the given config.
func NewSessionCorrelator(cfg CorrelatorConfig) *SessionCorrelator {
	return &SessionCorrelator{
		byUser: make(map[string][]*NTRIPSession),
		config: cfg,
	}
}

// AddListener registers a correlation event listener.
func (c *SessionCorrelator) AddListener(l CorrelatorListener) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.listeners = append(c.listeners, l)
}

// OnSessionCreated should be called when a new session starts.
// It checks for reconnection patterns and IP changes.
func (c *SessionCorrelator) OnSessionCreated(s *NTRIPSession) {
	s.mu.RLock()
	username := s.Username
	clientIP := effectiveIP(s.RealClientIP, s.ClientIP)
	startTime := s.ConnStartTime
	s.mu.RUnlock()

	if username == "" {
		return
	}

	c.mu.Lock()
	c.byUser[username] = append(c.byUser[username], s)
	prev := c.findPreviousSession(username, s)
	c.mu.Unlock()

	if prev == nil {
		return
	}

	// Check if this is a reconnection
	prev.mu.RLock()
	prevClose := prev.ConnCloseTime
	prevIP := effectiveIP(prev.RealClientIP, prev.ClientIP)
	prev.mu.RUnlock()

	if prevClose == nil {
		// Previous session still active → not a reconnection, it's concurrent
		// (could be kick-out scenario, handled by tracker's detectKickOut)
		return
	}

	gap := startTime.Sub(*prevClose)
	if gap > c.config.ReconnectWindow {
		return // too long ago to be a reconnection
	}

	ipChanged := prevIP != clientIP

	ev := ReconnectEvent{
		OldSessionID: prev.SessionID,
		NewSessionID: s.SessionID,
		OldClientIP:  prevIP,
		NewClientIP:  clientIP,
		Disconnect:   *prevClose,
		Reconnect:    startTime,
		Downtime:     gap,
		IPChanged:    ipChanged,
	}

	c.notifyReconnect(ev)
}

// OnSessionClosed is a no-op for the correlator but required by SessionListener.
func (c *SessionCorrelator) OnSessionClosed(s *NTRIPSession) {
	// Nothing to do on close; the session is already in the byUser map.
}

// SessionsForUser returns all sessions for a given username, ordered by start time.
func (c *SessionCorrelator) SessionsForUser(username string) []*NTRIPSession {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sessions := c.byUser[username]
	result := make([]*NTRIPSession, len(sessions))
	copy(result, sessions)
	return result
}

// Usernames returns all known usernames.
func (c *SessionCorrelator) Usernames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	users := make([]string, 0, len(c.byUser))
	for u := range c.byUser {
		users = append(users, u)
	}
	return users
}

// ReconnectEvents returns all detected reconnection events for a username.
func (c *SessionCorrelator) ReconnectEvents(username string) []ReconnectEvent {
	c.mu.RLock()
	sessions := c.byUser[username]
	c.mu.RUnlock()

	var events []ReconnectEvent
	for i := 1; i < len(sessions); i++ {
		curr := sessions[i]
		prev := sessions[i-1]

		prev.mu.RLock()
		prevClose := prev.ConnCloseTime
		prevIP := effectiveIP(prev.RealClientIP, prev.ClientIP)
		prev.mu.RUnlock()

		curr.mu.RLock()
		currStart := curr.ConnStartTime
		currIP := effectiveIP(curr.RealClientIP, curr.ClientIP)
		curr.mu.RUnlock()

		if prevClose == nil {
			continue
		}

		gap := currStart.Sub(*prevClose)
		if gap > c.config.ReconnectWindow {
			continue
		}

		events = append(events, ReconnectEvent{
			OldSessionID: prev.SessionID,
			NewSessionID: curr.SessionID,
			OldClientIP:  prevIP,
			NewClientIP:  currIP,
			Disconnect:   *prevClose,
			Reconnect:    currStart,
			Downtime:     gap,
			IPChanged:    prevIP != currIP,
		})
	}
	return events
}

// AccountSummary provides a high-level view of all sessions for a user.
type AccountSummary struct {
	Username          string
	TotalSessions     int
	ActiveSessions    int
	TotalReconnects   int
	IPChanges         int
	KickOuts          int
	AuthFailures      int
	FirstSeen         time.Time
	LastSeen          time.Time
	TotalDuration     time.Duration
	DisconnectReasons map[DisconnectReason]int
}

// SummarizeAccount generates a summary for the given username.
func (c *SessionCorrelator) SummarizeAccount(username string) AccountSummary {
	c.mu.RLock()
	sessions := c.byUser[username]
	c.mu.RUnlock()

	summary := AccountSummary{
		Username:          username,
		DisconnectReasons: make(map[DisconnectReason]int),
	}

	for i, s := range sessions {
		s.mu.RLock()
		summary.TotalSessions++
		if s.IsActive() {
			summary.ActiveSessions++
		}
		summary.DisconnectReasons[s.DisconnectReason]++
		if s.DisconnectReason == DisconnectAccountKickOut {
			summary.KickOuts++
		}
		if s.DisconnectReason == DisconnectAuthFailed {
			summary.AuthFailures++
		}
		if i == 0 {
			summary.FirstSeen = s.ConnStartTime
		}
		summary.LastSeen = s.ConnStartTime
		summary.TotalDuration += s.Duration()
		s.mu.RUnlock()
	}

	reconnects := c.ReconnectEvents(username)
	summary.TotalReconnects = len(reconnects)
	for _, r := range reconnects {
		if r.IPChanged {
			summary.IPChanges++
		}
	}

	return summary
}

// findPreviousSession returns the most recent session for the same username
// that is NOT the current session. Must be called with c.mu held.
func (c *SessionCorrelator) findPreviousSession(username string, current *NTRIPSession) *NTRIPSession {
	sessions := c.byUser[username]
	for i := len(sessions) - 1; i >= 0; i-- {
		if sessions[i] != current {
			return sessions[i]
		}
	}
	return nil
}

func (c *SessionCorrelator) notifyReconnect(ev ReconnectEvent) {
	c.mu.RLock()
	listeners := make([]CorrelatorListener, len(c.listeners))
	copy(listeners, c.listeners)
	c.mu.RUnlock()
	for _, l := range listeners {
		l.OnReconnect(ev)
	}
}

// String returns a human-readable summary of a ReconnectEvent.
func (r ReconnectEvent) String() string {
	ipNote := ""
	if r.IPChanged {
		ipNote = fmt.Sprintf(" [IP changed: %s → %s]", r.OldClientIP, r.NewClientIP)
	}
	return fmt.Sprintf("Reconnect: downtime=%s%s", r.Downtime.Round(time.Millisecond), ipNote)
}
