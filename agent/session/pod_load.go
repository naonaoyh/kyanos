package session

import (
	"math"
	"sort"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// PodLoadAnalyzer: multi-Pod load analysis (S6)
// ---------------------------------------------------------------------------
//
// PodLoadAnalyzer aggregates NTRIP sessions by the serving DS Pod, so operators
// can answer:
//   - How many connections / what frame rate is each Pod carrying?
//   - Is load balanced across Pods (coefficient of variation)?
//   - Does a given client always stick to the same Pod (session stickiness)?
//   - Did a client migrate from one Pod to another (Pod switch)?
//
// It implements SessionListener and is meant to be registered on a
// SessionTracker via tracker.AddListener(podLoadAnalyzer).
//
// Aggregation key: the serving Pod name (NTRIPSession.ServerPod). In non-K8s
// deployments ServerPod is empty, so we fall back to the server-side IP
// (NTRIPSession.ServerIP). The resolved key is exposed as PodStats.PodKey.

// PodLoadAnalyzer tracks per-Pod session load and detects imbalance / Pod
// switches. It is safe for concurrent use.
type PodLoadAnalyzer struct {
	mu sync.RWMutex

	// pods maps a resolved Pod key to its aggregated stats.
	pods map[string]*podAccumulator

	// clientToPod maps a client identity (IP) to the most recent Pod key it was
	// observed on, used for stickiness / Pod-switch detection.
	clientToPod map[string]string

	// switches records detected Pod switches (a client moving between Pods).
	switches []PodSwitchEvent
}

// podAccumulator is the mutable per-Pod state held by the analyzer.
type podAccumulator struct {
	podKey       string
	podName      string // original ServerPod (may be empty)
	serverIP     string
	sessions     map[string]*NTRIPSession // sessionID -> session
	totalCreated int
}

// PodStats is an immutable snapshot of one Pod's load.
type PodStats struct {
	PodKey          string  // resolved aggregation key (pod name, or "ip:<addr>")
	PodName         string  // K8s Pod name if known, else ""
	ServerIP        string  // server-side IP
	TotalSessions   int     // sessions ever assigned to this Pod
	ActiveSessions  int     // currently active sessions
	TotalRTCMFrames int64   // sum of RTCM frames across this Pod's sessions
	TotalRTCMBytes  int64   // sum of RTCM payload bytes
	FrameRate       float64 // aggregate RTCM frames-per-second across active sessions
	UniqueClients   int     // distinct client IPs currently active on this Pod
}

// PodSwitchEvent records a client moving from one serving Pod to another.
type PodSwitchEvent struct {
	ClientIP  string
	OldPodKey string
	NewPodKey string
	Timestamp time.Time
}

// NewPodLoadAnalyzer creates an empty analyzer.
func NewPodLoadAnalyzer() *PodLoadAnalyzer {
	return &PodLoadAnalyzer{
		pods:        make(map[string]*podAccumulator),
		clientToPod: make(map[string]string),
	}
}

// podKeyOf resolves the aggregation key for a session: the K8s Pod name when
// available, otherwise the server IP prefixed with "ip:" to avoid colliding
// with a real Pod literally named like an IP.
func podKeyOf(s *NTRIPSession) (key, podName, serverIP string) {
	s.mu.RLock()
	podName = s.ServerPod
	serverIP = s.ServerIP
	s.mu.RUnlock()

	if podName != "" {
		return podName, podName, serverIP
	}
	if serverIP != "" {
		return "ip:" + serverIP, "", serverIP
	}
	return "unknown", "", ""
}

// OnSessionCreated assigns a new session to its Pod and updates stickiness /
// switch tracking. Implements SessionListener.
func (p *PodLoadAnalyzer) OnSessionCreated(s *NTRIPSession) {
	key, podName, serverIP := podKeyOf(s)

	s.mu.RLock()
	sessionID := s.SessionID
	clientIP := s.ClientIP
	s.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	acc, ok := p.pods[key]
	if !ok {
		acc = &podAccumulator{
			podKey:   key,
			podName:  podName,
			serverIP: serverIP,
			sessions: make(map[string]*NTRIPSession),
		}
		p.pods[key] = acc
	}
	acc.sessions[sessionID] = s
	acc.totalCreated++

	// Pod-switch detection: same client, different Pod than last seen.
	if clientIP != "" {
		if prevKey, seen := p.clientToPod[clientIP]; seen && prevKey != key {
			p.switches = append(p.switches, PodSwitchEvent{
				ClientIP:  clientIP,
				OldPodKey: prevKey,
				NewPodKey: key,
				Timestamp: time.Now(),
			})
		}
		p.clientToPod[clientIP] = key
	}
}

// OnSessionClosed keeps the session in the accumulator (so historical totals
// remain) but it will no longer count as active. Implements SessionListener.
//
// We intentionally retain the session reference: ActiveSessions is derived from
// each session's live IsActive() state, so a closed session naturally drops out
// of the active count without us mutating shared state here.
func (p *PodLoadAnalyzer) OnSessionClosed(s *NTRIPSession) {
	// No-op: stats are computed on-demand from session state in Snapshot().
	// Defined to satisfy SessionListener.
}

// Snapshot returns an immutable per-Pod load snapshot, one PodStats per Pod,
// sorted by PodKey for stable output.
func (p *PodLoadAnalyzer) Snapshot() []PodStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]PodStats, 0, len(p.pods))
	for _, acc := range p.pods {
		stats := PodStats{
			PodKey:        acc.podKey,
			PodName:       acc.podName,
			ServerIP:      acc.serverIP,
			TotalSessions: acc.totalCreated,
		}
		clients := make(map[string]struct{})
		for _, s := range acc.sessions {
			stats.TotalRTCMFrames += int64(s.RTCMFrameCount())
			stats.TotalRTCMBytes += s.RTCMTotalBytes()
			if s.IsActive() {
				stats.ActiveSessions++
				stats.FrameRate += s.RTCMFrameRate()
				s.mu.RLock()
				cip := s.ClientIP
				s.mu.RUnlock()
				if cip != "" {
					clients[cip] = struct{}{}
				}
			}
		}
		stats.UniqueClients = len(clients)
		result = append(result, stats)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].PodKey < result[j].PodKey
	})
	return result
}

// PodSwitches returns a copy of all detected Pod-switch events.
func (p *PodLoadAnalyzer) PodSwitches() []PodSwitchEvent {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]PodSwitchEvent, len(p.switches))
	copy(out, p.switches)
	return out
}

// IsSticky reports whether the given client has only ever been observed on a
// single Pod (i.e. it never triggered a Pod switch). A client that has never
// been seen is reported as sticky (vacuously true).
func (p *PodLoadAnalyzer) IsSticky(clientIP string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, sw := range p.switches {
		if sw.ClientIP == clientIP {
			return false
		}
	}
	return true
}

// LoadImbalance returns the coefficient of variation (CV = stddev / mean) of
// active session counts across Pods. CV is a unit-less measure of dispersion:
//   - 0.0 means perfectly balanced (all Pods carry the same active load)
//   - higher values mean more imbalance
//
// Returns 0 when fewer than two Pods are present or the mean is zero.
func (p *PodLoadAnalyzer) LoadImbalance() float64 {
	return p.coefficientOfVariation(func(s PodStats) float64 {
		return float64(s.ActiveSessions)
	})
}

// FrameRateImbalance returns the coefficient of variation of aggregate RTCM
// frame rate across Pods. Useful to spot a Pod that is serving far more (or
// far less) data than its peers even when connection counts look balanced.
func (p *PodLoadAnalyzer) FrameRateImbalance() float64 {
	return p.coefficientOfVariation(func(s PodStats) float64 {
		return s.FrameRate
	})
}

// coefficientOfVariation computes CV over a metric extracted from each Pod's
// snapshot. Shared by LoadImbalance and FrameRateImbalance.
func (p *PodLoadAnalyzer) coefficientOfVariation(extract func(PodStats) float64) float64 {
	snapshot := p.Snapshot()
	n := len(snapshot)
	if n < 2 {
		return 0
	}

	var sum float64
	for _, s := range snapshot {
		sum += extract(s)
	}
	mean := sum / float64(n)
	if mean == 0 {
		return 0
	}

	var variance float64
	for _, s := range snapshot {
		d := extract(s) - mean
		variance += d * d
	}
	variance /= float64(n)

	return math.Sqrt(variance) / mean
}

// PodCount returns the number of distinct Pods observed.
func (p *PodLoadAnalyzer) PodCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.pods)
}
