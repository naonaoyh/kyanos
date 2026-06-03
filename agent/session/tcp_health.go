package session

import (
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// TCP Health Analyzer (S5: TCP Retransmission & Congestion Analysis)
// ---------------------------------------------------------------------------
//
// TCPHealthAnalyzer correlates TCP-level network quality signals
// (retransmissions, RTT jitter, window shrinkage) with RTCM delivery
// interruptions to identify congestion-induced data delivery degradation.
//
// Architecture:
//
//	BPF kernel events → Retransmission / RTT / Window events
//	                            │
//	            TCPHealthAnalyzer aggregates per-session
//	                            │
//	           ┌────────────────┼────────────────┐
//	           │                │                │
//	     Burst detection  Correlation      Summary
//	     (retrans clusters) with RTCM      (report)
//	                      interruptions
//
// Usage:
//
//	analyzer := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
//	analyzer.RecordPacket(seq, ts, true)   // original packet
//	analyzer.RecordPacket(seq, ts2, false) // retransmission of same seq
//	analyzer.RecordRTT(25*time.Millisecond, seq)
//	analyzer.RecordWindowShrink(65535, 32768)
//	bursts := analyzer.DetectBursts(3, 5*time.Second)
//	corr := analyzer.CorrelateWithRTCM(rtcmInterruptions)
//	summary := analyzer.Summary(rtcmInterruptions)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// TCPHealthConfig tunes the TCP health analysis behaviour.
type TCPHealthConfig struct {
	// BurstThreshold is the minimum retransmission count within the window
	// to classify as a congestion burst.
	BurstThreshold int
	// BurstWindow is the maximum time span for grouping retransmissions
	// into a single burst.
	BurstWindow time.Duration
	// RTTSpikeThreshold is the RTT value above which a sample is
	// considered a spike (potential congestion indicator).
	RTTSpikeThreshold time.Duration
	// WindowShrinkRatio is the minimum fractional reduction in TCP receive
	// window to flag as significant shrinkage (e.g. 0.5 = halved).
	WindowShrinkRatio float64
	// CorrelationMargin extends the RTCM interruption window on each side
	// when searching for overlapping retransmissions.
	CorrelationMargin time.Duration
}

// DefaultTCPHealthConfig returns sensible defaults.
func DefaultTCPHealthConfig() TCPHealthConfig {
	return TCPHealthConfig{
		BurstThreshold:    3,
		BurstWindow:       5 * time.Second,
		RTTSpikeThreshold: 100 * time.Millisecond,
		WindowShrinkRatio: 0.5,
		CorrelationMargin: 2 * time.Second,
	}
}

// ---------------------------------------------------------------------------
// Core event types
// ---------------------------------------------------------------------------

// RetransmissionEvent records a single TCP retransmission.
type RetransmissionEvent struct {
	Timestamp time.Time
	SeqNum    uint32 // TCP sequence number (0 if unavailable)
	Size      int    // payload size in bytes (0 if unknown)
}

// WindowShrinkEvent records a TCP receive window reduction.
type WindowShrinkEvent struct {
	Timestamp time.Time
	OldWindow int     // previous window size (bytes)
	NewWindow int     // reduced window size (bytes)
	Ratio     float64 // new / old (0.0-1.0)
}

// RTTSample records a single round-trip time observation with optional
// sequence number for correlation.
type RTTSample struct {
	Timestamp time.Time
	RTT       time.Duration
	SeqNum    uint32 // 0 if not tracked
}

// ---------------------------------------------------------------------------
// Analysis result types
// ---------------------------------------------------------------------------

// RetransmissionBurst represents a cluster of retransmissions within a
// short time window, indicating transient network congestion.
type RetransmissionBurst struct {
	StartTime     time.Time
	EndTime       time.Time
	Duration      time.Duration
	Count         int
	AvgRTTInBurst time.Duration // average RTT observed during the burst
	MaxRTTInBurst time.Duration
}

// CongestionCorrelation links a TCP congestion event (retransmission burst)
// to an RTCM delivery interruption, establishing a cause-effect relationship.
type CongestionCorrelation struct {
	InterruptionStart    time.Time
	InterruptionEnd      time.Time
	InterruptionDuration time.Duration
	RetransInWindow      int           // retransmissions during the interruption
	BurstOverlap         bool          // true if a retransmission burst overlaps
	AvgRTTDuring         time.Duration // average RTT during the interruption
	MaxRTTDuring         time.Duration
	ProbableCause        string // "congestion", "partial_congestion", "other"
}

// TCPHealthSummary provides a comprehensive view of TCP health for a session.
type TCPHealthSummary struct {
	TotalPackets         int
	TotalRetransmissions int
	RetransmissionRate   float64 // 0.0 - 1.0
	RTTAvg               time.Duration
	RTTP95               time.Duration
	RTTMax               time.Duration
	RTTJitter            time.Duration
	RTTSpikes            int
	WindowShrinks        int
	Bursts               []RetransmissionBurst
	Correlations         []CongestionCorrelation
}

// ---------------------------------------------------------------------------
// TCPHealthAnalyzer
// ---------------------------------------------------------------------------

// TCPHealthAnalyzer analyses TCP-level health indicators for a single
// NTRIP session, correlating retransmissions and RTT jitter with RTCM
// delivery interruptions.
type TCPHealthAnalyzer struct {
	mu sync.RWMutex

	config TCPHealthConfig

	// Raw event logs
	retransmissions []RetransmissionEvent
	rttSamples      []RTTSample
	windowShrinks   []WindowShrinkEvent

	// Packet counters for rate computation
	totalPackets    int
	retransmitCount int
	seenSeqs        map[uint32]int // seq → occurrence count

	// Last observed window size for shrink detection
	lastWindowSize int
}

// NewTCPHealthAnalyzer creates a new analyzer with the given config.
func NewTCPHealthAnalyzer(cfg TCPHealthConfig) *TCPHealthAnalyzer {
	return &TCPHealthAnalyzer{
		config:   cfg,
		seenSeqs: make(map[uint32]int),
	}
}

// ---------------------------------------------------------------------------
// Event recording
// ---------------------------------------------------------------------------

// RecordPacket records a TCP packet observation. If isRetransmit is false
// the packet is counted as an original transmission; if the same seq was
// already seen it is automatically counted as a retransmission.
// Pass seq=0 when sequence numbers are unavailable (explicit counting).
func (a *TCPHealthAnalyzer) RecordPacket(seq uint32, ts time.Time, isRetransmit bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.totalPackets++

	if seq != 0 {
		a.seenSeqs[seq]++
		if a.seenSeqs[seq] > 1 && !isRetransmit {
			// Duplicate seq → auto-detect as retransmission
			isRetransmit = true
		}
	}

	if isRetransmit {
		a.retransmitCount++
		a.retransmissions = append(a.retransmissions, RetransmissionEvent{
			Timestamp: ts,
			SeqNum:    seq,
		})
	}
}

// RecordRetransmission explicitly records a retransmission event (e.g., from
// BPF kernel events). Increments both total packet and retransmit counters.
func (a *TCPHealthAnalyzer) RecordRetransmission(ts time.Time, seq uint32, size int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.totalPackets++
	a.retransmitCount++
	a.retransmissions = append(a.retransmissions, RetransmissionEvent{
		Timestamp: ts,
		SeqNum:    seq,
		Size:      size,
	})
}

// RecordRTT records a round-trip time observation.
// Pass seq=0 if sequence numbers are not tracked.
func (a *TCPHealthAnalyzer) RecordRTT(rtt time.Duration, seq uint32) {
	a.RecordRTTAt(rtt, seq, time.Now())
}

// RecordRTTAt records an RTT observation with an explicit timestamp.
func (a *TCPHealthAnalyzer) RecordRTTAt(rtt time.Duration, seq uint32, ts time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rttSamples = append(a.rttSamples, RTTSample{
		Timestamp: ts,
		RTT:       rtt,
		SeqNum:    seq,
	})
}

// RecordWindowShrink records a TCP receive window reduction.
// oldWindow and newWindow are in bytes.
func (a *TCPHealthAnalyzer) RecordWindowShrink(oldWindow, newWindow int) {
	a.RecordWindowShrinkAt(oldWindow, newWindow, time.Now())
}

// RecordWindowShrinkAt records a window shrink event with explicit timestamp.
func (a *TCPHealthAnalyzer) RecordWindowShrinkAt(oldWindow, newWindow int, ts time.Time) {
	if oldWindow <= 0 || newWindow >= oldWindow {
		return // not a shrink
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	ratio := float64(newWindow) / float64(oldWindow)
	a.windowShrinks = append(a.windowShrinks, WindowShrinkEvent{
		Timestamp: ts,
		OldWindow: oldWindow,
		NewWindow: newWindow,
		Ratio:     ratio,
	})
}

// UpdateWindow tracks the TCP receive window size and automatically
// detects shrinkage relative to the previous observation.
func (a *TCPHealthAnalyzer) UpdateWindow(windowSize int, ts time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.lastWindowSize > 0 && windowSize < a.lastWindowSize {
		ratio := float64(windowSize) / float64(a.lastWindowSize)
		if ratio <= a.config.WindowShrinkRatio {
			a.windowShrinks = append(a.windowShrinks, WindowShrinkEvent{
				Timestamp: ts,
				OldWindow: a.lastWindowSize,
				NewWindow: windowSize,
				Ratio:     ratio,
			})
		}
	}
	a.lastWindowSize = windowSize
}

// ---------------------------------------------------------------------------
// Analysis methods
// ---------------------------------------------------------------------------

// ComputeRetransmissionRate calculates the retransmission rate.
// Returns 0 if no packets have been recorded.
func (a *TCPHealthAnalyzer) ComputeRetransmissionRate() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.totalPackets == 0 {
		return 0
	}
	return float64(a.retransmitCount) / float64(a.totalPackets)
}

// RTTSpikeCount returns the number of RTT samples exceeding the configured
// spike threshold.
func (a *TCPHealthAnalyzer) RTTSpikeCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	count := 0
	for _, s := range a.rttSamples {
		if s.RTT > a.config.RTTSpikeThreshold {
			count++
		}
	}
	return count
}

// DetectBursts identifies clusters of retransmissions where at least
// minCount events occur within the configured burst window.
// Pass minCount=0 to use the config's BurstThreshold.
func (a *TCPHealthAnalyzer) DetectBursts(minCount int) []RetransmissionBurst {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if minCount <= 0 {
		minCount = a.config.BurstThreshold
	}

	n := len(a.retransmissions)
	if n < minCount {
		return nil
	}

	window := a.config.BurstWindow
	var bursts []RetransmissionBurst

	i := 0
	for i < n {
		j := i
		var maxRTT time.Duration

		// Extend the burst while consecutive retransmissions are within the window
		for j < n && a.retransmissions[j].Timestamp.Sub(a.retransmissions[i].Timestamp) <= window {
			rtt := a.findRTTNear(a.retransmissions[j].Timestamp, window)
			if rtt > maxRTT {
				maxRTT = rtt
			}
			j++
		}

		count := j - i
		if count >= minCount {
			burst := RetransmissionBurst{
				StartTime:     a.retransmissions[i].Timestamp,
				EndTime:       a.retransmissions[j-1].Timestamp,
				Duration:      a.retransmissions[j-1].Timestamp.Sub(a.retransmissions[i].Timestamp),
				Count:         count,
				MaxRTTInBurst: maxRTT,
			}

			// Compute average RTT during burst
			rttSum := time.Duration(0)
			rttCount := 0
			for _, s := range a.rttSamples {
				if !s.Timestamp.Before(burst.StartTime) && !s.Timestamp.After(burst.EndTime) {
					rttSum += s.RTT
					rttCount++
				}
			}
			if rttCount > 0 {
				burst.AvgRTTInBurst = rttSum / time.Duration(rttCount)
			}

			bursts = append(bursts, burst)
		}

		// Advance: if a burst was found, skip past it; otherwise step by one
		if count >= minCount {
			i = j
		} else {
			i++
		}
	}

	return bursts
}

// CorrelateWithRTCM cross-references TCP retransmission events with RTCM
// delivery interruptions to establish congestion ↔ data gap causation.
func (a *TCPHealthAnalyzer) CorrelateWithRTCM(interruptions []RTCMInterruption) []CongestionCorrelation {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var results []CongestionCorrelation
	margin := a.config.CorrelationMargin

	for _, intr := range interruptions {
		windowStart := intr.StartTime.Add(-margin)
		windowEnd := intr.EndTime.Add(margin)

		// Count retransmissions in the extended interruption window
		retransCount := 0
		for _, r := range a.retransmissions {
			if !r.Timestamp.Before(windowStart) && !r.Timestamp.Before(intr.StartTime) &&
				!r.Timestamp.After(windowEnd) {
				retransCount++
			}
		}
		// Also count retransmissions strictly within the interruption
		retransStrict := 0
		for _, r := range a.retransmissions {
			if !r.Timestamp.Before(intr.StartTime) && !r.Timestamp.After(intr.EndTime) {
				retransStrict++
			}
		}

		// Average and max RTT during the interruption
		var avgRTT, maxRTT time.Duration
		rttCount := 0
		var rttSum time.Duration
		for _, s := range a.rttSamples {
			if !s.Timestamp.Before(intr.StartTime) && !s.Timestamp.After(intr.EndTime) {
				rttSum += s.RTT
				rttCount++
				if s.RTT > maxRTT {
					maxRTT = s.RTT
				}
			}
		}
		if rttCount > 0 {
			avgRTT = rttSum / time.Duration(rttCount)
		}

		// Check for burst overlap (any burst whose time range intersects)
		burstOverlap := false
		for _, b := range a.detectBurstsLocked(0) {
			if !b.EndTime.Before(intr.StartTime) && !b.StartTime.After(intr.EndTime) {
				burstOverlap = true
				break
			}
		}

		// Classify probable cause
		cause := "other"
		if retransStrict >= a.config.BurstThreshold || burstOverlap {
			cause = "congestion"
		} else if retransCount > 0 {
			cause = "partial_congestion"
		}

		results = append(results, CongestionCorrelation{
			InterruptionStart:    intr.StartTime,
			InterruptionEnd:      intr.EndTime,
			InterruptionDuration: intr.Duration,
			RetransInWindow:      retransCount,
			BurstOverlap:         burstOverlap,
			AvgRTTDuring:         avgRTT,
			MaxRTTDuring:         maxRTT,
			ProbableCause:        cause,
		})
	}

	return results
}

// Summary returns a comprehensive TCP health summary, optionally
// correlating with RTCM interruptions. Pass nil to skip correlation.
func (a *TCPHealthAnalyzer) Summary(interruptions []RTCMInterruption) TCPHealthSummary {
	a.mu.RLock()
	defer a.mu.RUnlock()

	summary := TCPHealthSummary{
		TotalPackets:         a.totalPackets,
		TotalRetransmissions: a.retransmitCount,
		WindowShrinks:        len(a.windowShrinks),
	}

	if a.totalPackets > 0 {
		summary.RetransmissionRate = float64(a.retransmitCount) / float64(a.totalPackets)
	}

	// RTT statistics
	n := len(a.rttSamples)
	if n > 0 {
		sorted := make([]time.Duration, n)
		for i, s := range a.rttSamples {
			sorted[i] = s.RTT
		}
		sortDurations(sorted)

		var total time.Duration
		for _, d := range sorted {
			total += d
		}
		summary.RTTAvg = total / time.Duration(n)
		summary.RTTMax = sorted[n-1]
		summary.RTTP95 = sorted[int(float64(n)*0.95)]

		// Jitter (standard deviation)
		avg := float64(summary.RTTAvg)
		var variance float64
		for _, d := range sorted {
			diff := float64(d) - avg
			variance += diff * diff
		}
		variance /= float64(n)
		summary.RTTJitter = time.Duration(sqrtF(variance))

		// Spike count
		for _, s := range a.rttSamples {
			if s.RTT > a.config.RTTSpikeThreshold {
				summary.RTTSpikes++
			}
		}
	}

	// Burst detection (use locked version since we already hold RLock)
	summary.Bursts = a.detectBurstsLocked(0)

	// Correlation
	if interruptions != nil {
		summary.Correlations = a.correlateLocked(interruptions)
	}

	return summary
}

// ---------------------------------------------------------------------------
// Session-level integration helpers
// ---------------------------------------------------------------------------

// ComputeFinalStats computes retransmission rate and updates the session's
// NetworkQuality stats. Should be called during session finalization.
func (a *TCPHealthAnalyzer) ComputeFinalStats(nq *NetworkQualityStats) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	nq.TotalRetransmissions = a.retransmitCount
	if a.totalPackets > 0 {
		nq.RetransmissionRate = float64(a.retransmitCount) / float64(a.totalPackets)
	}
}

// CorrelateAndScore performs correlation with RTCM interruptions and
// adjusts the network quality score based on findings.
func (a *TCPHealthAnalyzer) CorrelateAndScore(interruptions []RTCMInterruption, nq *NetworkQualityStats) {
	correlations := a.CorrelateWithRTCM(interruptions)

	congestionCount := 0
	for _, c := range correlations {
		if c.ProbableCause == "congestion" {
			congestionCount++
		}
	}

	// Update window shrink count
	a.mu.RLock()
	nq.WindowSizeMin = 0 // updated by UpdateWindow tracking
	shrinkCount := len(a.windowShrinks)
	a.mu.RUnlock()

	// ConnectionMigrations is tracked elsewhere; we just note shrinks here
	_ = shrinkCount
}

// RetransmissionCount returns the total retransmission count.
func (a *TCPHealthAnalyzer) RetransmissionCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.retransmitCount
}

// TotalPackets returns the total packet count.
func (a *TCPHealthAnalyzer) TotalPackets() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.totalPackets
}

// RTTSampleCount returns the number of RTT samples recorded.
func (a *TCPHealthAnalyzer) RTTSampleCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.rttSamples)
}

// WindowShrinkCount returns the number of window shrink events.
func (a *TCPHealthAnalyzer) WindowShrinkCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.windowShrinks)
}

// RetransmissionEvents returns a copy of all retransmission events.
func (a *TCPHealthAnalyzer) RetransmissionEvents() []RetransmissionEvent {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]RetransmissionEvent, len(a.retransmissions))
	copy(result, a.retransmissions)
	return result
}

// RetransmissionsInWindow returns the number of retransmissions whose timestamp
// falls within [end-window, end]. Used to classify a server-side disconnect as
// an RTCM retransmission abort based on recent congestion rather than the
// session's lifetime total. A non-positive window counts all retransmissions
// up to end.
func (a *TCPHealthAnalyzer) RetransmissionsInWindow(end time.Time, window time.Duration) int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if window <= 0 {
		count := 0
		for _, e := range a.retransmissions {
			if !e.Timestamp.After(end) {
				count++
			}
		}
		return count
	}

	start := end.Add(-window)
	count := 0
	for _, e := range a.retransmissions {
		if !e.Timestamp.Before(start) && !e.Timestamp.After(end) {
			count++
		}
	}
	return count
}

// WindowShrinkEvents returns a copy of all window shrink events.
func (a *TCPHealthAnalyzer) WindowShrinkEvents() []WindowShrinkEvent {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]WindowShrinkEvent, len(a.windowShrinks))
	copy(result, a.windowShrinks)
	return result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// detectBurstsLocked is the lock-free version of DetectBursts.
// Must be called with a.mu held (read or write).
func (a *TCPHealthAnalyzer) detectBurstsLocked(minCount int) []RetransmissionBurst {
	if minCount <= 0 {
		minCount = a.config.BurstThreshold
	}

	n := len(a.retransmissions)
	if n < minCount {
		return nil
	}

	window := a.config.BurstWindow
	var bursts []RetransmissionBurst

	i := 0
	for i < n {
		j := i
		var maxRTT time.Duration

		for j < n && a.retransmissions[j].Timestamp.Sub(a.retransmissions[i].Timestamp) <= window {
			rtt := a.findRTTNear(a.retransmissions[j].Timestamp, window)
			if rtt > maxRTT {
				maxRTT = rtt
			}
			j++
		}

		count := j - i
		if count >= minCount {
			burst := RetransmissionBurst{
				StartTime:     a.retransmissions[i].Timestamp,
				EndTime:       a.retransmissions[j-1].Timestamp,
				Duration:      a.retransmissions[j-1].Timestamp.Sub(a.retransmissions[i].Timestamp),
				Count:         count,
				MaxRTTInBurst: maxRTT,
			}

			rttSum := time.Duration(0)
			rttCount := 0
			for _, s := range a.rttSamples {
				if !s.Timestamp.Before(burst.StartTime) && !s.Timestamp.After(burst.EndTime) {
					rttSum += s.RTT
					rttCount++
				}
			}
			if rttCount > 0 {
				burst.AvgRTTInBurst = rttSum / time.Duration(rttCount)
			}

			bursts = append(bursts, burst)
			i = j
		} else {
			i++
		}
	}

	return bursts
}

// correlateLocked is the lock-free version of CorrelateWithRTCM.
// Must be called with a.mu held.
func (a *TCPHealthAnalyzer) correlateLocked(interruptions []RTCMInterruption) []CongestionCorrelation {
	var results []CongestionCorrelation
	margin := a.config.CorrelationMargin

	for _, intr := range interruptions {
		windowEnd := intr.EndTime.Add(margin)

		retransCount := 0
		retransStrict := 0
		for _, r := range a.retransmissions {
			if !r.Timestamp.Before(intr.StartTime) && !r.Timestamp.After(windowEnd) {
				retransCount++
			}
			if !r.Timestamp.Before(intr.StartTime) && !r.Timestamp.After(intr.EndTime) {
				retransStrict++
			}
		}

		var avgRTT, maxRTT time.Duration
		rttCount := 0
		var rttSum time.Duration
		for _, s := range a.rttSamples {
			if !s.Timestamp.Before(intr.StartTime) && !s.Timestamp.After(intr.EndTime) {
				rttSum += s.RTT
				rttCount++
				if s.RTT > maxRTT {
					maxRTT = s.RTT
				}
			}
		}
		if rttCount > 0 {
			avgRTT = rttSum / time.Duration(rttCount)
		}

		burstOverlap := false
		for _, b := range a.detectBurstsLocked(0) {
			if !b.EndTime.Before(intr.StartTime) && !b.StartTime.After(intr.EndTime) {
				burstOverlap = true
				break
			}
		}

		cause := "other"
		if retransStrict >= a.config.BurstThreshold || burstOverlap {
			cause = "congestion"
		} else if retransCount > 0 {
			cause = "partial_congestion"
		}

		results = append(results, CongestionCorrelation{
			InterruptionStart:    intr.StartTime,
			InterruptionEnd:      intr.EndTime,
			InterruptionDuration: intr.Duration,
			RetransInWindow:      retransCount,
			BurstOverlap:         burstOverlap,
			AvgRTTDuring:         avgRTT,
			MaxRTTDuring:         maxRTT,
			ProbableCause:        cause,
		})
	}

	return results
}

// findRTTNear returns the RTT sample closest to the given timestamp,
// within the specified tolerance. Returns 0 if no sample is found.
func (a *TCPHealthAnalyzer) findRTTNear(ts time.Time, tolerance time.Duration) time.Duration {
	var best time.Duration
	bestDiff := tolerance + 1
	for _, s := range a.rttSamples {
		diff := s.Timestamp.Sub(ts)
		if diff < 0 {
			diff = -diff
		}
		if diff <= tolerance && diff < bestDiff {
			best = s.RTT
			bestDiff = diff
		}
	}
	return best
}

// sqrtF computes the square root using Newton's method, avoiding
// an import of math just for Sqrt in this file.
func sqrtF(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 20; i++ {
		z = (z + x/z) / 2
	}
	return z
}

// String returns a human-readable summary of TCP health.
func (h TCPHealthSummary) String() string {
	return fmt.Sprintf(
		"TCP Health: pkts=%d retrans=%d (%.2f%%) RTT avg=%v p95=%v max=%v jitter=%v spikes=%d shrinks=%d bursts=%d correlations=%d",
		h.TotalPackets, h.TotalRetransmissions, h.RetransmissionRate*100,
		h.RTTAvg.Round(time.Microsecond),
		h.RTTP95.Round(time.Microsecond),
		h.RTTMax.Round(time.Microsecond),
		h.RTTJitter.Round(time.Microsecond),
		h.RTTSpikes,
		h.WindowShrinks,
		len(h.Bursts),
		len(h.Correlations),
	)
}
