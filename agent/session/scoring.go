package session

import (
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Diagnostic scoring engine
// ---------------------------------------------------------------------------
//
// Extracted from types.go (DEVELOPMENT_PLAN §5.10 planned scoring.go). Produces
// a 0-100 health score per session across five weighted dimensions:
//   login 15% · gga 20% · rtcm 35% · network 20% · stability 10%

// Scoring weights (percent). They must sum to 100.
const (
	weightLogin     = 15
	weightGGA       = 20
	weightRTCM      = 35
	weightNetwork   = 20
	weightStability = 10
)

// DiagnosticScore holds the per-dimension scores for a session.
type DiagnosticScore struct {
	Total          int // 0-100
	LoginScore     int // 0-100
	GGAScore       int // 0-100
	RTCMScore      int // 0-100
	NetworkScore   int // 0-100
	StabilityScore int // 0-100
	Issues         []DiagnosticIssue
}

// DiagnosticIssue describes a single detected problem.
type DiagnosticIssue struct {
	Category    string // "login", "gga", "rtcm", "network", "stability"
	Severity    string // "warning", "error", "critical"
	Description string
	Timestamp   time.Time // when the issue occurred (zero if N/A)
}

// Score computes the diagnostic score for a session.
func (s *NTRIPSession) Score(ggaWarnInterval, rtcmWarnInterval time.Duration) DiagnosticScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	score := DiagnosticScore{
		LoginScore:     100,
		GGAScore:       100,
		RTCMScore:      100,
		NetworkScore:   100,
		StabilityScore: 100,
	}

	// Login scoring — only penalize when we have a concrete failure
	// (response seen with non-2xx status), not when auth was merely
	// observed without a response (e.g. loopback split-capture).
	if s.AuthChecked && !s.AuthSuccess && s.HTTPStatusCode > 0 {
		score.LoginScore -= 100
		score.Issues = append(score.Issues, DiagnosticIssue{
			Category:    "login",
			Severity:    "critical",
			Description: fmt.Sprintf("Authentication failed (HTTP %d)", s.HTTPStatusCode),
		})
	}
	if s.LoginLatency > 5*time.Second {
		score.LoginScore -= 30
		score.Issues = append(score.Issues, DiagnosticIssue{
			Category:    "login",
			Severity:    "warning",
			Description: fmt.Sprintf("Login latency %.1fs exceeds 5s threshold", s.LoginLatency.Seconds()),
			Timestamp:   s.ConnStartTime,
		})
	}

	// GGA scoring
	ggaAnomalies := 0
	for _, e := range s.GGAEvents {
		if e.Interval > ggaWarnInterval {
			ggaAnomalies++
			score.GGAScore -= 3
		}
	}
	if ggaAnomalies > 0 {
		score.Issues = append(score.Issues, DiagnosticIssue{
			Category:    "gga",
			Severity:    "warning",
			Description: fmt.Sprintf("%d GGA interval anomalies (threshold %s)", ggaAnomalies, ggaWarnInterval),
		})
	}
	if len(s.GGAEvents) == 0 && s.durationLocked() > 30*time.Second {
		score.GGAScore -= 20
		score.Issues = append(score.Issues, DiagnosticIssue{
			Category:    "gga",
			Severity:    "warning",
			Description: "No GGA uploads detected during session",
		})
	}

	// RTCM scoring
	for _, intr := range s.RTCMStats.Interruptions {
		if intr.Duration > rtcmWarnInterval {
			score.RTCMScore -= 5
			score.Issues = append(score.Issues, DiagnosticIssue{
				Category:    "rtcm",
				Severity:    "warning",
				Description: fmt.Sprintf("RTCM interruption %.1fs at %s", intr.Duration.Seconds(), intr.StartTime.Format(time.RFC3339)),
				Timestamp:   intr.StartTime,
			})
		}
	}
	if s.RTCMStats.CRCErrorRate > 0.01 {
		score.RTCMScore -= 10
		score.Issues = append(score.Issues, DiagnosticIssue{
			Category:    "rtcm",
			Severity:    "error",
			Description: fmt.Sprintf("CRC error rate %.2f%% exceeds 1%%", s.RTCMStats.CRCErrorRate*100),
		})
	}

	// Network scoring
	if s.NetworkQuality.RetransmissionRate > 0.01 {
		score.NetworkScore -= 5
		score.Issues = append(score.Issues, DiagnosticIssue{
			Category:    "network",
			Severity:    "warning",
			Description: fmt.Sprintf("TCP retransmission rate %.2f%%", s.NetworkQuality.RetransmissionRate*100),
		})
	}
	if s.NetworkQuality.P95RTT > 50*time.Millisecond {
		score.NetworkScore -= 5
		score.Issues = append(score.Issues, DiagnosticIssue{
			Category:    "network",
			Severity:    "warning",
			Description: fmt.Sprintf("RTT P95 %.1fms exceeds 50ms", float64(s.NetworkQuality.P95RTT)/float64(time.Millisecond)),
		})
	}

	// Stability scoring
	if s.ConnCloseTime != nil && s.durationLocked() < 10*time.Second {
		score.StabilityScore -= 10
		score.Issues = append(score.Issues, DiagnosticIssue{
			Category:    "stability",
			Severity:    "warning",
			Description: fmt.Sprintf("Short-lived session: %.1fs", s.durationLocked().Seconds()),
			Timestamp:   s.ConnStartTime,
		})
	}
	for _, rst := range s.NetworkQuality.TCPResetEvents {
		score.StabilityScore -= 5
		score.Issues = append(score.Issues, DiagnosticIssue{
			Category:    "stability",
			Severity:    "warning",
			Description: fmt.Sprintf("TCP reset (%s) at %s", rst.Direction, rst.Timestamp.Format(time.RFC3339)),
			Timestamp:   rst.Timestamp,
		})
	}

	// Clamp scores to [0, 100]
	score.LoginScore = clampInt(score.LoginScore, 0, 100)
	score.GGAScore = clampInt(score.GGAScore, 0, 100)
	score.RTCMScore = clampInt(score.RTCMScore, 0, 100)
	score.NetworkScore = clampInt(score.NetworkScore, 0, 100)
	score.StabilityScore = clampInt(score.StabilityScore, 0, 100)

	// Weighted total
	score.Total = score.LoginScore*weightLogin/100 +
		score.GGAScore*weightGGA/100 +
		score.RTCMScore*weightRTCM/100 +
		score.NetworkScore*weightNetwork/100 +
		score.StabilityScore*weightStability/100

	return score
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
