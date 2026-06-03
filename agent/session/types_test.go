package session

import (
	"fmt"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NTRIPSession basics
// ---------------------------------------------------------------------------

func TestNewNTRIPSession(t *testing.T) {
	now := time.Now()
	s := NewNTRIPSession("s1", "MOUNT-A", "user1", "10.0.0.1", 12345, now)

	if s.SessionID != "s1" {
		t.Errorf("SessionID = %q, want %q", s.SessionID, "s1")
	}
	if s.MountPoint != "MOUNT-A" {
		t.Errorf("MountPoint = %q, want %q", s.MountPoint, "MOUNT-A")
	}
	if !s.IsActive() {
		t.Error("new session should be active")
	}
	if s.Duration() <= 0 {
		// Duration may be 0 immediately, but should not be negative
		if s.Duration() < 0 {
			t.Error("duration should be non-negative")
		}
	}
}

func TestSessionClose(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	closeTime := start.Add(5 * time.Minute)
	s.Close(closeTime)

	if s.IsActive() {
		t.Error("closed session should not be active")
	}
	if s.Duration() != 5*time.Minute {
		t.Errorf("Duration = %v, want 5m", s.Duration())
	}
}

// ---------------------------------------------------------------------------
// GGA events
// ---------------------------------------------------------------------------

func TestAddGGAEvent(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// First event: interval should be 0
	s.AddGGAEvent(start.Add(1*time.Second), 31.24, 121.48, 1, 12, 0.8, -1, "", "")
	if len(s.GGAEvents) != 1 {
		t.Fatalf("expected 1 GGA event, got %d", len(s.GGAEvents))
	}
	if s.GGAEvents[0].Interval != 0 {
		t.Errorf("first GGA interval should be 0, got %v", s.GGAEvents[0].Interval)
	}

	// Second event: interval = 1s
	s.AddGGAEvent(start.Add(2*time.Second), 31.24, 121.48, 1, 12, 0.8, -1, "", "")
	if s.GGAEvents[1].Interval != 1*time.Second {
		t.Errorf("second GGA interval = %v, want 1s", s.GGAEvents[1].Interval)
	}

	// Third event: interval = 5s
	s.AddGGAEvent(start.Add(7*time.Second), 31.24, 121.48, 1, 12, 0.8, -1, "", "")
	if s.GGAEvents[2].Interval != 5*time.Second {
		t.Errorf("third GGA interval = %v, want 5s", s.GGAEvents[2].Interval)
	}
}

func TestGGAIntervalAnomalies(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// 1s, 1s, 10s, 1s, 8s intervals
	times := []time.Duration{1, 2, 3, 13, 14, 22}
	for i, sec := range times {
		if i == 0 {
			s.AddGGAEvent(start.Add(sec*time.Second), 31.0, 121.0, 1, 10, 1.0, -1, "", "")
		} else {
			s.AddGGAEvent(start.Add(sec*time.Second), 31.0, 121.0, 1, 10, 1.0, -1, "", "")
		}
	}

	anomalies := s.GGAIntervalAnomalies(5 * time.Second)
	if len(anomalies) != 2 {
		t.Errorf("expected 2 anomalies, got %d", len(anomalies))
		for _, a := range anomalies {
			t.Logf("  anomaly: interval=%v ts=%v", a.Interval, a.Timestamp)
		}
	}
}

func TestComputeGGAFrequency(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// 10 events over 9 seconds → ~1.11 Hz
	for i := 0; i < 10; i++ {
		s.AddGGAEvent(start.Add(time.Duration(i)*time.Second), 31.0, 121.0, 1, 10, 1.0, -1, "", "")
	}
	s.Close(start.Add(10 * time.Second))

	if s.GGAFrequency < 1.0 || s.GGAFrequency > 1.2 {
		t.Errorf("GGAFrequency = %.3f, want ~1.11", s.GGAFrequency)
	}
}

func TestGGAFrequencyNoEvents(t *testing.T) {
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, time.Now())
	s.Close(time.Now().Add(time.Minute))
	if s.GGAFrequency != 0 {
		t.Errorf("GGAFrequency = %f, want 0 for no events", s.GGAFrequency)
	}
}

// ---------------------------------------------------------------------------
// RTCM frames
// ---------------------------------------------------------------------------

func TestAddRTCMFrame(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// Add 5 frames: 1005, 1074, 1074, 1124, 1074 (one CRC error)
	frames := []struct {
		ts      time.Duration
		msgType int
		size    int
		crc     bool
	}{
		{0, 1005, 36, true},
		{10 * time.Millisecond, 1074, 298, true},
		{20 * time.Millisecond, 1074, 298, false}, // CRC error
		{30 * time.Millisecond, 1124, 312, true},
		{40 * time.Millisecond, 1074, 298, true},
	}
	for _, f := range frames {
		s.AddRTCMFrame(start.Add(f.ts), f.msgType, f.size, f.crc, time.Time{})
	}

	if s.rtcmFrameCount != 5 {
		t.Errorf("rtcmFrameCount = %d, want 5", s.rtcmFrameCount)
	}
	if s.rtcmCRCErrors != 1 {
		t.Errorf("rtcmCRCErrors = %d, want 1", s.rtcmCRCErrors)
	}
	if s.rtcmMsgTypes[1074] != 3 {
		t.Errorf("msgType 1074 count = %d, want 3", s.rtcmMsgTypes[1074])
	}
}

func TestRTCMInterruptions(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// Normal frames at 10ms intervals, then a 2s gap
	for i := 0; i < 10; i++ {
		s.AddRTCMFrame(start.Add(time.Duration(i)*10*time.Millisecond), 1074, 100, true, time.Time{})
	}
	// Big gap
	s.AddRTCMFrame(start.Add(2*time.Second+100*time.Millisecond), 1074, 100, true, time.Time{})
	s.AddRTCMFrame(start.Add(2*time.Second+110*time.Millisecond), 1074, 100, true, time.Time{})

	interruptions := s.RTCMInterruptions(500 * time.Millisecond)
	if len(interruptions) != 1 {
		t.Errorf("expected 1 interruption, got %d", len(interruptions))
	} else if interruptions[0].Duration < 1900*time.Millisecond {
		t.Errorf("interruption duration = %v, want ~2s", interruptions[0].Duration)
	}
}

func TestComputeRTCMStats(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	for i := 0; i < 100; i++ {
		s.AddRTCMFrame(start.Add(time.Duration(i)*time.Millisecond), 1074, 200, true, time.Time{})
	}
	s.Close(start.Add(100 * time.Millisecond))

	stats := s.RTCMStats
	if stats.TotalFrames != 100 {
		t.Errorf("TotalFrames = %d, want 100", stats.TotalFrames)
	}
	if stats.CRCErrors != 0 {
		t.Errorf("CRCErrors = %d, want 0", stats.CRCErrors)
	}
	if stats.CRCErrorRate != 0 {
		t.Errorf("CRCErrorRate = %f, want 0", stats.CRCErrorRate)
	}
	if stats.TotalBytes != 20000 {
		t.Errorf("TotalBytes = %d, want 20000", stats.TotalBytes)
	}
	if stats.MinInterval <= 0 {
		t.Error("MinInterval should be > 0")
	}
	if stats.MaxInterval <= 0 {
		t.Error("MaxInterval should be > 0")
	}
}

// ---------------------------------------------------------------------------
// Network quality
// ---------------------------------------------------------------------------

func TestAddRTT(t *testing.T) {
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, time.Now())
	s.AddRTT(2 * time.Millisecond)
	s.AddRTT(5 * time.Millisecond)
	s.AddRTT(50 * time.Millisecond)

	s.mu.RLock()
	n := len(s.rttSamples)
	s.mu.RUnlock()

	if n != 3 {
		t.Errorf("rttSamples = %d, want 3", n)
	}
}

func TestComputeNetworkStats(t *testing.T) {
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, time.Now())
	s.AddRTT(1 * time.Millisecond)
	s.AddRTT(2 * time.Millisecond)
	s.AddRTT(3 * time.Millisecond)
	s.AddRTT(10 * time.Millisecond)
	s.AddRTT(50 * time.Millisecond)

	s.mu.Lock()
	s.computeNetworkStats()
	s.mu.Unlock()

	nq := s.NetworkQuality
	if nq.MaxRTT != 50*time.Millisecond {
		t.Errorf("MaxRTT = %v, want 50ms", nq.MaxRTT)
	}
	if nq.AvgRTT < 1*time.Millisecond || nq.AvgRTT > 20*time.Millisecond {
		t.Errorf("AvgRTT = %v, expected ~13ms", nq.AvgRTT)
	}
	if nq.P95RTT <= 0 {
		t.Error("P95RTT should be > 0")
	}
	if nq.RTTJitter <= 0 {
		t.Error("RTTJitter should be > 0")
	}
}

func TestAddRetransmission(t *testing.T) {
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, time.Now())
	s.AddRetransmission()
	s.AddRetransmission()
	s.AddRetransmission()

	if s.NetworkQuality.TotalRetransmissions != 3 {
		t.Errorf("TotalRetransmissions = %d, want 3", s.NetworkQuality.TotalRetransmissions)
	}
}

func TestAddTCPReset(t *testing.T) {
	now := time.Now()
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, now)
	s.AddTCPReset(now, "inbound")

	if len(s.NetworkQuality.TCPResetEvents) != 1 {
		t.Fatalf("expected 1 reset event, got %d", len(s.NetworkQuality.TCPResetEvents))
	}
	if s.NetworkQuality.TCPResetEvents[0].Direction != "inbound" {
		t.Errorf("direction = %q, want inbound", s.NetworkQuality.TCPResetEvents[0].Direction)
	}
}

// ---------------------------------------------------------------------------
// Diagnostic scoring
// ---------------------------------------------------------------------------

func TestScoreHealthySession(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, start)
	s.AuthChecked = true
	s.AuthSuccess = true
	s.LoginLatency = 50 * time.Millisecond

	// Regular GGA every 1s for 60s
	for i := 0; i < 60; i++ {
		s.AddGGAEvent(start.Add(time.Duration(i)*time.Second), 31.0, 121.0, 1, 12, 0.8, -1, "", "")
	}

	// Regular RTCM every 1ms for 60s (simplified: just 100 frames)
	for i := 0; i < 100; i++ {
		s.AddRTCMFrame(start.Add(time.Duration(i)*time.Millisecond), 1074, 200, true, time.Time{})
	}

	s.Close(start.Add(60 * time.Second))

	score := s.Score(5*time.Second, 2*time.Second)
	if score.Total < 80 {
		t.Errorf("healthy session score = %d, want >= 80 (issues: %v)", score.Total, score.Issues)
	}
}

func TestScoreFailedAuth(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "baduser", "10.0.0.1", 100, start)
	s.AuthChecked = true
	s.AuthSuccess = false
	s.HTTPStatusCode = 401

	s.Close(start.Add(2 * time.Second))

	score := s.Score(5*time.Second, 2*time.Second)
	if score.LoginScore != 0 {
		t.Errorf("LoginScore = %d, want 0 for failed auth", score.LoginScore)
	}
	hasCritical := false
	for _, issue := range score.Issues {
		if issue.Severity == "critical" && issue.Category == "login" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected critical login issue")
	}
}

func TestScoreRTCMErrors(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// 50% CRC error rate
	for i := 0; i < 100; i++ {
		s.AddRTCMFrame(start.Add(time.Duration(i)*time.Millisecond), 1074, 200, i%2 == 0, time.Time{})
	}

	s.Close(start.Add(100 * time.Millisecond))

	score := s.Score(5*time.Second, 2*time.Second)
	if score.RTCMScore >= 100 {
		t.Errorf("RTCMScore = %d, want < 100 for high CRC error rate", score.RTCMScore)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestClampInt(t *testing.T) {
	tests := []struct{ v, lo, hi, want int }{
		{50, 0, 100, 50},
		{-10, 0, 100, 0},
		{150, 0, 100, 100},
		{0, 0, 100, 0},
		{100, 0, 100, 100},
	}
	for _, tc := range tests {
		got := clampInt(tc.v, tc.lo, tc.hi)
		if got != tc.want {
			t.Errorf("clampInt(%d, %d, %d) = %d, want %d", tc.v, tc.lo, tc.hi, got, tc.want)
		}
	}
}

func TestSortDurations(t *testing.T) {
	input := []time.Duration{5 * time.Second, 1 * time.Second, 3 * time.Second, 2 * time.Second, 4 * time.Second}
	sortDurations(input)
	for i := 1; i < len(input); i++ {
		if input[i] < input[i-1] {
			t.Errorf("not sorted: %v", input)
			break
		}
	}
}

func TestDefaultCorrelatorConfig(t *testing.T) {
	cfg := DefaultCorrelatorConfig()
	if cfg.ReconnectWindow != 60*time.Second {
		t.Errorf("ReconnectWindow = %v, want 60s", cfg.ReconnectWindow)
	}
	if cfg.IPChangeThreshold != 120*time.Second {
		t.Errorf("IPChangeThreshold = %v, want 120s", cfg.IPChangeThreshold)
	}
}

// ---------------------------------------------------------------------------
// Haversine distance
// ---------------------------------------------------------------------------

func TestHaversineSamePoint(t *testing.T) {
	d := Haversine(31.24, 121.48, 31.24, 121.48)
	if d != 0 {
		t.Errorf("same point distance = %f, want 0", d)
	}
}

func TestHaversineKnownDistance(t *testing.T) {
	// Shanghai (31.2304, 121.4737) → Beijing (39.9042, 116.4074) ≈ 1068 km
	d := Haversine(31.2304, 121.4737, 39.9042, 116.4074)
	if d < 1_000_000 || d > 1_100_000 {
		t.Errorf("Shanghai→Beijing = %.0f m, want ~1068 km", d)
	}
}

func TestHaversineShortDistance(t *testing.T) {
	// Two points ~111 m apart (0.001 degree latitude at equator)
	d := Haversine(0.0, 0.0, 0.001, 0.0)
	if d < 100 || d > 120 {
		t.Errorf("0.001° lat distance = %.1f m, want ~111 m", d)
	}
}

// ---------------------------------------------------------------------------
// GGA distance anomaly detection
// ---------------------------------------------------------------------------

func TestGGADistanceAnomalies(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// Positions: Shanghai area, small moves, then a big jump
	s.AddGGAEvent(start.Add(1*time.Second), 31.2300, 121.4700, 1, 12, 0.8, -1, "", "") // first, dist=0
	s.AddGGAEvent(start.Add(2*time.Second), 31.2301, 121.4701, 1, 12, 0.8, -1, "", "") // ~13m
	s.AddGGAEvent(start.Add(3*time.Second), 31.2302, 121.4702, 1, 12, 0.8, -1, "", "") // ~13m
	s.AddGGAEvent(start.Add(4*time.Second), 31.2400, 121.4800, 1, 12, 0.8, -1, "", "") // ~1.5 km jump!

	anomalies := s.GGADistanceAnomalies(500.0)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0].Distance < 500 {
		t.Errorf("anomaly distance = %.1f m, want > 500m", anomalies[0].Distance)
	}
}

func TestGGADistanceAnomaliesNone(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// All positions within ~13m
	s.AddGGAEvent(start.Add(1*time.Second), 31.2300, 121.4700, 1, 12, 0.8, -1, "", "")
	s.AddGGAEvent(start.Add(2*time.Second), 31.2301, 121.4701, 1, 12, 0.8, -1, "", "")
	s.AddGGAEvent(start.Add(3*time.Second), 31.2302, 121.4702, 1, 12, 0.8, -1, "", "")

	anomalies := s.GGADistanceAnomalies(500.0)
	if len(anomalies) != 0 {
		t.Errorf("expected 0 anomalies, got %d", len(anomalies))
	}
}

func TestGGADistanceTracking(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	s.AddGGAEvent(start.Add(1*time.Second), 31.2300, 121.4700, 1, 12, 0.8, -1, "", "")
	s.AddGGAEvent(start.Add(2*time.Second), 31.2301, 121.4701, 1, 12, 0.8, -1, "", "")

	if s.GGAEvents[0].Distance != 0 {
		t.Errorf("first GGA distance should be 0, got %f", s.GGAEvents[0].Distance)
	}
	if s.GGAEvents[1].Distance <= 0 {
		t.Errorf("second GGA distance should be > 0, got %f", s.GGAEvents[1].Distance)
	}
}

// ---------------------------------------------------------------------------
// GGA summary
// ---------------------------------------------------------------------------

func TestComputeGGASummaryEmpty(t *testing.T) {
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, time.Now())
	summary := s.ComputeGGASummary()
	if summary.TotalEvents != 0 {
		t.Errorf("TotalEvents = %d, want 0", summary.TotalEvents)
	}
	if summary.MinSatellites != 0 {
		t.Errorf("MinSatellites = %d, want 0 for empty", summary.MinSatellites)
	}
}

func TestComputeGGASummaryMixed(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// Simulate 10 GGA events with mixed fix quality
	// 6 RTK-fixed (4), 2 RTK-float (5), 1 DGPS (2), 1 GPS (1)
	fixes := []int{4, 4, 4, 5, 4, 2, 4, 5, 1, 4}
	sats := []int{18, 19, 17, 16, 20, 15, 18, 14, 12, 19}
	diffAges := []float64{1.2, 1.5, 1.0, 2.0, 0.8, 3.5, 1.1, 2.2, -1, 1.3} // -1 = not present
	stations := []string{"0312", "0312", "0312", "0313", "0312", "0313", "0312", "0312", "", "0312"}

	for i := 0; i < 10; i++ {
		s.AddGGAEvent(
			start.Add(time.Duration(i)*time.Second),
			31.0+float64(i)*0.0001, 121.0,
			fixes[i], sats[i], 0.8,
			diffAges[i], stations[i], "",
		)
	}

	summary := s.ComputeGGASummary()

	if summary.TotalEvents != 10 {
		t.Errorf("TotalEvents = %d, want 10", summary.TotalEvents)
	}

	// Fix distribution
	if summary.FixDistribution[4] != 6 {
		t.Errorf("RTK-fixed count = %d, want 6", summary.FixDistribution[4])
	}
	if summary.FixDistribution[5] != 2 {
		t.Errorf("RTK-float count = %d, want 2", summary.FixDistribution[5])
	}
	if summary.FixDistribution[2] != 1 {
		t.Errorf("DGPS count = %d, want 1", summary.FixDistribution[2])
	}
	if summary.FixDistribution[1] != 1 {
		t.Errorf("GPS count = %d, want 1", summary.FixDistribution[1])
	}

	// Fix rate = 6/10 = 0.6
	if summary.FixRate < 0.59 || summary.FixRate > 0.61 {
		t.Errorf("FixRate = %f, want 0.6", summary.FixRate)
	}

	// Satellites
	if summary.MinSatellites != 12 {
		t.Errorf("MinSatellites = %d, want 12", summary.MinSatellites)
	}
	if summary.MaxSatellites != 20 {
		t.Errorf("MaxSatellites = %d, want 20", summary.MaxSatellites)
	}
	expectedAvgSats := (18 + 19 + 17 + 16 + 20 + 15 + 18 + 14 + 12 + 19) / 10.0
	if summary.AvgSatellites < expectedAvgSats-0.1 || summary.AvgSatellites > expectedAvgSats+0.1 {
		t.Errorf("AvgSatellites = %f, want ~%f", summary.AvgSatellites, expectedAvgSats)
	}

	// DiffAge (exclude -1 entry, 9 valid values)
	if summary.MaxDiffAge != 3.5 {
		t.Errorf("MaxDiffAge = %f, want 3.5", summary.MaxDiffAge)
	}
	if summary.AvgDiffAge <= 0 {
		t.Error("AvgDiffAge should be > 0")
	}

	// Station IDs
	if len(summary.StationIDs) != 2 {
		t.Errorf("StationIDs = %v, want 2 unique IDs (0312, 0313)", summary.StationIDs)
	}
}

func TestComputeGGASummaryAllRTKFixed(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	for i := 0; i < 5; i++ {
		s.AddGGAEvent(
			start.Add(time.Duration(i)*time.Second),
			31.0, 121.0, 4, 18, 0.8, 1.0, "0312", "",
		)
	}

	summary := s.ComputeGGASummary()
	if summary.FixRate != 1.0 {
		t.Errorf("FixRate = %f, want 1.0 (all RTK-fixed)", summary.FixRate)
	}
}

func TestGGASummaryNoDiffAge(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// All events with no diff age (-1)
	for i := 0; i < 5; i++ {
		s.AddGGAEvent(
			start.Add(time.Duration(i)*time.Second),
			31.0, 121.0, 1, 10, 1.0, -1, "", "",
		)
	}

	summary := s.ComputeGGASummary()
	if summary.AvgDiffAge != 0 {
		t.Errorf("AvgDiffAge = %f, want 0 when no valid diff age", summary.AvgDiffAge)
	}
	if summary.MaxDiffAge != 0 {
		t.Errorf("MaxDiffAge = %f, want 0", summary.MaxDiffAge)
	}
	if len(summary.StationIDs) != 0 {
		t.Errorf("StationIDs = %v, want empty", summary.StationIDs)
	}
}

// ---------------------------------------------------------------------------
// Disconnect reason analysis
// ---------------------------------------------------------------------------

func TestAnalyzeDisconnectAuthFailed(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "bad", "10.0.0.1", 100, start)
	s.AuthChecked = true
	s.AuthSuccess = false
	s.HTTPStatusCode = 401
	s.CloseDirection = CloseServer
	closeTime := start.Add(2 * time.Second)
	s.Close(closeTime)

	s.AnalyzeDisconnect(60*time.Second, 5, false)

	if s.DisconnectReason != DisconnectAuthFailed {
		t.Errorf("DisconnectReason = %v, want DisconnectAuthFailed", s.DisconnectReason)
	}
}

func TestAnalyzeDisconnectKickOut(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, start)
	s.AuthChecked = true
	s.AuthSuccess = true
	s.CloseDirection = CloseServer
	closeTime := start.Add(5 * time.Second)
	s.Close(closeTime)

	s.AnalyzeDisconnect(60*time.Second, 5, true)

	if s.DisconnectReason != DisconnectAccountKickOut {
		t.Errorf("DisconnectReason = %v, want DisconnectAccountKickOut", s.DisconnectReason)
	}
}

func TestAnalyzeDisconnectClientInitiated(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, start)
	s.AuthChecked = true
	s.AuthSuccess = true
	s.CloseDirection = CloseClient
	closeTime := start.Add(10 * time.Minute)
	s.Close(closeTime)

	s.AnalyzeDisconnect(60*time.Second, 5, false)

	if s.DisconnectReason != DisconnectClientInitiated {
		t.Errorf("DisconnectReason = %v, want DisconnectClientInitiated", s.DisconnectReason)
	}
}

func TestAnalyzeDisconnectRTCMAbort(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, start)
	s.AuthChecked = true
	s.AuthSuccess = true
	s.CloseDirection = CloseServer
	s.recentRetransCount = 10
	// Add some GGA so the GGA timeout rule doesn't take priority
	s.AddGGAEvent(start.Add(4*time.Minute+50*time.Second), 31.0, 121.0, 1, 10, 1.0, -1, "", "")
	closeTime := start.Add(5 * time.Minute)
	s.Close(closeTime)

	s.AnalyzeDisconnect(60*time.Second, 5, false)

	if s.DisconnectReason != DisconnectRTCMAbort {
		t.Errorf("DisconnectReason = %v, want DisconnectRTCMAbort", s.DisconnectReason)
	}
}

func TestAnalyzeDisconnectGGATimeout(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "MOUNT-A", "user1", "10.0.0.1", 100, start)
	s.AuthChecked = true
	s.AuthSuccess = true
	s.CloseDirection = CloseServer
	// GGA at T+1s, then nothing for 119s
	s.AddGGAEvent(start.Add(1*time.Second), 31.0, 121.0, 1, 10, 1.0, -1, "", "")
	closeTime := start.Add(120 * time.Second)
	s.Close(closeTime)

	s.AnalyzeDisconnect(60*time.Second, 5, false)

	if s.DisconnectReason != DisconnectGGATimeout {
		t.Errorf("DisconnectReason = %v, want DisconnectGGATimeout (detail: %s)", s.DisconnectReason, s.DisconnectDetail)
	}
}

func TestAnalyzeDisconnectGGANoGGAAtAll(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "MOUNT-A", "user1", "10.0.0.1", 100, start)
	s.AuthChecked = true
	s.AuthSuccess = true
	s.CloseDirection = CloseServer
	s.LastActivityType = "auth"
	closeTime := start.Add(30 * time.Second)
	s.Close(closeTime)

	s.AnalyzeDisconnect(60*time.Second, 5, false)

	if s.DisconnectReason != DisconnectGGATimeout {
		t.Errorf("DisconnectReason = %v, want DisconnectGGATimeout for no-GGA session", s.DisconnectReason)
	}
}

func TestAnalyzeDisconnectUnknown(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, start)
	s.AuthChecked = true
	s.AuthSuccess = true
	s.CloseDirection = CloseReset
	s.LastActivityType = "rtcm"
	s.LastActivityTime = start.Add(4 * time.Minute)
	closeTime := start.Add(5 * time.Minute)
	s.Close(closeTime)

	s.AnalyzeDisconnect(60*time.Second, 5, false)

	if s.DisconnectReason != DisconnectUnknown {
		t.Errorf("DisconnectReason = %v, want DisconnectUnknown", s.DisconnectReason)
	}
}

func TestDisconnectReasonString(t *testing.T) {
	tests := []struct {
		reason DisconnectReason
		want   string
	}{
		{DisconnectUnknown, "unknown"},
		{DisconnectGGATimeout, "gga_timeout"},
		{DisconnectClientInitiated, "client_initiated"},
		{DisconnectRTCMAbort, "rtcm_retransmission_abort"},
		{DisconnectAccountKickOut, "account_kickout"},
		{DisconnectAuthFailed, "auth_failed"},
	}
	for _, tc := range tests {
		if tc.reason.String() != tc.want {
			t.Errorf("DisconnectReason(%d).String() = %q, want %q", tc.reason, tc.reason.String(), tc.want)
		}
	}
}

func TestCloseDirectionString(t *testing.T) {
	tests := []struct {
		dir  CloseDirection
		want string
	}{
		{CloseDirectionUnknown, "unknown"},
		{CloseClient, "client"},
		{CloseServer, "server"},
		{CloseReset, "reset"},
	}
	for _, tc := range tests {
		if tc.dir.String() != tc.want {
			t.Errorf("CloseDirection(%d).String() = %q, want %q", tc.dir, tc.dir.String(), tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// SessionCorrelator
// ---------------------------------------------------------------------------

func TestCorrelatorReconnectSameIP(t *testing.T) {
	cfg := DefaultCorrelatorConfig()
	c := NewSessionCorrelator(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Session 1
	s1 := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, base)
	c.OnSessionCreated(s1)

	// Close session 1
	closeTime := base.Add(5 * time.Minute)
	s1.Close(closeTime)

	// Session 2 starts 3s after close (within 60s window), same IP
	s2 := NewNTRIPSession("s2", "M", "user1", "10.0.0.1", 101, base.Add(5*time.Minute+3*time.Second))
	c.OnSessionCreated(s2)

	events := c.ReconnectEvents("user1")
	if len(events) != 1 {
		t.Fatalf("expected 1 reconnect event, got %d", len(events))
	}
	if events[0].IPChanged {
		t.Error("expected IPChanged = false for same-IP reconnect")
	}
	if events[0].Downtime != 3*time.Second {
		t.Errorf("Downtime = %v, want 3s", events[0].Downtime)
	}
}

func TestCorrelatorReconnectIPChanged(t *testing.T) {
	cfg := DefaultCorrelatorConfig()
	c := NewSessionCorrelator(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	s1 := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, base)
	c.OnSessionCreated(s1)

	closeTime := base.Add(5 * time.Minute)
	s1.Close(closeTime)

	// Session 2 from different IP (WiFi → 4G switch)
	s2 := NewNTRIPSession("s2", "M", "user1", "10.0.0.2", 101, base.Add(5*time.Minute+5*time.Second))
	c.OnSessionCreated(s2)

	events := c.ReconnectEvents("user1")
	if len(events) != 1 {
		t.Fatalf("expected 1 reconnect event, got %d", len(events))
	}
	if !events[0].IPChanged {
		t.Error("expected IPChanged = true for different-IP reconnect")
	}
}

func TestCorrelatorNoReconnectTooLong(t *testing.T) {
	cfg := DefaultCorrelatorConfig() // 60s window
	c := NewSessionCorrelator(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	s1 := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, base)
	c.OnSessionCreated(s1)

	closeTime := base.Add(5 * time.Minute)
	s1.Close(closeTime)

	// Session 2 starts 5 minutes after close → too long for reconnect
	s2 := NewNTRIPSession("s2", "M", "user1", "10.0.0.1", 101, base.Add(10*time.Minute))
	c.OnSessionCreated(s2)

	events := c.ReconnectEvents("user1")
	if len(events) != 0 {
		t.Errorf("expected 0 reconnect events (gap too long), got %d", len(events))
	}
}

func TestCorrelatorNoReconnectForEmptyUser(t *testing.T) {
	cfg := DefaultCorrelatorConfig()
	c := NewSessionCorrelator(cfg)

	s := NewNTRIPSession("s1", "M", "", "10.0.0.1", 100, time.Now())
	c.OnSessionCreated(s)

	if len(c.Usernames()) != 0 {
		t.Errorf("expected 0 usernames for empty user, got %d", len(c.Usernames()))
	}
}

func TestCorrelatorSessionsForUser(t *testing.T) {
	cfg := DefaultCorrelatorConfig()
	c := NewSessionCorrelator(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	s1 := NewNTRIPSession("s1", "M", "alice", "10.0.0.1", 100, base)
	c.OnSessionCreated(s1)

	s2 := NewNTRIPSession("s2", "M", "alice", "10.0.0.1", 101, base.Add(10*time.Minute))
	c.OnSessionCreated(s2)

	sessions := c.SessionsForUser("alice")
	if len(sessions) != 2 {
		t.Errorf("alice sessions = %d, want 2", len(sessions))
	}

	nobody := c.SessionsForUser("nobody")
	if len(nobody) != 0 {
		t.Errorf("nobody sessions = %d, want 0", len(nobody))
	}
}

func TestCorrelatorAccountSummary(t *testing.T) {
	cfg := DefaultCorrelatorConfig()
	c := NewSessionCorrelator(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Session 1: successful auth, normal close
	s1 := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, base)
	s1.AuthChecked = true
	s1.AuthSuccess = true
	c.OnSessionCreated(s1)
	closeTime1 := base.Add(5 * time.Minute)
	s1.Close(closeTime1)

	// Session 2: reconnect from different IP
	s2 := NewNTRIPSession("s2", "M", "user1", "10.0.0.2", 101, base.Add(5*time.Minute+3*time.Second))
	s2.AuthChecked = true
	s2.AuthSuccess = true
	c.OnSessionCreated(s2)

	summary := c.SummarizeAccount("user1")
	if summary.Username != "user1" {
		t.Errorf("Username = %q, want user1", summary.Username)
	}
	if summary.TotalSessions != 2 {
		t.Errorf("TotalSessions = %d, want 2", summary.TotalSessions)
	}
	if summary.ActiveSessions != 1 {
		t.Errorf("ActiveSessions = %d, want 1", summary.ActiveSessions)
	}
	if summary.TotalReconnects != 1 {
		t.Errorf("TotalReconnects = %d, want 1", summary.TotalReconnects)
	}
	if summary.IPChanges != 1 {
		t.Errorf("IPChanges = %d, want 1", summary.IPChanges)
	}
}

func TestCorrelatorAccountSummaryWithKickOut(t *testing.T) {
	cfg := DefaultCorrelatorConfig()
	c := NewSessionCorrelator(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	s1 := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, base)
	s1.AuthChecked = true
	s1.AuthSuccess = true
	s1.DisconnectReason = DisconnectAccountKickOut
	c.OnSessionCreated(s1)
	closeTime1 := base.Add(5 * time.Second)
	s1.Close(closeTime1)

	summary := c.SummarizeAccount("user1")
	if summary.KickOuts != 1 {
		t.Errorf("KickOuts = %d, want 1", summary.KickOuts)
	}
}

func TestCorrelatorAccountSummaryWithAuthFailure(t *testing.T) {
	cfg := DefaultCorrelatorConfig()
	c := NewSessionCorrelator(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	s1 := NewNTRIPSession("s1", "M", "user1", "10.0.0.1", 100, base)
	s1.AuthChecked = true
	s1.AuthSuccess = false
	s1.DisconnectReason = DisconnectAuthFailed
	c.OnSessionCreated(s1)
	closeTime1 := base.Add(2 * time.Second)
	s1.Close(closeTime1)

	summary := c.SummarizeAccount("user1")
	if summary.AuthFailures != 1 {
		t.Errorf("AuthFailures = %d, want 1", summary.AuthFailures)
	}
}

func TestReconnectEventString(t *testing.T) {
	ev := ReconnectEvent{
		OldSessionID: "s1",
		NewSessionID: "s2",
		OldClientIP:  "10.0.0.1",
		NewClientIP:  "10.0.0.1",
		Downtime:     3 * time.Second,
		IPChanged:    false,
	}
	str := ev.String()
	if str == "" {
		t.Error("ReconnectEvent.String() should not be empty")
	}

	evIP := ReconnectEvent{
		OldClientIP: "10.0.0.1",
		NewClientIP: "10.0.0.2",
		Downtime:    5 * time.Second,
		IPChanged:   true,
	}
	strIP := evIP.String()
	if strIP == "" {
		t.Error("ReconnectEvent.String() with IP change should not be empty")
	}
}

// ---------------------------------------------------------------------------
// GGA UTC time parsing
// ---------------------------------------------------------------------------

func TestParseGGAUtcTimeBasic(t *testing.T) {
	// "143025.50" → 14:30:25.50
	captureTime := time.Date(2026, 6, 3, 14, 30, 26, 0, time.UTC)
	result := ParseGGAUtcTime("143025.50", captureTime)

	if result.IsZero() {
		t.Fatal("ParseGGAUtcTime returned zero")
	}
	if result.Hour() != 14 || result.Minute() != 30 || result.Second() != 25 {
		t.Errorf("time = %v, want 14:30:25", result)
	}
	if result.Nanosecond() != 500_000_000 {
		t.Errorf("nanos = %d, want 500000000", result.Nanosecond())
	}
}

func TestParseGGAUtcTimeMidnightWrap(t *testing.T) {
	// Capture at 00:00:05, GGA says 23:59:58 → should be previous day
	captureTime := time.Date(2026, 6, 4, 0, 0, 5, 0, time.UTC)
	result := ParseGGAUtcTime("235958.00", captureTime)

	if result.Day() != 3 {
		t.Errorf("day = %d, want 3 (previous day due to midnight wrap)", result.Day())
	}
}

func TestParseGGAUtcTimeInvalid(t *testing.T) {
	tests := []string{"", "12345", "250000.00", "126000.00", "abcdef"}
	for _, s := range tests {
		result := ParseGGAUtcTime(s, time.Now())
		if !result.IsZero() {
			t.Errorf("ParseGGAUtcTime(%q) = %v, want zero", s, result)
		}
	}
}

// ---------------------------------------------------------------------------
// GGA latency tracking
// ---------------------------------------------------------------------------

func TestGGALatencyTracking(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// GGA at capture time 14:00:01, with UTC time "140000.50" (0.5s ago)
	s.AddGGAEvent(start.Add(1*time.Second), 31.0, 121.0, 4, 18, 0.8, 1.0, "0312", "140000.50")

	if len(s.GGAEvents) != 1 {
		t.Fatal("expected 1 GGA event")
	}
	ev := s.GGAEvents[0]
	if ev.GGAUtcTime.IsZero() {
		t.Fatal("GGAUtcTime should not be zero")
	}
	if ev.Latency <= 0 {
		t.Errorf("Latency = %v, want > 0 (capture is after GGA UTC)", ev.Latency)
	}
}

func TestGGALatencyNoUtcTime(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// No UTC time string → latency should be 0
	s.AddGGAEvent(start.Add(1*time.Second), 31.0, 121.0, 1, 10, 1.0, -1, "", "")

	ev := s.GGAEvents[0]
	if !ev.GGAUtcTime.IsZero() {
		t.Error("GGAUtcTime should be zero when no UTC string provided")
	}
	if ev.Latency != 0 {
		t.Errorf("Latency = %v, want 0", ev.Latency)
	}
}

func TestGGALatencyStats(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// 5 GGA events with ~1s latency each
	for i := 0; i < 5; i++ {
		captureTime := start.Add(time.Duration(i+1) * time.Second)
		// UTC time is 0.5s before capture
		utcStr := fmt.Sprintf("14%02d%05.2f", 0, float64(i)+0.5)
		s.AddGGAEvent(captureTime, 31.0, 121.0, 4, 18, 0.8, 1.0, "0312", utcStr)
	}

	stats := s.GGALatencyStats()
	if stats.Count != 5 {
		t.Errorf("Count = %d, want 5", stats.Count)
	}
	if stats.Avg <= 0 {
		t.Error("Avg should be > 0")
	}
}

// ---------------------------------------------------------------------------
// RTCM latency tracking
// ---------------------------------------------------------------------------

func TestRTCMLatencyTracking(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// Simulate RTCM frame with epoch time 100ms before capture
	captureTime := start.Add(1 * time.Second)
	epochTime := captureTime.Add(-100 * time.Millisecond)
	s.AddRTCMFrame(captureTime, 1074, 200, true, epochTime)

	if len(s.RTCMEvents) != 1 {
		t.Fatal("expected 1 RTCM event")
	}
	ev := s.RTCMEvents[0]
	if ev.EpochTime.IsZero() {
		t.Fatal("EpochTime should not be zero")
	}
	if ev.Latency != 100*time.Millisecond {
		t.Errorf("Latency = %v, want 100ms", ev.Latency)
	}
}

func TestRTCMLatencyNoEpoch(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// No epoch time → latency should be 0
	s.AddRTCMFrame(start.Add(1*time.Second), 1005, 100, true, time.Time{})

	ev := s.RTCMEvents[0]
	if !ev.EpochTime.IsZero() {
		t.Error("EpochTime should be zero")
	}
	if ev.Latency != 0 {
		t.Errorf("Latency = %v, want 0", ev.Latency)
	}
}

func TestRTCMLatencyStats(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// 10 RTCM frames with varying latency (50-150ms)
	for i := 0; i < 10; i++ {
		captureTime := start.Add(time.Duration(i+1) * time.Second)
		latency := time.Duration(50+i*10) * time.Millisecond
		epochTime := captureTime.Add(-latency)
		s.AddRTCMFrame(captureTime, 1074, 200, true, epochTime)
	}

	stats := s.RTCMLatencyStats()
	if stats.Count != 10 {
		t.Errorf("Count = %d, want 10", stats.Count)
	}
	if stats.Min != 50*time.Millisecond {
		t.Errorf("Min = %v, want 50ms", stats.Min)
	}
	if stats.Max != 140*time.Millisecond {
		t.Errorf("Max = %v, want 140ms", stats.Max)
	}
	if stats.P95 <= 0 {
		t.Error("P95 should be > 0")
	}
}

// ---------------------------------------------------------------------------
// ComputeLatencyStats
// ---------------------------------------------------------------------------

func TestComputeLatencyStatsEmpty(t *testing.T) {
	stats := ComputeLatencyStats(nil)
	if stats.Count != 0 {
		t.Errorf("Count = %d, want 0", stats.Count)
	}
	if stats.Avg != 0 || stats.Min != 0 || stats.Max != 0 {
		t.Error("all stats should be 0 for empty input")
	}
}

func TestComputeLatencyStatsSingle(t *testing.T) {
	stats := ComputeLatencyStats([]time.Duration{100 * time.Millisecond})
	if stats.Count != 1 {
		t.Errorf("Count = %d, want 1", stats.Count)
	}
	if stats.Avg != 100*time.Millisecond {
		t.Errorf("Avg = %v, want 100ms", stats.Avg)
	}
	if stats.P50 != 100*time.Millisecond {
		t.Errorf("P50 = %v, want 100ms", stats.P50)
	}
}
