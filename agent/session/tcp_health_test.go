package session

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestDefaultTCPHealthConfig(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	if cfg.BurstThreshold != 3 {
		t.Errorf("BurstThreshold = %d, want 3", cfg.BurstThreshold)
	}
	if cfg.BurstWindow != 5*time.Second {
		t.Errorf("BurstWindow = %v, want 5s", cfg.BurstWindow)
	}
	if cfg.RTTSpikeThreshold != 100*time.Millisecond {
		t.Errorf("RTTSpikeThreshold = %v, want 100ms", cfg.RTTSpikeThreshold)
	}
	if cfg.WindowShrinkRatio != 0.5 {
		t.Errorf("WindowShrinkRatio = %f, want 0.5", cfg.WindowShrinkRatio)
	}
	if cfg.CorrelationMargin != 2*time.Second {
		t.Errorf("CorrelationMargin = %v, want 2s", cfg.CorrelationMargin)
	}
}

// ---------------------------------------------------------------------------
// Packet recording and retransmission counting
// ---------------------------------------------------------------------------

func TestRecordPacketOriginal(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// 5 original packets with different seq numbers
	for i := uint32(1); i <= 5; i++ {
		a.RecordPacket(i, base.Add(time.Duration(i)*time.Millisecond), false)
	}

	if a.TotalPackets() != 5 {
		t.Errorf("TotalPackets = %d, want 5", a.TotalPackets())
	}
	if a.RetransmissionCount() != 0 {
		t.Errorf("RetransmissionCount = %d, want 0", a.RetransmissionCount())
	}
}

func TestRecordPacketAutoDetectRetransmission(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// First send seq=100 (original)
	a.RecordPacket(100, base, false)
	// Send seq=100 again → auto-detected retransmission
	a.RecordPacket(100, base.Add(100*time.Millisecond), false)
	// seq=200 (original)
	a.RecordPacket(200, base.Add(200*time.Millisecond), false)
	// seq=100 again → another retransmission
	a.RecordPacket(100, base.Add(300*time.Millisecond), false)

	if a.TotalPackets() != 4 {
		t.Errorf("TotalPackets = %d, want 4", a.TotalPackets())
	}
	if a.RetransmissionCount() != 2 {
		t.Errorf("RetransmissionCount = %d, want 2 (auto-detected dup seqs)", a.RetransmissionCount())
	}
}

func TestRecordPacketExplicitRetransmission(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	a.RecordPacket(100, base, false)                           // original
	a.RecordPacket(100, base.Add(50*time.Millisecond), true)   // explicit retransmit
	a.RecordPacket(200, base.Add(100*time.Millisecond), false) // original

	if a.TotalPackets() != 3 {
		t.Errorf("TotalPackets = %d, want 3", a.TotalPackets())
	}
	if a.RetransmissionCount() != 1 {
		t.Errorf("RetransmissionCount = %d, want 1", a.RetransmissionCount())
	}
}

func TestRecordRetransmissionExplicit(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	a.RecordRetransmission(base, 100, 1400)
	a.RecordRetransmission(base.Add(100*time.Millisecond), 200, 1400)
	a.RecordRetransmission(base.Add(200*time.Millisecond), 300, 700)

	if a.RetransmissionCount() != 3 {
		t.Errorf("RetransmissionCount = %d, want 3", a.RetransmissionCount())
	}
	if a.TotalPackets() != 3 {
		t.Errorf("TotalPackets = %d, want 3", a.TotalPackets())
	}

	events := a.RetransmissionEvents()
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	if events[0].Size != 1400 {
		t.Errorf("first event size = %d, want 1400", events[0].Size)
	}
}

func TestComputeRetransmissionRate(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// 100 packets, 5 retransmissions → 5%
	for i := 0; i < 95; i++ {
		a.RecordPacket(uint32(i+1), base.Add(time.Duration(i)*time.Millisecond), false)
	}
	for i := 0; i < 5; i++ {
		a.RecordPacket(uint32(i+1), base.Add(time.Duration(95+i)*time.Millisecond), true)
	}

	rate := a.ComputeRetransmissionRate()
	if rate < 0.049 || rate > 0.051 {
		t.Errorf("RetransmissionRate = %.4f, want ~0.05", rate)
	}
}

func TestComputeRetransmissionRateNoPackets(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	rate := a.ComputeRetransmissionRate()
	if rate != 0 {
		t.Errorf("RetransmissionRate = %f, want 0 for no packets", rate)
	}
}

func TestRecordPacketSeqZero(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// seq=0 should not trigger auto-detection
	a.RecordPacket(0, base, false)
	a.RecordPacket(0, base.Add(time.Millisecond), false)
	a.RecordPacket(0, base.Add(2*time.Millisecond), false)

	if a.RetransmissionCount() != 0 {
		t.Errorf("RetransmissionCount = %d, want 0 (seq=0 should not auto-detect)", a.RetransmissionCount())
	}
}

// ---------------------------------------------------------------------------
// RTT recording and spike detection
// ---------------------------------------------------------------------------

func TestRecordRTT(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	a.RecordRTTAt(10*time.Millisecond, 100, time.Now())
	a.RecordRTTAt(20*time.Millisecond, 200, time.Now())
	a.RecordRTTAt(200*time.Millisecond, 300, time.Now()) // spike!

	if a.RTTSampleCount() != 3 {
		t.Errorf("RTTSampleCount = %d, want 3", a.RTTSampleCount())
	}
}

func TestRTTSpikeCount(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.RTTSpikeThreshold = 50 * time.Millisecond
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	rtts := []time.Duration{
		10 * time.Millisecond,  // normal
		20 * time.Millisecond,  // normal
		60 * time.Millisecond,  // spike
		150 * time.Millisecond, // spike
		30 * time.Millisecond,  // normal
		80 * time.Millisecond,  // spike
	}
	for i, rtt := range rtts {
		a.RecordRTTAt(rtt, uint32(i+1), base.Add(time.Duration(i)*time.Second))
	}

	spikes := a.RTTSpikeCount()
	if spikes != 3 {
		t.Errorf("RTTSpikeCount = %d, want 3", spikes)
	}
}

func TestRTTSpikeCountNone(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	for i := 0; i < 10; i++ {
		a.RecordRTTAt(10*time.Millisecond, uint32(i), base.Add(time.Duration(i)*time.Second))
	}

	if a.RTTSpikeCount() != 0 {
		t.Errorf("RTTSpikeCount = %d, want 0", a.RTTSpikeCount())
	}
}

// ---------------------------------------------------------------------------
// Window shrink detection
// ---------------------------------------------------------------------------

func TestRecordWindowShrink(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	a.RecordWindowShrinkAt(65535, 32768, time.Now()) // 50% shrink
	a.RecordWindowShrinkAt(32768, 16384, time.Now()) // 50% shrink

	events := a.WindowShrinkEvents()
	if len(events) != 2 {
		t.Fatalf("WindowShrinkEvents = %d, want 2", len(events))
	}
	if events[0].OldWindow != 65535 {
		t.Errorf("first OldWindow = %d, want 65535", events[0].OldWindow)
	}
	if events[0].Ratio < 0.49 || events[0].Ratio > 0.51 {
		t.Errorf("first Ratio = %f, want ~0.5", events[0].Ratio)
	}
}

func TestRecordWindowShrinkNotAShrink(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	// Increase: should be ignored
	a.RecordWindowShrinkAt(32768, 65535, time.Now())
	// Same: should be ignored
	a.RecordWindowShrinkAt(32768, 32768, time.Now())
	// Zero old: should be ignored
	a.RecordWindowShrinkAt(0, 100, time.Now())

	if a.WindowShrinkCount() != 0 {
		t.Errorf("WindowShrinkCount = %d, want 0 (increases/same ignored)", a.WindowShrinkCount())
	}
}

func TestUpdateWindowAutoDetect(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.WindowShrinkRatio = 0.5
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Set initial window
	a.UpdateWindow(65535, base)
	// Small reduction (not enough to trigger): 65535 → 50000 (ratio=0.76)
	a.UpdateWindow(50000, base.Add(time.Second))
	// Large reduction: 50000 → 10000 (ratio=0.2)
	a.UpdateWindow(10000, base.Add(2*time.Second))

	if a.WindowShrinkCount() != 1 {
		t.Errorf("WindowShrinkCount = %d, want 1 (only large reduction)", a.WindowShrinkCount())
	}
	events := a.WindowShrinkEvents()
	if events[0].OldWindow != 50000 || events[0].NewWindow != 10000 {
		t.Errorf("shrink event: %d→%d, want 50000→10000", events[0].OldWindow, events[0].NewWindow)
	}
}

func TestUpdateWindowGradual(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.WindowShrinkRatio = 0.5
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Gradual reduction: each step is ~90% of previous → no single step triggers
	a.UpdateWindow(100000, base)
	a.UpdateWindow(90000, base.Add(time.Second))
	a.UpdateWindow(81000, base.Add(2*time.Second))
	a.UpdateWindow(72900, base.Add(3*time.Second))

	if a.WindowShrinkCount() != 0 {
		t.Errorf("WindowShrinkCount = %d, want 0 for gradual reduction", a.WindowShrinkCount())
	}
}

// ---------------------------------------------------------------------------
// Burst detection
// ---------------------------------------------------------------------------

func TestDetectBurstsBasic(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.BurstThreshold = 3
	cfg.BurstWindow = 5 * time.Second
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// 5 retransmissions within 2 seconds → burst
	for i := 0; i < 5; i++ {
		a.RecordRetransmission(base.Add(time.Duration(i)*500*time.Millisecond), uint32(i+1), 1400)
	}

	bursts := a.DetectBursts(0)
	if len(bursts) != 1 {
		t.Fatalf("expected 1 burst, got %d", len(bursts))
	}
	if bursts[0].Count != 5 {
		t.Errorf("burst count = %d, want 5", bursts[0].Count)
	}
	if bursts[0].Duration != 2*time.Second {
		t.Errorf("burst duration = %v, want 2s", bursts[0].Duration)
	}
}

func TestDetectBurstsMultiple(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.BurstThreshold = 3
	cfg.BurstWindow = 2 * time.Second
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Burst 1: 3 retransmissions in 1s
	for i := 0; i < 3; i++ {
		a.RecordRetransmission(base.Add(time.Duration(i)*500*time.Millisecond), uint32(i+1), 100)
	}
	// Gap of 10 seconds
	// Burst 2: 4 retransmissions in 1.5s
	for i := 0; i < 4; i++ {
		a.RecordRetransmission(base.Add(10*time.Second+time.Duration(i)*500*time.Millisecond), uint32(10+i), 100)
	}

	bursts := a.DetectBursts(0)
	if len(bursts) != 2 {
		t.Fatalf("expected 2 bursts, got %d", len(bursts))
	}
	if bursts[0].Count != 3 {
		t.Errorf("burst 1 count = %d, want 3", bursts[0].Count)
	}
	if bursts[1].Count != 4 {
		t.Errorf("burst 2 count = %d, want 4", bursts[1].Count)
	}
}

func TestDetectBurstsTooFew(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.BurstThreshold = 5
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Only 3 retransmissions (below threshold of 5)
	for i := 0; i < 3; i++ {
		a.RecordRetransmission(base.Add(time.Duration(i)*time.Second), uint32(i+1), 100)
	}

	bursts := a.DetectBursts(0)
	if len(bursts) != 0 {
		t.Errorf("expected 0 bursts (below threshold), got %d", len(bursts))
	}
}

func TestDetectBurstsCustomMinCount(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	for i := 0; i < 4; i++ {
		a.RecordRetransmission(base.Add(time.Duration(i)*time.Second), uint32(i+1), 100)
	}

	// minCount=2 → should find bursts
	bursts := a.DetectBursts(2)
	if len(bursts) == 0 {
		t.Error("expected at least 1 burst with minCount=2")
	}

	// minCount=10 → too few
	bursts = a.DetectBursts(10)
	if len(bursts) != 0 {
		t.Errorf("expected 0 bursts with minCount=10, got %d", len(bursts))
	}
}

func TestDetectBurstsWithRTT(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.BurstThreshold = 3
	cfg.BurstWindow = 5 * time.Second
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Retransmissions at T+0, T+0.5s, T+1s
	for i := 0; i < 3; i++ {
		a.RecordRetransmission(base.Add(time.Duration(i)*500*time.Millisecond), uint32(i+1), 100)
	}
	// RTT samples during the burst
	a.RecordRTTAt(50*time.Millisecond, 1, base.Add(100*time.Millisecond))
	a.RecordRTTAt(150*time.Millisecond, 2, base.Add(600*time.Millisecond))

	bursts := a.DetectBursts(0)
	if len(bursts) != 1 {
		t.Fatalf("expected 1 burst, got %d", len(bursts))
	}
	if bursts[0].AvgRTTInBurst <= 0 {
		t.Error("AvgRTTInBurst should be > 0")
	}
	if bursts[0].MaxRTTInBurst != 150*time.Millisecond {
		t.Errorf("MaxRTTInBurst = %v, want 150ms", bursts[0].MaxRTTInBurst)
	}
}

// ---------------------------------------------------------------------------
// Correlation with RTCM interruptions
// ---------------------------------------------------------------------------

func TestCorrelateWithRTCMCongestion(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.BurstThreshold = 3
	cfg.CorrelationMargin = 1 * time.Second
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// RTCM interruption from T+5s to T+8s
	interruptions := []RTCMInterruption{
		{
			StartTime: base.Add(5 * time.Second),
			EndTime:   base.Add(8 * time.Second),
			Duration:  3 * time.Second,
		},
	}

	// 5 retransmissions during the interruption
	for i := 0; i < 5; i++ {
		a.RecordRetransmission(
			base.Add(5*time.Second+time.Duration(i)*500*time.Millisecond),
			uint32(i+1), 1400,
		)
	}
	// RTT samples during interruption
	a.RecordRTTAt(200*time.Millisecond, 1, base.Add(5500*time.Millisecond))
	a.RecordRTTAt(300*time.Millisecond, 2, base.Add(6500*time.Millisecond))

	correlations := a.CorrelateWithRTCM(interruptions)
	if len(correlations) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(correlations))
	}
	c := correlations[0]
	if c.ProbableCause != "congestion" {
		t.Errorf("ProbableCause = %q, want congestion", c.ProbableCause)
	}
	if c.RetransInWindow < 5 {
		t.Errorf("RetransInWindow = %d, want >= 5", c.RetransInWindow)
	}
	if c.AvgRTTDuring <= 0 {
		t.Error("AvgRTTDuring should be > 0")
	}
	if c.MaxRTTDuring != 300*time.Millisecond {
		t.Errorf("MaxRTTDuring = %v, want 300ms", c.MaxRTTDuring)
	}
}

func TestCorrelateWithRTCMPartialCongestion(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.BurstThreshold = 5 // high threshold
	cfg.CorrelationMargin = 2 * time.Second
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	interruptions := []RTCMInterruption{
		{
			StartTime: base.Add(5 * time.Second),
			EndTime:   base.Add(8 * time.Second),
			Duration:  3 * time.Second,
		},
	}

	// 2 retransmissions (below burst threshold) during the interruption
	a.RecordRetransmission(base.Add(6*time.Second), 1, 1400)
	a.RecordRetransmission(base.Add(7*time.Second), 2, 1400)

	correlations := a.CorrelateWithRTCM(interruptions)
	if len(correlations) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(correlations))
	}
	if correlations[0].ProbableCause != "partial_congestion" {
		t.Errorf("ProbableCause = %q, want partial_congestion", correlations[0].ProbableCause)
	}
}

func TestCorrelateWithRTCMNoCongestion(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	interruptions := []RTCMInterruption{
		{
			StartTime: base.Add(5 * time.Second),
			EndTime:   base.Add(8 * time.Second),
			Duration:  3 * time.Second,
		},
	}

	// No retransmissions at all → "other" cause
	correlations := a.CorrelateWithRTCM(interruptions)
	if len(correlations) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(correlations))
	}
	if correlations[0].ProbableCause != "other" {
		t.Errorf("ProbableCause = %q, want other", correlations[0].ProbableCause)
	}
	if correlations[0].RetransInWindow != 0 {
		t.Errorf("RetransInWindow = %d, want 0", correlations[0].RetransInWindow)
	}
}

func TestCorrelateWithRTCMBurstOverlap(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.BurstThreshold = 3
	cfg.BurstWindow = 5 * time.Second
	cfg.CorrelationMargin = 0
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Interruption from T+5s to T+10s
	interruptions := []RTCMInterruption{
		{
			StartTime: base.Add(5 * time.Second),
			EndTime:   base.Add(10 * time.Second),
			Duration:  5 * time.Second,
		},
	}

	// 4 retransmissions during the interruption (forms a burst)
	for i := 0; i < 4; i++ {
		a.RecordRetransmission(
			base.Add(5*time.Second+time.Duration(i)*time.Second),
			uint32(i+1), 100,
		)
	}

	correlations := a.CorrelateWithRTCM(interruptions)
	if len(correlations) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(correlations))
	}
	if !correlations[0].BurstOverlap {
		t.Error("BurstOverlap should be true")
	}
}

func TestCorrelateWithMultipleInterruptions(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	interruptions := []RTCMInterruption{
		{StartTime: base.Add(5 * time.Second), EndTime: base.Add(8 * time.Second), Duration: 3 * time.Second},
		{StartTime: base.Add(30 * time.Second), EndTime: base.Add(35 * time.Second), Duration: 5 * time.Second},
	}

	// Retransmissions only during first interruption
	for i := 0; i < 2; i++ {
		a.RecordRetransmission(base.Add(6*time.Second+time.Duration(i)*time.Second), uint32(i+1), 100)
	}

	correlations := a.CorrelateWithRTCM(interruptions)
	if len(correlations) != 2 {
		t.Fatalf("expected 2 correlations, got %d", len(correlations))
	}
	if correlations[0].RetransInWindow < 2 {
		t.Errorf("first interruption RetransInWindow = %d, want >= 2", correlations[0].RetransInWindow)
	}
	if correlations[1].RetransInWindow != 0 {
		t.Errorf("second interruption RetransInWindow = %d, want 0", correlations[1].RetransInWindow)
	}
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

func TestSummaryComprehensive(t *testing.T) {
	cfg := DefaultTCPHealthConfig()
	cfg.BurstThreshold = 2
	cfg.BurstWindow = 5 * time.Second
	cfg.RTTSpikeThreshold = 50 * time.Millisecond
	a := NewTCPHealthAnalyzer(cfg)

	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// 20 original packets
	for i := 0; i < 20; i++ {
		a.RecordPacket(uint32(i+1), base.Add(time.Duration(i)*100*time.Millisecond), false)
	}

	// 5 retransmissions within 2s (forms a burst)
	for i := 0; i < 5; i++ {
		a.RecordRetransmission(base.Add(time.Duration(i)*400*time.Millisecond), uint32(i+1), 1400)
	}

	// RTT samples: some normal, some spikes
	rtts := []time.Duration{
		10 * time.Millisecond, 20 * time.Millisecond, 60 * time.Millisecond,
		100 * time.Millisecond, 30 * time.Millisecond,
	}
	for i, rtt := range rtts {
		a.RecordRTTAt(rtt, uint32(i+1), base.Add(time.Duration(i)*500*time.Millisecond))
	}

	// Window shrink
	a.RecordWindowShrinkAt(65535, 16384, base.Add(time.Second))

	interruptions := []RTCMInterruption{
		{StartTime: base, EndTime: base.Add(2 * time.Second), Duration: 2 * time.Second},
	}

	summary := a.Summary(interruptions)

	if summary.TotalPackets != 25 {
		t.Errorf("TotalPackets = %d, want 25", summary.TotalPackets)
	}
	if summary.TotalRetransmissions != 5 {
		t.Errorf("TotalRetransmissions = %d, want 5", summary.TotalRetransmissions)
	}
	if summary.RetransmissionRate < 0.19 || summary.RetransmissionRate > 0.21 {
		t.Errorf("RetransmissionRate = %.4f, want ~0.20", summary.RetransmissionRate)
	}
	if summary.RTTSpikes != 2 {
		t.Errorf("RTTSpikes = %d, want 2 (60ms, 100ms)", summary.RTTSpikes)
	}
	if summary.WindowShrinks != 1 {
		t.Errorf("WindowShrinks = %d, want 1", summary.WindowShrinks)
	}
	if len(summary.Bursts) == 0 {
		t.Error("expected at least 1 burst in summary")
	}
	if len(summary.Correlations) != 1 {
		t.Errorf("Correlations = %d, want 1", len(summary.Correlations))
	}
}

func TestSummaryNoData(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	summary := a.Summary(nil)

	if summary.TotalPackets != 0 {
		t.Errorf("TotalPackets = %d, want 0", summary.TotalPackets)
	}
	if summary.RetransmissionRate != 0 {
		t.Errorf("RetransmissionRate = %f, want 0", summary.RetransmissionRate)
	}
	if len(summary.Bursts) != 0 {
		t.Errorf("Bursts = %d, want 0", len(summary.Bursts))
	}
}

func TestSummaryString(t *testing.T) {
	summary := TCPHealthSummary{
		TotalPackets:         1000,
		TotalRetransmissions: 50,
		RetransmissionRate:   0.05,
		RTTAvg:               25 * time.Millisecond,
		RTTP95:               80 * time.Millisecond,
		RTTMax:               200 * time.Millisecond,
		RTTJitter:            15 * time.Millisecond,
		RTTSpikes:            3,
		WindowShrinks:        2,
	}
	str := summary.String()
	if str == "" {
		t.Error("String() should not be empty")
	}
	// Should contain key info
	if len(str) < 20 {
		t.Error("String() seems too short")
	}
}

// ---------------------------------------------------------------------------
// ComputeFinalStats integration
// ---------------------------------------------------------------------------

func TestComputeFinalStats(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// 100 packets, 10 retransmissions
	for i := 0; i < 90; i++ {
		a.RecordPacket(uint32(i+1), base.Add(time.Duration(i)*time.Millisecond), false)
	}
	for i := 0; i < 10; i++ {
		a.RecordPacket(uint32(i+1), base.Add(time.Duration(90+i)*time.Millisecond), true)
	}

	nq := &NetworkQualityStats{}
	a.ComputeFinalStats(nq)

	if nq.TotalRetransmissions != 10 {
		t.Errorf("TotalRetransmissions = %d, want 10", nq.TotalRetransmissions)
	}
	if nq.RetransmissionRate != 0.1 {
		t.Errorf("RetransmissionRate = %f, want 0.1", nq.RetransmissionRate)
	}
}

// ---------------------------------------------------------------------------
// sqrtF helper
// ---------------------------------------------------------------------------

func TestSqrtF(t *testing.T) {
	tests := []struct {
		input, want float64
	}{
		{0, 0},
		{1, 1},
		{4, 2},
		{9, 3},
		{100, 10},
		{2, 1.414},
	}
	for _, tc := range tests {
		got := sqrtF(tc.input)
		diff := got - tc.want
		if diff < 0 {
			diff = -diff
		}
		if diff > 0.01 {
			t.Errorf("sqrtF(%f) = %f, want ~%f", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestDetectBurstsNoRetransmissions(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	bursts := a.DetectBursts(0)
	if len(bursts) != 0 {
		t.Errorf("expected 0 bursts for empty analyzer, got %d", len(bursts))
	}
}

func TestCorrelateWithRTCMEmptyInterruptions(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	correlations := a.CorrelateWithRTCM(nil)
	if len(correlations) != 0 {
		t.Errorf("expected 0 correlations for nil interruptions, got %d", len(correlations))
	}
}

func TestFindRTTNear(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	a.RecordRTTAt(50*time.Millisecond, 1, base.Add(1*time.Second))
	a.RecordRTTAt(100*time.Millisecond, 2, base.Add(3*time.Second))
	a.RecordRTTAt(200*time.Millisecond, 3, base.Add(5*time.Second))

	// Find RTT near T+1s → should be 50ms
	rtt := a.findRTTNear(base.Add(1*time.Second), 500*time.Millisecond)
	if rtt != 50*time.Millisecond {
		t.Errorf("RTT near T+1s = %v, want 50ms", rtt)
	}

	// Find RTT near T+3s → should be 100ms
	rtt = a.findRTTNear(base.Add(3*time.Second), 500*time.Millisecond)
	if rtt != 100*time.Millisecond {
		t.Errorf("RTT near T+3s = %v, want 100ms", rtt)
	}

	// Find RTT far from any sample → 0
	rtt = a.findRTTNear(base.Add(10*time.Second), 500*time.Millisecond)
	if rtt != 0 {
		t.Errorf("RTT far from samples = %v, want 0", rtt)
	}
}

func TestRecordWindowShrinkAtInvalid(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	// oldWindow=0 → invalid
	a.RecordWindowShrinkAt(0, 100, time.Now())
	if a.WindowShrinkCount() != 0 {
		t.Errorf("count = %d, want 0 for oldWindow=0", a.WindowShrinkCount())
	}
}

func TestSessionIntegrationWithTCPAnalyzer(t *testing.T) {
	start := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	s := NewNTRIPSession("s1", "M", "u", "10.0.0.1", 100, start)

	// Attach TCP analyzer
	analyzer := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	s.TCPAnalyzer = analyzer

	// Simulate some traffic
	base := start
	for i := 0; i < 50; i++ {
		analyzer.RecordPacket(uint32(i+1), base.Add(time.Duration(i)*10*time.Millisecond), false)
	}
	// 3 retransmissions
	for i := 0; i < 3; i++ {
		analyzer.RecordRetransmission(
			base.Add(time.Duration(50+i)*10*time.Millisecond),
			uint32(i+1), 1400,
		)
	}
	// RTT samples
	for i := 0; i < 10; i++ {
		analyzer.RecordRTTAt(
			time.Duration(10+i*5)*time.Millisecond,
			uint32(i+1),
			base.Add(time.Duration(i)*50*time.Millisecond),
		)
	}

	// Verify integration
	if s.TCPAnalyzer == nil {
		t.Fatal("TCPAnalyzer should not be nil")
	}
	rate := s.TCPAnalyzer.ComputeRetransmissionRate()
	if rate < 0.05 || rate > 0.07 {
		t.Errorf("RetransmissionRate = %.4f, want ~0.057 (3/53)", rate)
	}
	if s.TCPAnalyzer.RTTSampleCount() != 10 {
		t.Errorf("RTTSampleCount = %d, want 10", s.TCPAnalyzer.RTTSampleCount())
	}
}

func TestRetransmissionsInWindow(t *testing.T) {
	a := NewTCPHealthAnalyzer(DefaultTCPHealthConfig())
	base := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)

	// Three old retransmissions, then two recent ones near "close".
	a.RecordRetransmission(base, 100, 1400)
	a.RecordRetransmission(base.Add(1*time.Second), 200, 1400)
	a.RecordRetransmission(base.Add(2*time.Second), 300, 1400)
	a.RecordRetransmission(base.Add(58*time.Second), 400, 1400)
	a.RecordRetransmission(base.Add(59*time.Second), 500, 1400)

	closeTime := base.Add(60 * time.Second)

	// Last 5s window: only the two near the end.
	if got := a.RetransmissionsInWindow(closeTime, 5*time.Second); got != 2 {
		t.Errorf("RetransmissionsInWindow(5s) = %d, want 2", got)
	}
	// Last 3s window includes 58s and 59s events (>= 57s).
	if got := a.RetransmissionsInWindow(closeTime, 3*time.Second); got != 2 {
		t.Errorf("RetransmissionsInWindow(3s) = %d, want 2", got)
	}
	// Window of 0 counts all up to closeTime.
	if got := a.RetransmissionsInWindow(closeTime, 0); got != 5 {
		t.Errorf("RetransmissionsInWindow(0) = %d, want 5 (all)", got)
	}
	// A very wide window also counts all.
	if got := a.RetransmissionsInWindow(closeTime, time.Hour); got != 5 {
		t.Errorf("RetransmissionsInWindow(1h) = %d, want 5", got)
	}
}
