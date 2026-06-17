package session

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Diagnostic report rendering
// ---------------------------------------------------------------------------
//
// This file turns a finalized NTRIPSession into a human-readable text report,
// and provides DiagnosticReporter, a SessionListener that prints the report
// when a session closes. It deliberately avoids the Bubble Tea TUI pipeline:
// session diagnostics are long-lived, session-scoped artifacts that map poorly
// onto the per-record table UI, so plain text via a sink (logger/stdout) is the
// least intrusive and most useful form.
//
// Concurrency note: FormatSessionReport calls methods that lock s internally
// (Score, ComputeGGASummary, Duration) and also reads identity fields directly.
// It is intended to be called AFTER the session is closed (e.g. from
// OnSessionClosed), at which point the session no longer receives records, so
// the direct field reads are race-free.

// ReportConfig controls report rendering thresholds (mirrors the tracker's
// warn intervals so issue detection in Score() matches what the report shows).
type ReportConfig struct {
	GGAWarnInterval  time.Duration
	RTCMWarnInterval time.Duration
	ShowPassword     bool
}

// DefaultReportConfig returns sensible defaults.
func DefaultReportConfig() ReportConfig {
	return ReportConfig{
		GGAWarnInterval:  5 * time.Second,
		RTCMWarnInterval: 2 * time.Second,
		ShowPassword:     false,
	}
}

// FormatSessionReport renders a finalized session as a multi-line text report
// covering identity, login, GGA, RTCM, network and the diagnostic score.
func FormatSessionReport(s *NTRIPSession, cfg ReportConfig) string {
	score := s.Score(cfg.GGAWarnInterval, cfg.RTCMWarnInterval)
	gga := s.ComputeGGASummary()
	duration := s.Duration()

	// Read identity fields (safe post-close; see file-level concurrency note).
	s.mu.RLock()
	sessionID := s.SessionID
	mount := s.MountPoint
	username := s.Username
	password := s.Password
	version := s.NTRIPVersion
	clientIP := effectiveIP(s.RealClientIP, s.ClientIP)
	socketIP := s.ClientIP
	realClientIPSet := s.RealClientIP != ""
	clientPort := s.ClientPort
	serverPod := s.ServerPod
	serverIP := s.ServerIP
	authMethod := s.AuthMethod
	authSuccess := s.AuthSuccess
	authChecked := s.AuthChecked
	httpStatus := s.HTTPStatusCode
	loginLatency := s.LoginLatency
	disconnectReason := s.DisconnectReason
	disconnectDetail := s.DisconnectDetail
	rtcm := s.RTCMStats
	nq := s.NetworkQuality
	clientRole := s.ClientRole
	serverRole := s.ServerRole
	s.mu.RUnlock()

	var b strings.Builder

	writeLine := func(format string, args ...any) {
		b.WriteString(fmt.Sprintf(format, args...))
		b.WriteByte('\n')
	}

	writeLine("========== NTRIP Session Diagnostic Report ==========")
	writeLine("Session:    %s", sessionID)
	writeLine("Client:     %s:%d", clientIP, clientPort)
	if realClientIPSet && socketIP != clientIP {
		writeLine("  (real IP via LB header; socket peer was %s)", socketIP)
	}
	if clientRole != "" {
		writeLine("Client Role: %s", clientRole)
	}
	if serverRole != "" {
		writeLine("Server Role: %s", serverRole)
	}
	if serverPod != "" {
		writeLine("Server Pod: %s", serverPod)
	} else if serverIP != "" {
		writeLine("Server IP:  %s", serverIP)
	}
	if mount != "" {
		writeLine("Mountpoint: %s", mount)
	}
	if username != "" {
		writeLine("Username:   %s", username)
	}
	if cfg.ShowPassword && password != "" {
		writeLine("Password:   %s", password)
	}
	if version != "" {
		writeLine("Version:    %s", version)
	}
	writeLine("Duration:   %s", duration.Round(time.Millisecond))

	// --- Login ---
	writeLine("--- Login (S1) ---")
	if authChecked && httpStatus > 0 {
		status := "success"
		if !authSuccess {
			status = "FAILED"
		}
		writeLine("  Auth:    %s (%s), HTTP %d", status, authMethod, httpStatus)
	} else if authChecked {
		writeLine("  Auth:    observed (%s), response not captured", authMethod)
	} else {
		writeLine("  Auth:    not observed")
	}
	if loginLatency > 0 {
		writeLine("  Latency: %s", loginLatency.Round(time.Millisecond))
	}

	// --- GGA ---
	writeLine("--- GGA Uploads (S2) ---")
	writeLine("  Events:     %d", gga.TotalEvents)
	if gga.TotalEvents > 0 {
		writeLine("  RTK-fixed:  %.1f%% (fix rate)", gga.FixRate*100)
		writeLine("  Satellites: avg %.1f (min %d, max %d)", gga.AvgSatellites, gga.MinSatellites, gga.MaxSatellites)
		if len(gga.StationIDs) > 0 {
			writeLine("  Stations:   %s", strings.Join(gga.StationIDs, ", "))
		}
	}

	// --- RTCM ---
	writeLine("--- RTCM Delivery (S3) ---")
	writeLine("  Frames:      %d (%d bytes)", rtcm.TotalFrames, rtcm.TotalBytes)
	if rtcm.TotalFrames > 0 {
		writeLine("  CRC errors:  %d (%.2f%%)", rtcm.CRCErrors, rtcm.CRCErrorRate*100)
		writeLine("  Interval:    avg %s, max %s, p95 %s",
			rtcm.AvgInterval.Round(time.Millisecond),
			rtcm.MaxInterval.Round(time.Millisecond),
			rtcm.P95Interval.Round(time.Millisecond))
		writeLine("  Throughput:  %.0f B/s", rtcm.ThroughputBps)
		if len(rtcm.Interruptions) > 0 {
			writeLine("  Interruptions: %d (threshold %s)", len(rtcm.Interruptions), cfg.RTCMWarnInterval)
		}
		if len(rtcm.MessageTypes) > 0 {
			writeLine("  Msg types:   %s", formatMessageTypes(rtcm.MessageTypes))
		}
	}

	// --- Network ---
	writeLine("--- Network Quality (S5) ---")
	writeLine("  Retransmissions: %d (%.2f%%)", nq.TotalRetransmissions, nq.RetransmissionRate*100)
	if nq.AvgRTT > 0 {
		writeLine("  RTT: avg %s, p95 %s, max %s, jitter %s",
			nq.AvgRTT.Round(time.Microsecond),
			nq.P95RTT.Round(time.Microsecond),
			nq.MaxRTT.Round(time.Microsecond),
			nq.RTTJitter.Round(time.Microsecond))
	}
	if len(nq.TCPResetEvents) > 0 {
		writeLine("  TCP resets: %d", len(nq.TCPResetEvents))
	}

	// --- Disconnect ---
	writeLine("--- Disconnect (S4) ---")
	writeLine("  Reason: %s", disconnectReason)
	if disconnectDetail != "" {
		writeLine("  Detail: %s", disconnectDetail)
	}

	// --- Score ---
	writeLine("--- Diagnostic Score ---")
	writeLine("  Total: %d/100  (login %d, gga %d, rtcm %d, network %d, stability %d)",
		score.Total, score.LoginScore, score.GGAScore, score.RTCMScore,
		score.NetworkScore, score.StabilityScore)
	if len(score.Issues) > 0 {
		writeLine("  Issues:")
		for _, issue := range score.Issues {
			writeLine("    [%s/%s] %s", issue.Severity, issue.Category, issue.Description)
		}
	}
	b.WriteString("=====================================================")

	return b.String()
}

// formatMessageTypes renders the RTCM message-type histogram as "1074:120 1005:6"
// ordered by message type for stable output.
func formatMessageTypes(m map[int]int) string {
	types := make([]int, 0, len(m))
	for t := range m {
		types = append(types, t)
	}
	sort.Ints(types)

	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%d:%d", t, m[t]))
	}
	return strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------
// DiagnosticReporter: a SessionListener that emits a report on session close
// ---------------------------------------------------------------------------

// ReportSink receives rendered report text. It decouples the reporter from any
// particular output (logger, stdout, file, test buffer).
type ReportSink func(report string)

// DiagnosticReporter prints a diagnostic report whenever a session closes.
// Register it on a SessionTracker via tracker.AddListener(reporter).
type DiagnosticReporter struct {
	cfg  ReportConfig
	sink ReportSink
}

// NewDiagnosticReporter creates a reporter that renders with cfg and writes to
// sink. If sink is nil, reports are silently dropped.
func NewDiagnosticReporter(cfg ReportConfig, sink ReportSink) *DiagnosticReporter {
	return &DiagnosticReporter{cfg: cfg, sink: sink}
}

// OnSessionCreated is a no-op (reports are emitted on close). Implements SessionListener.
func (r *DiagnosticReporter) OnSessionCreated(s *NTRIPSession) {}

// OnSessionClosed renders and emits the diagnostic report. Implements SessionListener.
func (r *DiagnosticReporter) OnSessionClosed(s *NTRIPSession) {
	if r.sink == nil {
		return
	}
	r.sink(FormatSessionReport(s, r.cfg))
}

// ---------------------------------------------------------------------------
// Multi-Pod load summary rendering (S6)
// ---------------------------------------------------------------------------

// FormatPodLoadSummary renders a PodLoadAnalyzer snapshot as a text table:
// per-Pod connections / frame rate / clients, plus load-imbalance coefficients
// and any detected Pod switches. Returns a short notice when no Pods were seen.
func FormatPodLoadSummary(p *PodLoadAnalyzer) string {
	if p == nil {
		return ""
	}
	snapshot := p.Snapshot()
	if len(snapshot) == 0 {
		return "========== Multi-Pod Load Summary ==========\n  (no NTRIP/RTCM sessions observed)\n============================================"
	}

	var b strings.Builder
	writeLine := func(format string, args ...any) {
		b.WriteString(fmt.Sprintf(format, args...))
		b.WriteByte('\n')
	}

	writeLine("========== Multi-Pod Load Summary (S6) ==========")
	writeLine("%-24s %8s %8s %8s %10s %8s", "POD/SERVER", "ACTIVE", "TOTAL", "CLIENTS", "FRAMES", "FPS")
	for _, s := range snapshot {
		writeLine("%-24s %8d %8d %8d %10d %8.1f",
			truncate(s.PodKey, 24),
			s.ActiveSessions,
			s.TotalSessions,
			s.UniqueClients,
			s.TotalRTCMFrames,
			s.FrameRate)
	}
	writeLine("-------------------------------------------------")
	writeLine("Pods: %d", len(snapshot))
	writeLine("Load imbalance (CV, active conns): %.3f", p.LoadImbalance())
	writeLine("Frame-rate imbalance (CV):         %.3f", p.FrameRateImbalance())

	if switches := p.PodSwitches(); len(switches) > 0 {
		writeLine("Pod switches: %d", len(switches))
		for _, sw := range switches {
			writeLine("  %s: %s -> %s @ %s",
				sw.ClientIP, sw.OldPodKey, sw.NewPodKey,
				sw.Timestamp.Format(time.RFC3339))
		}
	}
	b.WriteString("=================================================")
	return b.String()
}

// truncate shortens s to at most n runes, appending no ellipsis (keeps columns
// aligned in fixed-width output).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
