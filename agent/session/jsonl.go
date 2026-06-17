package session

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// JSONL session-summary export (Phase 6)
// ---------------------------------------------------------------------------
//
// Where report.go renders a session as human-readable text, this file renders
// it as a single machine-readable JSON object ("JSON Lines": one object per
// line). This is the structured data feed intended for downstream tooling
// (Web Console, alerting, dashboards) and offline analysis.
//
// One closed session -> one SessionSummaryJSON -> one line in the .jsonl file.

// SessionSummaryJSON is a flat, self-contained JSON view of a finalized
// session. Field names are stable and snake_case for easy consumption.
type SessionSummaryJSON struct {
	Type       string `json:"type"` // always "session_summary"
	SessionID  string `json:"session_id"`
	Mount      string `json:"mount,omitempty"`
	Username   string `json:"username,omitempty"`
	Version    string `json:"ntrip_version,omitempty"`
	ClientRole string `json:"client_role,omitempty"`
	ServerRole string `json:"server_role,omitempty"`

	ClientIP   string `json:"client_ip"`
	ClientPort uint16 `json:"client_port"`
	// SocketIP is the raw socket peer IP (the LB's IP behind a load balancer).
	// Preserved for traceability; client_ip is the effective (real) client IP.
	SocketIP  string `json:"socket_ip"`
	ServerPod string `json:"server_pod,omitempty"`
	ServerIP  string `json:"server_ip,omitempty"`

	StartTime  time.Time  `json:"start_time"`
	CloseTime  *time.Time `json:"close_time,omitempty"`
	DurationMs int64      `json:"duration_ms"`

	// Login (S1)
	AuthMethod     string `json:"auth_method,omitempty"`
	AuthChecked    bool   `json:"auth_checked"`
	AuthSuccess    bool   `json:"auth_success"`
	HTTPStatusCode int    `json:"http_status_code,omitempty"`
	LoginLatencyMs int64  `json:"login_latency_ms,omitempty"`

	// GGA (S2)
	GGAEvents    int     `json:"gga_events"`
	GGAFixRate   float64 `json:"gga_fix_rate"`
	GGAAvgSats   float64 `json:"gga_avg_satellites"`
	GGAFrequency float64 `json:"gga_frequency_hz"`

	// RTCM (S3)
	RTCMFrames        int            `json:"rtcm_frames"`
	RTCMBytes         int64          `json:"rtcm_bytes"`
	RTCMCRCErrors     int            `json:"rtcm_crc_errors"`
	RTCMCRCErrorRate  float64        `json:"rtcm_crc_error_rate"`
	RTCMAvgIntervalMs int64          `json:"rtcm_avg_interval_ms"`
	RTCMP95IntervalMs int64          `json:"rtcm_p95_interval_ms"`
	RTCMThroughputBps float64        `json:"rtcm_throughput_bps"`
	RTCMInterruptions int            `json:"rtcm_interruptions"`
	RTCMMessageTypes  map[string]int `json:"rtcm_message_types,omitempty"`

	// Network (S5)
	Retransmissions    int     `json:"retransmissions"`
	RetransmissionRate float64 `json:"retransmission_rate"`
	AvgRTTMs           float64 `json:"avg_rtt_ms"`
	P95RTTMs           float64 `json:"p95_rtt_ms"`
	RTTJitterMs        float64 `json:"rtt_jitter_ms"`
	TCPResets          int     `json:"tcp_resets"`

	// Disconnect (S4)
	DisconnectReason string `json:"disconnect_reason"`
	DisconnectDetail string `json:"disconnect_detail,omitempty"`

	// Diagnostic score
	Score          int `json:"score"`
	LoginScore     int `json:"login_score"`
	GGAScore       int `json:"gga_score"`
	RTCMScore      int `json:"rtcm_score"`
	NetworkScore   int `json:"network_score"`
	StabilityScore int `json:"stability_score"`

	Issues []SessionIssueJSON `json:"issues,omitempty"`
}

// SessionIssueJSON is the JSON form of a DiagnosticIssue.
type SessionIssueJSON struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// SessionSummaryFromSession builds a JSON summary from a finalized session.
// Like FormatSessionReport, it is intended to be called after the session is
// closed; ShowPassword is intentionally NOT honored here — the structured feed
// never includes credentials.
func SessionSummaryFromSession(s *NTRIPSession, cfg ReportConfig) SessionSummaryJSON {
	score := s.Score(cfg.GGAWarnInterval, cfg.RTCMWarnInterval)
	gga := s.ComputeGGASummary()
	duration := s.Duration()

	s.mu.RLock()
	defer s.mu.RUnlock()

	summary := SessionSummaryJSON{
		Type:       "session_summary",
		SessionID:  s.SessionID,
		Mount:      s.MountPoint,
		Username:   s.Username,
		Version:    s.NTRIPVersion,
		ClientRole: s.ClientRole,
		ServerRole: s.ServerRole,
		ClientIP:   effectiveIP(s.RealClientIP, s.ClientIP),
		SocketIP:   s.ClientIP,
		ClientPort: s.ClientPort,
		ServerPod:  s.ServerPod,
		ServerIP:   s.ServerIP,
		StartTime:  s.ConnStartTime,
		CloseTime:  s.ConnCloseTime,
		DurationMs: duration.Milliseconds(),

		AuthMethod:     s.AuthMethod,
		AuthChecked:    s.AuthChecked,
		AuthSuccess:    s.AuthSuccess,
		HTTPStatusCode: s.HTTPStatusCode,
		LoginLatencyMs: s.LoginLatency.Milliseconds(),

		GGAEvents:    gga.TotalEvents,
		GGAFixRate:   gga.FixRate,
		GGAAvgSats:   gga.AvgSatellites,
		GGAFrequency: s.GGAFrequency,

		RTCMFrames:        s.RTCMStats.TotalFrames,
		RTCMBytes:         s.RTCMStats.TotalBytes,
		RTCMCRCErrors:     s.RTCMStats.CRCErrors,
		RTCMCRCErrorRate:  s.RTCMStats.CRCErrorRate,
		RTCMAvgIntervalMs: s.RTCMStats.AvgInterval.Milliseconds(),
		RTCMP95IntervalMs: s.RTCMStats.P95Interval.Milliseconds(),
		RTCMThroughputBps: s.RTCMStats.ThroughputBps,
		RTCMInterruptions: len(s.RTCMStats.Interruptions),

		Retransmissions:    s.NetworkQuality.TotalRetransmissions,
		RetransmissionRate: s.NetworkQuality.RetransmissionRate,
		AvgRTTMs:           durationToMs(s.NetworkQuality.AvgRTT),
		P95RTTMs:           durationToMs(s.NetworkQuality.P95RTT),
		RTTJitterMs:        durationToMs(s.NetworkQuality.RTTJitter),
		TCPResets:          len(s.NetworkQuality.TCPResetEvents),

		DisconnectReason: s.DisconnectReason.String(),
		DisconnectDetail: s.DisconnectDetail,

		Score:          score.Total,
		LoginScore:     score.LoginScore,
		GGAScore:       score.GGAScore,
		RTCMScore:      score.RTCMScore,
		NetworkScore:   score.NetworkScore,
		StabilityScore: score.StabilityScore,
	}

	if len(s.RTCMStats.MessageTypes) > 0 {
		summary.RTCMMessageTypes = make(map[string]int, len(s.RTCMStats.MessageTypes))
		for mt, count := range s.RTCMStats.MessageTypes {
			summary.RTCMMessageTypes[fmt.Sprintf("%d", mt)] = count
		}
	}

	for _, issue := range score.Issues {
		summary.Issues = append(summary.Issues, SessionIssueJSON{
			Category:    issue.Category,
			Severity:    issue.Severity,
			Description: issue.Description,
		})
	}

	return summary
}

// MarshalSessionSummaryLine renders a session as a single compact JSON line
// (no trailing newline). Returns an error only if marshaling fails.
func MarshalSessionSummaryLine(s *NTRIPSession, cfg ReportConfig) ([]byte, error) {
	return json.Marshal(SessionSummaryFromSession(s, cfg))
}

func durationToMs(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// ---------------------------------------------------------------------------
// JSONLExporter: thread-safe writer of session-summary JSON lines
// ---------------------------------------------------------------------------

// JSONLExporter writes one JSON object per line to an output stream. It is safe
// for concurrent use from multiple goroutines.
type JSONLExporter struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer // non-nil when the exporter owns the underlying file
	path   string
}

// NewJSONLExporter creates an exporter writing to the given file path.
// The file is created (or truncated) immediately.
func NewJSONLExporter(path string) (*JSONLExporter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create jsonl file %q: %w", path, err)
	}
	return &JSONLExporter{w: f, closer: f, path: path}, nil
}

// NewJSONLExporterWriter creates an exporter writing to an arbitrary io.Writer
// (e.g. a test buffer or stdout). Close will not close the underlying writer.
func NewJSONLExporterWriter(w io.Writer) *JSONLExporter {
	return &JSONLExporter{w: w}
}

// WriteSession marshals the session summary and appends it as one line.
func (e *JSONLExporter) WriteSession(s *NTRIPSession, cfg ReportConfig) error {
	line, err := MarshalSessionSummaryLine(s, cfg)
	if err != nil {
		return fmt.Errorf("marshal session summary: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.w.Write(line); err != nil {
		return err
	}
	_, err = e.w.Write([]byte("\n"))
	return err
}

// Close closes the underlying file if the exporter owns one.
func (e *JSONLExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closer != nil {
		return e.closer.Close()
	}
	return nil
}

// Path returns the output file path ("" for writer-backed exporters).
func (e *JSONLExporter) Path() string {
	return e.path
}

// ---------------------------------------------------------------------------
// JSONLReporter: a SessionListener that exports a JSON line on session close
// ---------------------------------------------------------------------------

// JSONLReporter writes a session-summary JSON line whenever a session closes.
// Register it on a SessionTracker via tracker.AddListener(reporter).
type JSONLReporter struct {
	exporter *JSONLExporter
	cfg      ReportConfig
}

// NewJSONLReporter creates a reporter backed by the given exporter.
func NewJSONLReporter(exporter *JSONLExporter, cfg ReportConfig) *JSONLReporter {
	return &JSONLReporter{exporter: exporter, cfg: cfg}
}

// OnSessionCreated is a no-op. Implements SessionListener.
func (r *JSONLReporter) OnSessionCreated(s *NTRIPSession) {}

// OnSessionClosed writes the session summary line. Implements SessionListener.
// Write errors are intentionally swallowed (best-effort export); callers that
// need error visibility should use the exporter directly.
func (r *JSONLReporter) OnSessionClosed(s *NTRIPSession) {
	if r.exporter == nil {
		return
	}
	_ = r.exporter.WriteSession(s, r.cfg)
}
