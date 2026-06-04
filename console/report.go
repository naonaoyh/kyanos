// Package console — report.go
//
// DiagnosticReporter generates session diagnostic reports in both HTML
// and structured JSON formats. The HTML report provides a comprehensive
// view suitable for operations engineers, covering all diagnostic
// dimensions: login, GGA, RTCM, network quality, and overall score.
package console

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

// DiagnosticReporter generates diagnostic reports from session records.
type DiagnosticReporter struct {
	tmpl *template.Template
}

// NewDiagnosticReporter creates a reporter with the embedded HTML template.
func NewDiagnosticReporter() *DiagnosticReporter {
	return &DiagnosticReporter{
		tmpl: template.Must(template.New("report").Parse(reportHTMLTemplate)),
	}
}

// ReportJSON is the structured JSON output of a diagnostic report.
type ReportJSON struct {
	SessionID    string            `json:"session_id"`
	Mountpoint   string            `json:"mountpoint"`
	Username     string            `json:"username"`
	NTRIPVersion string            `json:"ntrip_version"`
	ClientAddr   string            `json:"client_addr"`
	ServerPod    string            `json:"server_pod"`
	NodeName     string            `json:"node_name"`
	StartTime    string            `json:"start_time"`
	Duration     string            `json:"duration"`
	Score        int32             `json:"score"`
	Dimensions   []DimensionReport `json:"dimensions"`
	Issues       []SessionIssue    `json:"issues,omitempty"`
	Verdict      string            `json:"verdict"`
}

// DimensionReport is a single diagnostic dimension in the JSON report.
type DimensionReport struct {
	Name     string         `json:"name"`
	Score    int32          `json:"score"`
	MaxScore int32          `json:"max_score"`
	Status   string         `json:"status"` // "pass", "warn", "fail"
	Metrics  map[string]any `json:"metrics"`
	Findings []string       `json:"findings,omitempty"`
}

// FormatJSON generates a structured JSON report for the session.
func (r *DiagnosticReporter) FormatJSON(s *SessionRecord, store SessionStore) *ReportJSON {
	report := &ReportJSON{
		SessionID:    s.SessionID,
		Mountpoint:   s.Mountpoint,
		Username:     s.Username,
		NTRIPVersion: s.NTRIPVer,
		ClientAddr:   fmt.Sprintf("%s:%d", s.ClientIP, s.ClientPort),
		ServerPod:    s.ServerPod,
		NodeName:     s.NodeName,
		StartTime:    s.StartTime.Format(time.RFC3339),
		Duration:     formatDuration(s.DurationMs),
		Score:        s.Score,
	}
	
	// Copy original issues.
	if len(s.Issues) > 0 {
		report.Issues = make([]SessionIssue, len(s.Issues))
		copy(report.Issues, s.Issues)
	}

	// Login dimension.
	loginDim := DimensionReport{
		Name:     "Login / Authentication",
		Score:    s.LoginScore,
		MaxScore: 100,
		Metrics: map[string]any{
			"method":           s.AuthMethod,
			"success":          s.AuthSuccess,
			"http_status":      s.HTTPStatusCode,
			"login_latency_ms": s.LoginLatencyMs,
		},
	}
	loginDim.Status = dimensionStatus(s.LoginScore)
	if !s.AuthChecked {
		loginDim.Findings = append(loginDim.Findings, "Authentication was not observed")
	} else if !s.AuthSuccess {
		loginDim.Findings = append(loginDim.Findings, "Authentication failed")
	}
	if s.LoginLatencyMs > 3000 {
		loginDim.Findings = append(loginDim.Findings, fmt.Sprintf("High login latency: %dms", s.LoginLatencyMs))
	}
	report.Dimensions = append(report.Dimensions, loginDim)

	// GGA dimension.
	ggaDim := DimensionReport{
		Name:     "GGA Position Reports",
		Score:    s.GGAScore,
		MaxScore: 100,
		Metrics: map[string]any{
			"events":         s.GGAEvents,
			"fix_rate":       s.GGAFixRate,
			"avg_satellites": s.GGAAvgSats,
			"frequency_hz":   s.GGAFrequencyHz,
		},
	}
	ggaDim.Status = dimensionStatus(s.GGAScore)
	if s.GGAEvents == 0 {
		ggaDim.Findings = append(ggaDim.Findings, "No GGA events observed")
	} else {
		if s.GGAFixRate < 0.9 {
			ggaDim.Findings = append(ggaDim.Findings, fmt.Sprintf("Low fix rate: %.1f%%", s.GGAFixRate*100))
		}
		if s.GGAAvgSats < 6 {
			ggaDim.Findings = append(ggaDim.Findings, fmt.Sprintf("Low average satellite count: %.1f", s.GGAAvgSats))
		}
	}
	report.Dimensions = append(report.Dimensions, ggaDim)

	// RTCM dimension.
	rtcmDim := DimensionReport{
		Name:     "RTCM Message Delivery",
		Score:    s.RTCMScore,
		MaxScore: 100,
		Metrics: map[string]any{
			"frames":          s.RTCMFrames,
			"bytes":           s.RTCMBytes,
			"crc_errors":      s.RTCMCRCErrors,
			"crc_error_rate":  s.RTCMCRCErrorRate,
			"avg_interval_ms": s.RTCMAvgIntervalMs,
			"p95_interval_ms": s.RTCMP95IntervalMs,
			"throughput_bps":  s.RTCMThroughputBps,
			"interruptions":   s.RTCMInterruptions,
			"message_types":   s.RTCMMessageTypes,
		},
	}
	rtcmDim.Status = dimensionStatus(s.RTCMScore)
	if s.RTCMCRCErrors > 0 {
		rtcmDim.Findings = append(rtcmDim.Findings, fmt.Sprintf("%d CRC errors detected (%.2f%% rate)", s.RTCMCRCErrors, s.RTCMCRCErrorRate*100))
	}
	if s.RTCMInterruptions > 0 {
		rtcmDim.Findings = append(rtcmDim.Findings, fmt.Sprintf("%d RTCM delivery interruptions", s.RTCMInterruptions))
	}
	report.Dimensions = append(report.Dimensions, rtcmDim)

	// Network dimension.
	netDim := DimensionReport{
		Name:     "Network Quality",
		Score:    s.NetworkScore,
		MaxScore: 100,
		Metrics: map[string]any{
			"retransmissions":     s.Retransmissions,
			"retransmission_rate": s.RetransmitRate,
			"avg_rtt_ms":          s.AvgRTTMs,
			"p95_rtt_ms":          s.P95RTTMs,
			"rtt_jitter_ms":       s.RTTJitterMs,
			"tcp_resets":          s.TCPResets,
		},
	}
	netDim.Status = dimensionStatus(s.NetworkScore)
	if s.Retransmissions > 10 {
		netDim.Findings = append(netDim.Findings, fmt.Sprintf("High retransmission count: %d", s.Retransmissions))
	}
	if s.P95RTTMs > 100 {
		netDim.Findings = append(netDim.Findings, fmt.Sprintf("High P95 RTT: %.1fms", s.P95RTTMs))
	}
	if s.TCPResets > 0 {
		netDim.Findings = append(netDim.Findings, fmt.Sprintf("%d TCP resets observed", s.TCPResets))
	}
	report.Dimensions = append(report.Dimensions, netDim)

	// Global session correlation.
	stabilityScore := s.StabilityScore
	var stabilityFindings []string
	var correlationIssues []SessionIssue

	if store != nil && s.Username != "" && s.TaskID != "" {
		// List historical sessions for the same user and task
		sessions, _ := store.ListSessions(SessionFilter{
			Username: s.Username,
			TaskID:   s.TaskID,
		})

		// Find the most recent closed session that ended before this one started.
		var prev *SessionRecord
		for _, ps := range sessions {
			if ps.SessionID == s.SessionID || !ps.Closed {
				continue
			}
			if ps.CloseTime.Before(s.StartTime) {
				if prev == nil || ps.CloseTime.After(prev.CloseTime) {
					prev = ps
				}
			}
		}

		if prev != nil {
			reconnectDelay := s.StartTime.Sub(prev.CloseTime)
			if reconnectDelay <= 60*time.Second {
				stabilityFindings = append(stabilityFindings, fmt.Sprintf("Global Client Reconnection: reconnected %s after previous session (%s) closed", reconnectDelay.Round(time.Second), prev.SessionID))

				// Check IP change (Connection Migration)
				if s.ClientIP != prev.ClientIP {
					stabilityFindings = append(stabilityFindings, fmt.Sprintf("Connection Migration: client IP changed from %s to %s", prev.ClientIP, s.ClientIP))
				}

				// Check Server/Pod/Node change (Cross-Server Migration)
				if s.ServerPod != prev.ServerPod || s.NodeName != prev.NodeName {
					stabilityFindings = append(stabilityFindings, fmt.Sprintf("Cross-Server Migration: client migrated from node %s (%s) to node %s (%s)", prev.NodeName, prev.ServerPod, s.NodeName, s.ServerPod))
					
					// Apply deduction for drift
					stabilityScore = stabilityScore - 10
					if stabilityScore < 0 {
						stabilityScore = 0
					}

					// Append to issues
					correlationIssues = append(correlationIssues, SessionIssue{
						Category:    "STABILITY",
						Severity:    "warn",
						Description: fmt.Sprintf("Client migrated across nodes/pods after %s disconnect. (Previous: %s/%s, Current: %s/%s)", reconnectDelay.Round(time.Second), prev.NodeName, prev.ServerPod, s.NodeName, s.ServerPod),
					})
				}
			}
		}
	}

	// Stability dimension (disconnect reason).
	stabDim := DimensionReport{
		Name:     "Session Stability",
		Score:    stabilityScore,
		MaxScore: 100,
		Metrics: map[string]any{
			"disconnect_reason": s.DisconnectReason,
			"disconnect_detail": s.DisconnectDetail,
			"duration":          formatDuration(s.DurationMs),
		},
	}
	stabDim.Status = dimensionStatus(stabilityScore)
	if s.DisconnectReason != "" {
		stabDim.Findings = append(stabDim.Findings, fmt.Sprintf("Disconnect: %s (%s)", s.DisconnectReason, s.DisconnectDetail))
	}
	// Append global stability findings
	stabDim.Findings = append(stabDim.Findings, stabilityFindings...)
	report.Dimensions = append(report.Dimensions, stabDim)

	// Append correlation issues to report
	if len(correlationIssues) > 0 {
		report.Issues = append(report.Issues, correlationIssues...)
	}

	// Overall verdict.
	switch {
	case s.Score >= 80:
		report.Verdict = "HEALTHY"
	case s.Score >= 60:
		report.Verdict = "DEGRADED"
	case s.Score >= 40:
		report.Verdict = "POOR"
	default:
		report.Verdict = "CRITICAL"
	}

	return report
}

// FormatHTML generates an HTML diagnostic report for the session.
func (r *DiagnosticReporter) FormatHTML(s *SessionRecord, store SessionStore) string {
	data := r.FormatJSON(s, store)
	var buf strings.Builder
	if err := r.tmpl.Execute(&buf, data); err != nil {
		return fmt.Sprintf("<html><body><h1>Report Generation Error</h1><p>%s</p></body></html>", err.Error())
	}
	return buf.String()
}

// dimensionStatus converts a numeric score to a status string.
func dimensionStatus(score int32) string {
	switch {
	case score >= 80:
		return "pass"
	case score >= 60:
		return "warn"
	default:
		return "fail"
	}
}

// formatDuration formats milliseconds as a human-readable duration string.
func formatDuration(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	if d < time.Second {
		return fmt.Sprintf("%dms", ms)
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%02dm", h, m)
}

// reportHTMLTemplate is the HTML template for diagnostic reports.
var reportHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NTRIP Session Diagnostic Report — {{.SessionID}}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 960px; margin: 0 auto; padding: 24px; color: #1a1a2e; background: #f8f9fa; }
  h1 { font-size: 1.5em; border-bottom: 2px solid #3b82f6; padding-bottom: 8px; }
  h2 { font-size: 1.2em; margin-top: 28px; }
  .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 16px 0; font-size: 0.9em; }
  .meta dt { font-weight: 600; color: #64748b; }
  .meta dd { margin: 0; }
  .score-badge { display: inline-block; padding: 4px 16px; border-radius: 20px; font-weight: 700; font-size: 1.4em; }
  .verdict-HEALTHY { background: #dcfce7; color: #166534; }
  .verdict-DEGRADED { background: #fef9c3; color: #854d0e; }
  .verdict-POOR { background: #fed7aa; color: #9a3412; }
  .verdict-CRITICAL { background: #fecaca; color: #991b1b; }
  .dimension { background: white; border-radius: 8px; padding: 16px; margin: 12px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  .dim-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .dim-name { font-weight: 600; font-size: 1.05em; }
  .dim-score { font-size: 0.9em; padding: 2px 10px; border-radius: 12px; }
  .status-pass { background: #dcfce7; color: #166534; }
  .status-warn { background: #fef9c3; color: #854d0e; }
  .status-fail { background: #fecaca; color: #991b1b; }
  .metrics { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 6px; font-size: 0.85em; margin: 8px 0; }
  .metric { padding: 4px 0; }
  .metric-key { color: #64748b; }
  .finding { font-size: 0.9em; color: #b45309; margin: 4px 0; padding-left: 16px; }
  .finding::before { content: "⚠ "; }
  .issues { margin-top: 16px; }
  .issue { padding: 8px 12px; margin: 4px 0; border-left: 3px solid #ef4444; background: #fef2f2; font-size: 0.9em; }
  .issue-severity { font-weight: 600; text-transform: uppercase; font-size: 0.8em; }
  footer { margin-top: 32px; font-size: 0.8em; color: #94a3b8; text-align: center; }
</style>
</head>
<body>
<h1>NTRIP Session Diagnostic Report</h1>

<div class="meta">
  <dt>Session ID</dt><dd>{{.SessionID}}</dd>
  <dt>Mountpoint</dt><dd>{{.Mountpoint}}</dd>
  <dt>Username</dt><dd>{{.Username}}</dd>
  <dt>NTRIP Version</dt><dd>{{.NTRIPVersion}}</dd>
  <dt>Client</dt><dd>{{.ClientAddr}}</dd>
  <dt>Server Pod</dt><dd>{{.ServerPod}}</dd>
  <dt>Node</dt><dd>{{.NodeName}}</dd>
  <dt>Start Time</dt><dd>{{.StartTime}}</dd>
  <dt>Duration</dt><dd>{{.Duration}}</dd>
</div>

<div style="text-align:center;margin:24px 0;">
  <span class="score-badge verdict-{{.Verdict}}">{{.Verdict}} — Score: {{.Score}}/100</span>
</div>

<h2>Diagnostic Dimensions</h2>
{{range .Dimensions}}
<div class="dimension">
  <div class="dim-header">
    <span class="dim-name">{{.Name}}</span>
    <span class="dim-score status-{{.Status}}">{{.Score}}/{{.MaxScore}} ({{.Status}})</span>
  </div>
  <div class="metrics">
    {{range $k, $v := .Metrics}}
    <div class="metric"><span class="metric-key">{{$k}}:</span> {{$v}}</div>
    {{end}}
  </div>
  {{range .Findings}}
  <div class="finding">{{.}}</div>
  {{end}}
</div>
{{end}}

{{if .Issues}}
<h2>Diagnostic Issues</h2>
<div class="issues">
{{range .Issues}}
<div class="issue">
  <span class="issue-severity">{{.Severity}}</span>
  <strong>[{{.Category}}]</strong> {{.Description}}
</div>
{{end}}
</div>
{{end}}

<footer>Generated by Kyanos NTRIP Diagnostic Console — {{.StartTime}}</footer>
</body>
</html>`
