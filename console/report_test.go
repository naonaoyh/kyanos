// Package console — report_test.go
//
// Tests for DiagnosticReporter: JSON and HTML report generation.
package console

import (
	"strings"
	"testing"
	"time"
)

func makeTestSession() *SessionRecord {
	return &SessionRecord{
		SessionID:  "sess-test-001",
		TaskID:     "task-1",
		Mountpoint: "MOUNT-A",
		Username:   "user001",
		NTRIPVer:   "2.0",
		ClientIP:   "10.0.0.1",
		ClientPort: 12345,
		ServerPod:  "ds-pod-7",
		NodeName:   "node-3",
		StartTime:  time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC),
		CloseTime:  time.Date(2026, 6, 4, 14, 35, 12, 0, time.UTC),
		DurationMs: 9312000, // 2h35m12s
		Closed:     true,

		AuthMethod:     "basic_auth",
		AuthChecked:    true,
		AuthSuccess:    true,
		HTTPStatusCode: 200,
		LoginLatencyMs: 120,

		GGAEvents:      2012,
		GGAFixRate:     0.99,
		GGAAvgSats:     12.5,
		GGAFrequencyHz: 1.0,

		RTCMFrames:        180720,
		RTCMBytes:         54216000,
		RTCMCRCErrors:     0,
		RTCMCRCErrorRate:  0.0,
		RTCMAvgIntervalMs: 1,
		RTCMP95IntervalMs: 2,
		RTCMThroughputBps: 58320,
		RTCMInterruptions: 0,
		RTCMMessageTypes:  map[string]int32{"1005": 2012, "1074": 2012, "1124": 2012},

		Retransmissions: 3,
		RetransmitRate:  0.001,
		AvgRTTMs:        2.1,
		P95RTTMs:        5.3,
		RTTJitterMs:     1.2,
		TCPResets:       0,

		DisconnectReason: "client_fin",
		DisconnectDetail: "normal close",

		Score:          92,
		LoginScore:     100,
		GGAScore:       95,
		RTCMScore:      98,
		NetworkScore:   85,
		StabilityScore: 90,
	}
}

func TestReportFormatJSON(t *testing.T) {
	r := NewDiagnosticReporter()
	s := makeTestSession()
	report := r.FormatJSON(s)

	if report.SessionID != "sess-test-001" {
		t.Errorf("session_id = %q", report.SessionID)
	}
	if report.Score != 92 {
		t.Errorf("score = %d, want 92", report.Score)
	}
	if report.Verdict != "HEALTHY" {
		t.Errorf("verdict = %q, want HEALTHY", report.Verdict)
	}
	if len(report.Dimensions) != 5 {
		t.Errorf("dimensions = %d, want 5", len(report.Dimensions))
	}

	// Check login dimension.
	login := report.Dimensions[0]
	if login.Name != "Login / Authentication" {
		t.Errorf("dim[0].name = %q", login.Name)
	}
	if login.Status != "pass" {
		t.Errorf("login status = %q, want pass", login.Status)
	}
}

func TestReportFormatJSONDegraded(t *testing.T) {
	r := NewDiagnosticReporter()
	s := makeTestSession()
	s.Score = 65
	s.RTCMScore = 50
	s.RTCMCRCErrors = 100
	s.RTCMCRCErrorRate = 0.05
	s.RTCMInterruptions = 5
	report := r.FormatJSON(s)

	if report.Verdict != "DEGRADED" {
		t.Errorf("verdict = %q, want DEGRADED", report.Verdict)
	}

	// RTCM dimension should have findings.
	rtcm := report.Dimensions[2]
	if len(rtcm.Findings) == 0 {
		t.Error("expected RTCM findings")
	}
}

func TestReportFormatJSONCritical(t *testing.T) {
	r := NewDiagnosticReporter()
	s := makeTestSession()
	s.Score = 20
	s.LoginScore = 0
	s.AuthSuccess = false
	report := r.FormatJSON(s)

	if report.Verdict != "CRITICAL" {
		t.Errorf("verdict = %q, want CRITICAL", report.Verdict)
	}
}

func TestReportFormatHTML(t *testing.T) {
	r := NewDiagnosticReporter()
	s := makeTestSession()
	html := r.FormatHTML(s)

	if !strings.Contains(html, "sess-test-001") {
		t.Error("HTML missing session ID")
	}
	if !strings.Contains(html, "MOUNT-A") {
		t.Error("HTML missing mountpoint")
	}
	if !strings.Contains(html, "HEALTHY") {
		t.Error("HTML missing verdict")
	}
	if !strings.Contains(html, "Login / Authentication") {
		t.Error("HTML missing login dimension")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("HTML not properly closed")
	}
}

func TestReportFormatHTMLWithIssues(t *testing.T) {
	r := NewDiagnosticReporter()
	s := makeTestSession()
	s.Issues = []SessionIssue{
		{Category: "rtcm", Severity: "warning", Description: "CRC errors above threshold"},
	}
	html := r.FormatHTML(s)

	if !strings.Contains(html, "CRC errors above threshold") {
		t.Error("HTML missing issue description")
	}
	if !strings.Contains(html, "warning") {
		t.Error("HTML missing severity")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		ms   int64
		want string
	}{
		{500, "500ms"},
		{3000, "3.0s"},
		{90000, "1m30s"},
		{9312000, "2h35m"},
	}
	for _, tt := range tests {
		got := formatDuration(tt.ms)
		if got != tt.want {
			t.Errorf("formatDuration(%d) = %q, want %q", tt.ms, got, tt.want)
		}
	}
}

func TestDimensionStatus(t *testing.T) {
	tests := []struct {
		score int32
		want  string
	}{
		{90, "pass"},
		{80, "pass"},
		{70, "warn"},
		{60, "warn"},
		{50, "fail"},
		{0, "fail"},
	}
	for _, tt := range tests {
		got := dimensionStatus(tt.score)
		if got != tt.want {
			t.Errorf("dimensionStatus(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
