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
	report := r.FormatJSON(s, nil)

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
	report := r.FormatJSON(s, nil)

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
	report := r.FormatJSON(s, nil)

	if report.Verdict != "CRITICAL" {
		t.Errorf("verdict = %q, want CRITICAL", report.Verdict)
	}
}

func TestReportFormatHTML(t *testing.T) {
	r := NewDiagnosticReporter()
	s := makeTestSession()
	html := r.FormatHTML(s, nil)

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
	html := r.FormatHTML(s, nil)

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

func TestReport_GlobalCorrelation(t *testing.T) {
	r := NewDiagnosticReporter()
	store := NewMemoryStore()

	// 1. Create a previous closed session
	prevTime := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	prev := &SessionRecord{
		SessionID:       "prev-session",
		TaskID:          "task-123",
		Username:        "testuser",
		ClientIP:        "10.0.0.1",
		ServerPod:       "pod-1",
		NodeName:        "node-1",
		StartTime:       prevTime,
		CloseTime:       prevTime.Add(30 * time.Minute), // Ends at 12:30
		Closed:          true,
		StabilityScore: 100,
	}
	store.SaveSession(prev)

	// 2. Create a new session (starts 10 seconds later, same IP, same node -> no drift)
	curr1 := &SessionRecord{
		SessionID:       "curr-session-1",
		TaskID:          "task-123",
		Username:        "testuser",
		ClientIP:        "10.0.0.1",
		ServerPod:       "pod-1",
		NodeName:        "node-1",
		StartTime:       prev.CloseTime.Add(10 * time.Second), // Starts at 12:30:10
		Closed:          false,
		StabilityScore: 100,
	}
	report1 := r.FormatJSON(curr1, store)
	
	// Verify reconnection is detected
	stabDim1 := report1.Dimensions[4] // Index 4 is stability dimension
	hasReconn := false
	for _, f := range stabDim1.Findings {
		if strings.Contains(f, "Global Client Reconnection") {
			hasReconn = true
		}
	}
	if !hasReconn {
		t.Error("expected global client reconnection finding")
	}
	if stabDim1.Score != 100 {
		t.Errorf("stability score = %d, want 100", stabDim1.Score)
	}
	if len(report1.Issues) != 0 {
		t.Errorf("len(issues) = %d, want 0", len(report1.Issues))
	}

	// 3. Create a new session (starts 20 seconds later, different IP, different server -> drift!)
	curr2 := &SessionRecord{
		SessionID:       "curr-session-2",
		TaskID:          "task-123",
		Username:        "testuser",
		ClientIP:        "10.0.0.2", // IP changed!
		ServerPod:       "pod-2",   // Pod changed!
		NodeName:        "node-2",   // Node changed!
		StartTime:       prev.CloseTime.Add(20 * time.Second),
		Closed:          false,
		StabilityScore: 100,
	}
	report2 := r.FormatJSON(curr2, store)

	stabDim2 := report2.Dimensions[4]
	hasReconn = false
	hasIPChange := false
	hasMigrate := false
	for _, f := range stabDim2.Findings {
		if strings.Contains(f, "Global Client Reconnection") {
			hasReconn = true
		}
		if strings.Contains(f, "Connection Migration") {
			hasIPChange = true
		}
		if strings.Contains(f, "Cross-Server Migration") {
			hasMigrate = true
		}
	}
	if !hasReconn {
		t.Error("expected global client reconnection finding")
	}
	if !hasIPChange {
		t.Error("expected connection migration finding")
	}
	if !hasMigrate {
		t.Error("expected cross-server migration finding")
	}
	
	// Check score deduction: StabilityScore was 100, should be 90 now
	if stabDim2.Score != 90 {
		t.Errorf("stability score = %d, want 90", stabDim2.Score)
	}

	// Check issue is appended
	if len(report2.Issues) != 1 {
		t.Errorf("len(issues) = %d, want 1", len(report2.Issues))
	} else {
		issue := report2.Issues[0]
		if issue.Category != "STABILITY" {
			t.Errorf("issue category = %q, want STABILITY", issue.Category)
		}
		if issue.Severity != "warn" {
			t.Errorf("issue severity = %q, want warn", issue.Severity)
		}
		if !strings.Contains(issue.Description, "Client migrated across nodes/pods") {
			t.Errorf("issue description = %q, expected migration info", issue.Description)
		}
	}
}
