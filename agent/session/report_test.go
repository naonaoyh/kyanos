package session

import (
	"strings"
	"testing"
	"time"
)

// buildClosedSession creates a finalized session with a little of every signal
// so the report exercises all sections.
func buildClosedSession() *NTRIPSession {
	start := time.Now().Add(-30 * time.Second)
	s := NewNTRIPSession("sess-1", "MOUNT01", "operator01", "192.168.1.10", 55000, start)
	s.ServerIP = "10.0.1.5"
	s.NTRIPVersion = "NTRIPv2"
	s.AuthMethod = "basic_auth"
	s.AuthChecked = true
	s.AuthSuccess = true
	s.HTTPStatusCode = 200
	s.LoginLatency = 25 * time.Millisecond

	// GGA events
	s.AddGGAEvent(start.Add(1*time.Second), 31.24, 121.48, 4, 18, 0.8, 1.2, "0312", "")
	s.AddGGAEvent(start.Add(2*time.Second), 31.24, 121.48, 4, 17, 0.9, 1.3, "0312", "")

	// RTCM frames
	for i := 0; i < 10; i++ {
		s.AddRTCMFrame(start.Add(time.Duration(i)*time.Second), 1074, 200, true, time.Time{})
	}
	// one CRC error
	s.AddRTCMFrame(start.Add(11*time.Second), 1005, 36, false, time.Time{})

	s.Close(start.Add(30 * time.Second))
	s.AnalyzeDisconnect(60*time.Second, 5, false)
	return s
}

func TestFormatSessionReport_ContainsKeySections(t *testing.T) {
	s := buildClosedSession()
	report := FormatSessionReport(s, DefaultReportConfig())

	mustContain := []string{
		"NTRIP Session Diagnostic Report",
		"sess-1",
		"192.168.1.10:55000",
		"MOUNT01",
		"operator01",
		"Login (S1)",
		"GGA Uploads (S2)",
		"RTCM Delivery (S3)",
		"Network Quality (S5)",
		"Disconnect (S4)",
		"Diagnostic Score",
		"Total:",
	}
	for _, want := range mustContain {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q\n---\n%s", want, report)
		}
	}
}

func TestFormatSessionReport_HidesPasswordByDefault(t *testing.T) {
	s := buildClosedSession()
	s.Password = "supersecret"

	// Default config: password hidden.
	report := FormatSessionReport(s, DefaultReportConfig())
	if strings.Contains(report, "supersecret") {
		t.Error("default report should NOT contain the password")
	}

	// With ShowPassword, it appears.
	cfg := DefaultReportConfig()
	cfg.ShowPassword = true
	report = FormatSessionReport(s, cfg)
	if !strings.Contains(report, "supersecret") {
		t.Error("report with ShowPassword=true should contain the password")
	}
}

func TestFormatSessionReport_ShowsRTCMStats(t *testing.T) {
	s := buildClosedSession()
	report := FormatSessionReport(s, DefaultReportConfig())

	// 11 frames total (10 ok + 1 crc error), should be reflected.
	if !strings.Contains(report, "Frames:      11") {
		t.Errorf("report should show 11 frames\n---\n%s", report)
	}
	// Message-type histogram includes both types.
	if !strings.Contains(report, "1074:10") || !strings.Contains(report, "1005:1") {
		t.Errorf("report should show msg-type histogram\n---\n%s", report)
	}
}

func TestDiagnosticReporter_EmitsOnClose(t *testing.T) {
	var captured []string
	reporter := NewDiagnosticReporter(DefaultReportConfig(), func(r string) {
		captured = append(captured, r)
	})

	// OnSessionCreated is a no-op.
	s := buildClosedSession()
	reporter.OnSessionCreated(s)
	if len(captured) != 0 {
		t.Fatalf("OnSessionCreated should not emit, got %d reports", len(captured))
	}

	reporter.OnSessionClosed(s)
	if len(captured) != 1 {
		t.Fatalf("OnSessionClosed should emit exactly 1 report, got %d", len(captured))
	}
	if !strings.Contains(captured[0], "sess-1") {
		t.Errorf("emitted report missing session id\n%s", captured[0])
	}
}

func TestDiagnosticReporter_NilSinkSafe(t *testing.T) {
	reporter := NewDiagnosticReporter(DefaultReportConfig(), nil)
	// Should not panic with a nil sink.
	reporter.OnSessionClosed(buildClosedSession())
}

func TestFormatPodLoadSummary_Empty(t *testing.T) {
	p := NewPodLoadAnalyzer()
	out := FormatPodLoadSummary(p)
	if !strings.Contains(out, "no NTRIP/RTCM sessions observed") {
		t.Errorf("empty summary should note no sessions\n%s", out)
	}
}

func TestFormatPodLoadSummary_WithPods(t *testing.T) {
	p := NewPodLoadAnalyzer()
	p.OnSessionCreated(newPodSession("s1", "pod-a", "10.0.0.1", "192.168.0.1", 10, time.Second))
	p.OnSessionCreated(newPodSession("s2", "pod-b", "10.0.0.2", "192.168.0.2", 5, time.Second))

	out := FormatPodLoadSummary(p)
	for _, want := range []string{"Multi-Pod Load Summary", "pod-a", "pod-b", "Load imbalance", "Pods: 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("pod-load summary missing %q\n---\n%s", want, out)
		}
	}
}

func TestFormatPodLoadSummary_NilAnalyzer(t *testing.T) {
	if out := FormatPodLoadSummary(nil); out != "" {
		t.Errorf("nil analyzer should return empty string, got %q", out)
	}
}
