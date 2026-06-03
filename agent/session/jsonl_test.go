package session

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSessionSummaryFromSession(t *testing.T) {
	s := buildClosedSession() // defined in report_test.go
	summary := SessionSummaryFromSession(s, DefaultReportConfig())

	if summary.Type != "session_summary" {
		t.Errorf("Type = %q, want session_summary", summary.Type)
	}
	if summary.SessionID != "sess-1" {
		t.Errorf("SessionID = %q, want sess-1", summary.SessionID)
	}
	if summary.Username != "operator01" {
		t.Errorf("Username = %q, want operator01", summary.Username)
	}
	if summary.ClientIP != "192.168.1.10" || summary.ClientPort != 55000 {
		t.Errorf("client = %s:%d, want 192.168.1.10:55000", summary.ClientIP, summary.ClientPort)
	}
	// 11 RTCM frames seeded in buildClosedSession (10 ok + 1 crc error).
	if summary.RTCMFrames != 11 {
		t.Errorf("RTCMFrames = %d, want 11", summary.RTCMFrames)
	}
	if summary.RTCMCRCErrors != 1 {
		t.Errorf("RTCMCRCErrors = %d, want 1", summary.RTCMCRCErrors)
	}
	if summary.RTCMMessageTypes["1074"] != 10 || summary.RTCMMessageTypes["1005"] != 1 {
		t.Errorf("RTCMMessageTypes = %v, want 1074:10 1005:1", summary.RTCMMessageTypes)
	}
	if summary.Score < 0 || summary.Score > 100 {
		t.Errorf("Score = %d, out of range", summary.Score)
	}
	if summary.DisconnectReason == "" {
		t.Error("DisconnectReason should not be empty")
	}
}

func TestSessionSummaryNeverIncludesPassword(t *testing.T) {
	s := buildClosedSession()
	s.Password = "supersecret"

	// Even with ShowPassword=true, the structured feed must not carry credentials.
	cfg := DefaultReportConfig()
	cfg.ShowPassword = true

	line, err := MarshalSessionSummaryLine(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(line, []byte("supersecret")) {
		t.Error("JSONL output must never contain the password")
	}
}

func TestMarshalSessionSummaryLine_IsValidSingleLineJSON(t *testing.T) {
	s := buildClosedSession()
	line, err := MarshalSessionSummaryLine(s, DefaultReportConfig())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(line, []byte("\n")) {
		t.Error("a JSONL record must not contain embedded newlines")
	}
	var decoded map[string]any
	if err := json.Unmarshal(line, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded["type"] != "session_summary" {
		t.Errorf("decoded type = %v, want session_summary", decoded["type"])
	}
}

func TestJSONLExporter_WritesOneLinePerSession(t *testing.T) {
	var buf bytes.Buffer
	exp := NewJSONLExporterWriter(&buf)

	s1 := buildClosedSession()
	s2 := buildClosedSession()

	if err := exp.WriteSession(s1, DefaultReportConfig()); err != nil {
		t.Fatal(err)
	}
	if err := exp.WriteSession(s2, DefaultReportConfig()); err != nil {
		t.Fatal(err)
	}

	out := strings.TrimRight(buf.String(), "\n")
	lines := strings.Split(out, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), buf.String())
	}
	for i, ln := range lines {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(ln), &decoded); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
	}

	// Writer-backed exporter has no path and Close is a no-op.
	if exp.Path() != "" {
		t.Errorf("Path() = %q, want empty for writer-backed exporter", exp.Path())
	}
	if err := exp.Close(); err != nil {
		t.Errorf("Close() on writer-backed exporter = %v, want nil", err)
	}
}

func TestJSONLReporter_ExportsOnClose(t *testing.T) {
	var buf bytes.Buffer
	exp := NewJSONLExporterWriter(&buf)
	reporter := NewJSONLReporter(exp, DefaultReportConfig())

	s := buildClosedSession()
	reporter.OnSessionCreated(s) // no-op
	if buf.Len() != 0 {
		t.Fatal("OnSessionCreated should not write")
	}

	reporter.OnSessionClosed(s)
	if buf.Len() == 0 {
		t.Fatal("OnSessionClosed should write a JSON line")
	}
	if !strings.Contains(buf.String(), "sess-1") {
		t.Errorf("exported line missing session id: %s", buf.String())
	}
}

func TestJSONLReporter_NilExporterSafe(t *testing.T) {
	reporter := NewJSONLReporter(nil, DefaultReportConfig())
	// Must not panic with a nil exporter.
	reporter.OnSessionClosed(buildClosedSession())
}
