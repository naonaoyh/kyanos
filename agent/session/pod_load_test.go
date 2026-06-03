package session

import (
	"testing"
	"time"

	"kyanos/agent/protocol"
)

// newPodSession builds a session assigned to a given Pod / server IP and seeds
// it with a number of RTCM frames spread over the elapsed duration so that
// RTCMFrameRate() is well-defined.
func newPodSession(id, pod, serverIP, clientIP string, frames int, age time.Duration) *NTRIPSession {
	start := time.Now().Add(-age)
	s := NewNTRIPSession(id, "MOUNT", "user", clientIP, 12345, start)
	s.ServerPod = pod
	s.ServerIP = serverIP
	for i := 0; i < frames; i++ {
		s.AddRTCMFrame(start.Add(time.Duration(i)*time.Millisecond), 1074, 200, true, time.Time{})
	}
	return s
}

func TestPodLoadAnalyzer_AggregatesByPod(t *testing.T) {
	p := NewPodLoadAnalyzer()

	p.OnSessionCreated(newPodSession("s1", "pod-a", "10.0.0.1", "192.168.0.1", 10, time.Second))
	p.OnSessionCreated(newPodSession("s2", "pod-a", "10.0.0.1", "192.168.0.2", 20, time.Second))
	p.OnSessionCreated(newPodSession("s3", "pod-b", "10.0.0.2", "192.168.0.3", 5, time.Second))

	if got := p.PodCount(); got != 2 {
		t.Fatalf("PodCount() = %d, want 2", got)
	}

	snap := p.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot len = %d, want 2", len(snap))
	}

	// Sorted by PodKey: pod-a then pod-b.
	podA := snap[0]
	if podA.PodKey != "pod-a" {
		t.Fatalf("snap[0].PodKey = %q, want pod-a", podA.PodKey)
	}
	if podA.ActiveSessions != 2 {
		t.Errorf("pod-a ActiveSessions = %d, want 2", podA.ActiveSessions)
	}
	if podA.TotalRTCMFrames != 30 {
		t.Errorf("pod-a TotalRTCMFrames = %d, want 30", podA.TotalRTCMFrames)
	}
	if podA.UniqueClients != 2 {
		t.Errorf("pod-a UniqueClients = %d, want 2", podA.UniqueClients)
	}

	podB := snap[1]
	if podB.PodKey != "pod-b" {
		t.Fatalf("snap[1].PodKey = %q, want pod-b", podB.PodKey)
	}
	if podB.ActiveSessions != 1 {
		t.Errorf("pod-b ActiveSessions = %d, want 1", podB.ActiveSessions)
	}
	if podB.TotalRTCMFrames != 5 {
		t.Errorf("pod-b TotalRTCMFrames = %d, want 5", podB.TotalRTCMFrames)
	}
}

func TestPodLoadAnalyzer_FallbackToServerIP(t *testing.T) {
	p := NewPodLoadAnalyzer()
	// No ServerPod set -> key falls back to "ip:<serverIP>".
	p.OnSessionCreated(newPodSession("s1", "", "10.0.0.9", "192.168.0.1", 3, time.Second))

	snap := p.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("Snapshot len = %d, want 1", len(snap))
	}
	if snap[0].PodKey != "ip:10.0.0.9" {
		t.Errorf("PodKey = %q, want ip:10.0.0.9", snap[0].PodKey)
	}
	if snap[0].PodName != "" {
		t.Errorf("PodName = %q, want empty", snap[0].PodName)
	}
}

func TestPodLoadAnalyzer_LoadImbalance_Balanced(t *testing.T) {
	p := NewPodLoadAnalyzer()
	// Two pods, one active session each -> perfectly balanced -> CV 0.
	p.OnSessionCreated(newPodSession("s1", "pod-a", "10.0.0.1", "192.168.0.1", 1, time.Second))
	p.OnSessionCreated(newPodSession("s2", "pod-b", "10.0.0.2", "192.168.0.2", 1, time.Second))

	if cv := p.LoadImbalance(); cv != 0 {
		t.Errorf("LoadImbalance() = %f, want 0 for balanced load", cv)
	}
}

func TestPodLoadAnalyzer_LoadImbalance_Unbalanced(t *testing.T) {
	p := NewPodLoadAnalyzer()
	// pod-a: 3 active sessions, pod-b: 1 active session -> CV > 0.
	p.OnSessionCreated(newPodSession("s1", "pod-a", "10.0.0.1", "192.168.0.1", 1, time.Second))
	p.OnSessionCreated(newPodSession("s2", "pod-a", "10.0.0.1", "192.168.0.2", 1, time.Second))
	p.OnSessionCreated(newPodSession("s3", "pod-a", "10.0.0.1", "192.168.0.3", 1, time.Second))
	p.OnSessionCreated(newPodSession("s4", "pod-b", "10.0.0.2", "192.168.0.4", 1, time.Second))

	cv := p.LoadImbalance()
	if cv <= 0 {
		t.Errorf("LoadImbalance() = %f, want > 0 for unbalanced load", cv)
	}
}

func TestPodLoadAnalyzer_SinglePodImbalanceZero(t *testing.T) {
	p := NewPodLoadAnalyzer()
	p.OnSessionCreated(newPodSession("s1", "pod-a", "10.0.0.1", "192.168.0.1", 1, time.Second))
	if cv := p.LoadImbalance(); cv != 0 {
		t.Errorf("LoadImbalance() with one pod = %f, want 0", cv)
	}
}

func TestPodLoadAnalyzer_PodSwitchDetection(t *testing.T) {
	p := NewPodLoadAnalyzer()
	client := "192.168.0.50"

	// Same client first on pod-a, then on pod-b -> one switch.
	p.OnSessionCreated(newPodSession("s1", "pod-a", "10.0.0.1", client, 1, time.Second))
	p.OnSessionCreated(newPodSession("s2", "pod-b", "10.0.0.2", client, 1, time.Second))

	switches := p.PodSwitches()
	if len(switches) != 1 {
		t.Fatalf("PodSwitches len = %d, want 1", len(switches))
	}
	sw := switches[0]
	if sw.ClientIP != client || sw.OldPodKey != "pod-a" || sw.NewPodKey != "pod-b" {
		t.Errorf("unexpected switch event: %+v", sw)
	}
	if p.IsSticky(client) {
		t.Errorf("IsSticky(%q) = true, want false after a Pod switch", client)
	}
}

func TestPodLoadAnalyzer_StickyClient(t *testing.T) {
	p := NewPodLoadAnalyzer()
	client := "192.168.0.60"

	// Same client, same pod twice (e.g. reconnect to same Pod) -> sticky.
	p.OnSessionCreated(newPodSession("s1", "pod-a", "10.0.0.1", client, 1, time.Second))
	p.OnSessionCreated(newPodSession("s2", "pod-a", "10.0.0.1", client, 1, time.Second))

	if len(p.PodSwitches()) != 0 {
		t.Errorf("PodSwitches len = %d, want 0 for same-pod reconnect", len(p.PodSwitches()))
	}
	if !p.IsSticky(client) {
		t.Errorf("IsSticky(%q) = false, want true (never switched pods)", client)
	}
	// Unknown client is vacuously sticky.
	if !p.IsSticky("0.0.0.0") {
		t.Errorf("IsSticky(unknown) = false, want true")
	}
}

func TestPodLoadAnalyzer_ClosedSessionsDropFromActive(t *testing.T) {
	p := NewPodLoadAnalyzer()
	s := newPodSession("s1", "pod-a", "10.0.0.1", "192.168.0.1", 10, time.Second)
	p.OnSessionCreated(s)

	if snap := p.Snapshot(); snap[0].ActiveSessions != 1 {
		t.Fatalf("ActiveSessions before close = %d, want 1", snap[0].ActiveSessions)
	}

	s.Close(time.Now())
	p.OnSessionClosed(s)

	snap := p.Snapshot()
	if snap[0].ActiveSessions != 0 {
		t.Errorf("ActiveSessions after close = %d, want 0", snap[0].ActiveSessions)
	}
	// Historical totals are retained.
	if snap[0].TotalSessions != 1 {
		t.Errorf("TotalSessions after close = %d, want 1", snap[0].TotalSessions)
	}
	if snap[0].TotalRTCMFrames != 10 {
		t.Errorf("TotalRTCMFrames after close = %d, want 10", snap[0].TotalRTCMFrames)
	}
}

func TestPodLoadAnalyzer_IntegrationWithTracker(t *testing.T) {
	cfg := DefaultTrackerConfig()
	tracker := NewSessionTracker(cfg)
	analyzer := NewPodLoadAnalyzer()
	tracker.AddListener(analyzer)

	// Two clients connecting to the same server (server IP 10.0.1.5).
	conn1 := makeConnInfo("10.0.1.5", "192.168.1.100", 2101, 54321)
	conn2 := makeConnInfo("10.0.1.5", "192.168.1.101", 2101, 54322)

	req1 := makeNTRIPRequest(1_000_000, "MOUNT01", "u1", "p1", true)
	resp1 := makeNTRIPResponse(1_100_000, 200)
	tracker.OnRecord(protocol.Record{Req: req1, Resp: resp1}, conn1)

	req2 := makeNTRIPRequest(2_000_000, "MOUNT01", "u2", "p2", true)
	resp2 := makeNTRIPResponse(2_100_000, 200)
	tracker.OnRecord(protocol.Record{Req: req2, Resp: resp2}, conn2)

	// Both sessions share server IP 10.0.1.5 -> aggregated under one Pod key.
	if got := analyzer.PodCount(); got != 1 {
		t.Fatalf("PodCount() = %d, want 1 (same server IP)", got)
	}
	snap := analyzer.Snapshot()
	if snap[0].PodKey != "ip:10.0.1.5" {
		t.Errorf("PodKey = %q, want ip:10.0.1.5", snap[0].PodKey)
	}
	if snap[0].ActiveSessions != 2 {
		t.Errorf("ActiveSessions = %d, want 2", snap[0].ActiveSessions)
	}
	if snap[0].UniqueClients != 2 {
		t.Errorf("UniqueClients = %d, want 2", snap[0].UniqueClients)
	}
}
