// Package console — types_test.go
//
// Tests for protobuf conversion helpers.
package console

import (
	"testing"

	"kyanos/proto/agentpb"
)

func TestPodInfoFromProto(t *testing.T) {
	p := &agentpb.PodInfo{
		PodName:      "ds-pod-7",
		PodIp:        "10.0.1.7",
		Namespace:    "gnss-prod",
		NodeName:     "node-3",
		ContainerIds: []string{"abc123"},
		CgroupIds:    []uint64{42, 43},
	}
	got := PodInfoFromProto(p)
	if got.PodName != "ds-pod-7" {
		t.Errorf("PodName = %q", got.PodName)
	}
	if got.PodIP != "10.0.1.7" {
		t.Errorf("PodIP = %q", got.PodIP)
	}
	if len(got.ContainerIDs) != 1 {
		t.Errorf("ContainerIDs len = %d", len(got.ContainerIDs))
	}
	if len(got.CgroupIDs) != 2 {
		t.Errorf("CgroupIDs len = %d", len(got.CgroupIDs))
	}
}

func TestPodInfoFromProtoNil(t *testing.T) {
	got := PodInfoFromProto(nil)
	if got.PodName != "" {
		t.Errorf("expected empty PodName for nil input")
	}
}

func TestPodInfosFromProto(t *testing.T) {
	ps := []*agentpb.PodInfo{
		{PodName: "pod-a"},
		{PodName: "pod-b"},
	}
	got := PodInfosFromProto(ps)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].PodName != "pod-a" || got[1].PodName != "pod-b" {
		t.Error("pod names mismatch")
	}
}

func TestPodInfosFromProtoNil(t *testing.T) {
	got := PodInfosFromProto(nil)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestSessionRecordFromSummary(t *testing.T) {
	summary := &agentpb.SessionSummary{
		SessionId:       "sess-001",
		Mountpoint:      "MOUNT-A",
		Username:        "user001",
		NtripVersion:    "2.0",
		ClientIp:        "10.0.0.1",
		ClientPort:      12345,
		ServerPod:       "ds-pod-7",
		ServerIp:        "10.0.1.7",
		StartTimeNs:     1000000000,
		CloseTimeNs:     2000000000,
		DurationMs:      1000,
		AuthMethod:      "basic_auth",
		AuthChecked:     true,
		AuthSuccess:     true,
		HttpStatusCode:  200,
		GgaEvents:       100,
		RtcmFrames:      5000,
		RtcmCrcErrors:   2,
		Retransmissions: 1,
		Score:           85,
		LoginScore:      100,
		GgaScore:        90,
		RtcmScore:       80,
		NetworkScore:    75,
		StabilityScore:  85,
		Issues: []*agentpb.SessionIssue{
			{Category: "rtcm", Severity: "warning", Description: "CRC errors"},
		},
	}

	rec := SessionRecordFromSummary(summary, "task-1", "node-1")
	if rec == nil {
		t.Fatal("expected non-nil record")
	}
	if rec.SessionID != "sess-001" {
		t.Errorf("SessionID = %q", rec.SessionID)
	}
	if rec.TaskID != "task-1" {
		t.Errorf("TaskID = %q", rec.TaskID)
	}
	if rec.NodeName != "node-1" {
		t.Errorf("NodeName = %q", rec.NodeName)
	}
	if rec.Score != 85 {
		t.Errorf("Score = %d", rec.Score)
	}
	if len(rec.Issues) != 1 {
		t.Errorf("Issues len = %d", len(rec.Issues))
	}
	if rec.Issues[0].Category != "rtcm" {
		t.Errorf("Issue category = %q", rec.Issues[0].Category)
	}
}

func TestSessionRecordFromSummaryNil(t *testing.T) {
	rec := SessionRecordFromSummary(nil, "", "")
	if rec != nil {
		t.Errorf("expected nil for nil summary")
	}
}

func TestEventRecordFromProtoAuth(t *testing.T) {
	evt := &agentpb.SessionEvent{
		TaskId:         "task-1",
		SessionId:      "sess-001",
		TimestampNs:    1000000,
		Pod:            &agentpb.PodInfo{PodName: "pod-a", Namespace: "default"},
		ObservedClient: &agentpb.ClientAddr{Ip: "10.0.0.1", Port: 12345},
		Event: &agentpb.SessionEvent_Auth{
			Auth: &agentpb.AuthEvent{
				Method:     "basic_auth",
				Success:    true,
				Mountpoint: "MOUNT-A",
				Username:   "user001",
			},
		},
	}
	rec := EventRecordFromProto(evt)
	if rec == nil {
		t.Fatal("expected non-nil record")
	}
	if rec.EventType != "auth" {
		t.Errorf("EventType = %q, want auth", rec.EventType)
	}
	if rec.PodName != "pod-a" {
		t.Errorf("PodName = %q", rec.PodName)
	}
	if rec.ClientIP != "10.0.0.1" {
		t.Errorf("ClientIP = %q", rec.ClientIP)
	}
	authData, ok := rec.EventData.(AuthEventData)
	if !ok {
		t.Fatal("expected AuthEventData")
	}
	if !authData.Success {
		t.Error("expected auth success")
	}
}

func TestEventRecordFromProtoGGA(t *testing.T) {
	evt := &agentpb.SessionEvent{
		SessionId:   "sess-001",
		TimestampNs: 2000000,
		Event: &agentpb.SessionEvent_Gga{
			Gga: &agentpb.GgaEvent{
				Latitude:      39.9,
				Longitude:     116.4,
				FixQuality:    1,
				NumSatellites: 12,
			},
		},
	}
	rec := EventRecordFromProto(evt)
	if rec.EventType != "gga" {
		t.Errorf("EventType = %q, want gga", rec.EventType)
	}
	gga, ok := rec.EventData.(GGAEventData)
	if !ok {
		t.Fatal("expected GGAEventData")
	}
	if gga.NumSats != 12 {
		t.Errorf("NumSats = %d", gga.NumSats)
	}
}

func TestEventRecordFromProtoRTCM(t *testing.T) {
	evt := &agentpb.SessionEvent{
		SessionId:   "sess-001",
		TimestampNs: 3000000,
		Event: &agentpb.SessionEvent_Rtcm{
			Rtcm: &agentpb.RtcmEvent{
				MessageType: 1074,
				Size:        300,
				CrcValid:    true,
			},
		},
	}
	rec := EventRecordFromProto(evt)
	if rec.EventType != "rtcm" {
		t.Errorf("EventType = %q", rec.EventType)
	}
	rtcm, ok := rec.EventData.(RTCMEventData)
	if !ok {
		t.Fatal("expected RTCMEventData")
	}
	if rtcm.MessageType != 1074 {
		t.Errorf("MessageType = %d", rtcm.MessageType)
	}
}

func TestEventRecordFromProtoNetwork(t *testing.T) {
	evt := &agentpb.SessionEvent{
		SessionId: "sess-001",
		Event: &agentpb.SessionEvent_Network{
			Network: &agentpb.NetworkEvent{
				Retransmissions:    5,
				RetransmissionRate: 0.01,
				AvgRttUs:           2100,
			},
		},
	}
	rec := EventRecordFromProto(evt)
	if rec.EventType != "network" {
		t.Errorf("EventType = %q", rec.EventType)
	}
}

func TestEventRecordFromProtoClose(t *testing.T) {
	evt := &agentpb.SessionEvent{
		SessionId: "sess-001",
		Event: &agentpb.SessionEvent_Close{
			Close: &agentpb.SessionCloseEvent{
				DisconnectReason: "client_fin",
				Summary:          &agentpb.SessionSummary{SessionId: "sess-001"},
			},
		},
	}
	rec := EventRecordFromProto(evt)
	if rec.EventType != "close" {
		t.Errorf("EventType = %q", rec.EventType)
	}
	closeData, ok := rec.EventData.(CloseEventData)
	if !ok {
		t.Fatal("expected CloseEventData")
	}
	if !closeData.HasSummary {
		t.Error("expected HasSummary=true")
	}
}

func TestEventRecordFromProtoUnknown(t *testing.T) {
	evt := &agentpb.SessionEvent{
		SessionId: "sess-001",
		Event:     nil, // unknown event type
	}
	rec := EventRecordFromProto(evt)
	if rec.EventType != "unknown" {
		t.Errorf("EventType = %q, want unknown", rec.EventType)
	}
}

func TestEventRecordFromProtoNil(t *testing.T) {
	rec := EventRecordFromProto(nil)
	if rec != nil {
		t.Errorf("expected nil for nil event")
	}
}

func TestTaskStatusString(t *testing.T) {
	tests := []struct {
		s    TaskStatus
		want string
	}{
		{TaskStatusPending, "pending"},
		{TaskStatusRunning, "running"},
		{TaskStatusStopped, "stopped"},
		{TaskStatusCompleted, "completed"},
		{TaskStatusFailed, "failed"},
		{TaskStatus(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.s.String()
		if got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}
