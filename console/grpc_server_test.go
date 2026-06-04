// Package console — grpc_server_test.go
//
// Tests for AgentServiceHandler: Connect, ReportEvents, StartCapture,
// StopCapture, ReportStatus.
package console

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"kyanos/proto/agentpb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- Mock gRPC streams ---

type mockConnectStream struct {
	grpc.ServerStreamingServer[agentpb.ControlCommand]
	ctx     context.Context
	cancel  context.CancelFunc
	sent    []*agentpb.ControlCommand
	mu      sync.Mutex
	recvMsg *agentpb.AgentInfo
}

func newMockConnectStream(info *agentpb.AgentInfo) *mockConnectStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &mockConnectStream{
		ctx:     ctx,
		cancel:  cancel,
		recvMsg: info,
	}
}

func (s *mockConnectStream) Context() context.Context { return s.ctx }

func (s *mockConnectStream) Send(cmd *agentpb.ControlCommand) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, cmd)
	return nil
}

func (s *mockConnectStream) SendMsg(m any) error { return nil }
func (s *mockConnectStream) RecvMsg(m any) error { return nil }

type mockReportEventsStream struct {
	grpc.ClientStreamingServer[agentpb.SessionEvent, agentpb.EventAck]
	ctx    context.Context
	events []*agentpb.SessionEvent
	idx    int
	mu     sync.Mutex
	acked  *agentpb.EventAck
}

func newMockReportEventsStream(events []*agentpb.SessionEvent) *mockReportEventsStream {
	return &mockReportEventsStream{
		ctx:    context.Background(),
		events: events,
	}
}

func (s *mockReportEventsStream) Context() context.Context { return s.ctx }

func (s *mockReportEventsStream) Recv() (*agentpb.SessionEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idx >= len(s.events) {
		return nil, io.EOF
	}
	evt := s.events[s.idx]
	s.idx++
	return evt, nil
}

func (s *mockReportEventsStream) SendAndClose(ack *agentpb.EventAck) error {
	s.acked = ack
	return nil
}

func (s *mockReportEventsStream) SendMsg(m any) error { return nil }
func (s *mockReportEventsStream) RecvMsg(m any) error { return nil }

// --- Tests ---

func TestHandlerConnectRegistersAgent(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	info := &agentpb.AgentInfo{
		NodeName:     "node-1",
		AgentVersion: "v1.0",
		ManagedPods: []*agentpb.PodInfo{
			{PodName: "pod-a", Namespace: "default"},
		},
	}
	stream := newMockConnectStream(info)

	done := make(chan error, 1)
	go func() {
		done <- handler.Connect(info, stream)
	}()

	// Wait briefly for registration.
	time.Sleep(50 * time.Millisecond)

	// Verify agent is registered.
	agents := handler.ConnectedAgents()
	if len(agents) != 1 || agents[0] != "node-1" {
		t.Errorf("connected agents = %v, want [node-1]", agents)
	}

	a := store.GetAgent("node-1")
	if a == nil {
		t.Fatal("expected agent in store")
	}
	if a.AgentVersion != "v1.0" {
		t.Errorf("version = %q, want v1.0", a.AgentVersion)
	}

	// Disconnect.
	stream.cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Connect did not return after cancel")
	}

	// Verify agent unregistered.
	if agents := handler.ConnectedAgents(); len(agents) != 0 {
		t.Errorf("connected agents = %v, want empty", agents)
	}
}

func TestHandlerConnectNilInfo(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	stream := newMockConnectStream(nil)
	err := handler.Connect(nil, stream)
	if err == nil {
		t.Fatal("expected error for nil info")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument", err)
	}
}

func TestHandlerConnectEmptyNodeName(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	info := &agentpb.AgentInfo{NodeName: ""}
	stream := newMockConnectStream(info)
	err := handler.Connect(info, stream)
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument", err)
	}
}

func TestHandlerReportEvents(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	events := []*agentpb.SessionEvent{
		{
			TaskId:      "task-1",
			SessionId:   "sess-001",
			TimestampNs: 1000000,
			Event: &agentpb.SessionEvent_Auth{
				Auth: &agentpb.AuthEvent{
					Method:     "basic_auth",
					Success:    true,
					Mountpoint: "MOUNT-A",
					Username:   "user001",
				},
			},
		},
		{
			TaskId:      "task-1",
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
		},
		{
			TaskId:      "task-1",
			SessionId:   "sess-001",
			TimestampNs: 3000000,
			Event: &agentpb.SessionEvent_Close{
				Close: &agentpb.SessionCloseEvent{
					DisconnectReason: "client_fin",
					Summary: &agentpb.SessionSummary{
						SessionId:  "sess-001",
						Mountpoint: "MOUNT-A",
						Username:   "user001",
						DurationMs: 5000,
						Score:      90,
					},
				},
			},
		},
	}

	stream := newMockReportEventsStream(events)
	err := handler.ReportEvents(stream)
	if err != nil {
		t.Fatalf("ReportEvents error: %v", err)
	}

	// Verify ack.
	if stream.acked == nil {
		t.Fatal("expected ack")
	}
	if stream.acked.Received != 3 {
		t.Errorf("received = %d, want 3", stream.acked.Received)
	}

	// Verify events stored.
	evts := store.ListEvents("sess-001")
	if len(evts) != 3 {
		t.Errorf("events stored = %d, want 3", len(evts))
	}

	// Verify session saved from close summary.
	sess := store.GetSession("sess-001")
	if sess == nil {
		t.Fatal("expected session saved from summary")
	}
	if sess.Score != 90 {
		t.Errorf("score = %d, want 90", sess.Score)
	}
	if sess.Mountpoint != "MOUNT-A" {
		t.Errorf("mountpoint = %q, want MOUNT-A", sess.Mountpoint)
	}
}

func TestHandlerStartCapture(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	task := &agentpb.CaptureTask{
		TaskId:          "task-001",
		TargetPod:       "ds-pod-7",
		TargetNamespace: "gnss-prod",
		DurationSeconds: 3600,
	}

	resp, err := handler.StartCapture(context.Background(), task)
	if err != nil {
		t.Fatalf("StartCapture error: %v", err)
	}
	if !resp.Accepted {
		t.Error("expected accepted")
	}

	// Verify task persisted.
	got := store.GetTask("task-001")
	if got == nil {
		t.Fatal("expected task in store")
	}
	if got.TargetPod != "ds-pod-7" {
		t.Errorf("target_pod = %q, want ds-pod-7", got.TargetPod)
	}
	if got.Status != TaskStatusRunning {
		t.Errorf("status = %v, want running", got.Status)
	}
}

func TestHandlerStartCaptureNilTask(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	_, err := handler.StartCapture(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil task")
	}
}

func TestHandlerStopCapture(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	// First create a task.
	store.SaveTask(&Task{ID: "task-001", Status: TaskStatusRunning, CreatedAt: time.Now()})

	resp, err := handler.StopCapture(context.Background(), &agentpb.StopRequest{TaskId: "task-001"})
	if err != nil {
		t.Fatalf("StopCapture error: %v", err)
	}
	if resp.Status != agentpb.Status_STOPPED {
		t.Errorf("status = %v, want STOPPED", resp.Status)
	}

	got := store.GetTask("task-001")
	if got.Status != TaskStatusStopped {
		t.Errorf("task status = %v, want stopped", got.Status)
	}
}

func TestHandlerStopCaptureNotFound(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	resp, err := handler.StopCapture(context.Background(), &agentpb.StopRequest{TaskId: "nonexistent"})
	if err != nil {
		t.Fatalf("StopCapture error: %v", err)
	}
	if resp.Status != agentpb.Status_NOT_FOUND {
		t.Errorf("status = %v, want NOT_FOUND", resp.Status)
	}
}

func TestHandlerReportStatus(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	// Pre-register agent via Connect.
	info := &agentpb.AgentInfo{NodeName: "node-1", AgentVersion: "v1.0"}
	stream := newMockConnectStream(info)
	done := make(chan error, 1)
	go func() { done <- handler.Connect(info, stream) }()
	time.Sleep(50 * time.Millisecond)

	// Report status.
	ack, err := handler.ReportStatus(context.Background(), &agentpb.AgentStatus{
		NodeName:        "node-1",
		DiscardedEvents: 42,
		ManagedPods: []*agentpb.PodInfo{
			{PodName: "pod-a"},
			{PodName: "pod-b"},
		},
	})
	if err != nil {
		t.Fatalf("ReportStatus error: %v", err)
	}
	if !ack.Ok {
		t.Error("expected ok=true")
	}

	a := store.GetAgent("node-1")
	if a == nil {
		t.Fatal("expected agent")
	}
	if a.DiscardedEvts != 42 {
		t.Errorf("discarded = %d, want 42", a.DiscardedEvts)
	}

	stream.cancel()
	<-done
}

func TestHandlerSendFilterUpdate(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	// Connect an agent.
	info := &agentpb.AgentInfo{NodeName: "node-1"}
	stream := newMockConnectStream(info)
	done := make(chan error, 1)
	go func() { done <- handler.Connect(info, stream) }()
	time.Sleep(50 * time.Millisecond)

	handler.SendFilterUpdate(&agentpb.FilterUpdate{
		AddPods: []string{"new-pod"},
	})

	stream.mu.Lock()
	sent := len(stream.sent)
	stream.mu.Unlock()

	if sent < 1 {
		t.Errorf("expected at least 1 command sent, got %d", sent)
	}

	stream.cancel()
	<-done
}

func TestHandlerStartCapture_NodeAffinityRouting(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	// Pre-register node-a managing pod-1
	infoA := &agentpb.AgentInfo{
		NodeName: "node-a",
		ManagedPods: []*agentpb.PodInfo{
			{PodName: "pod-1", Namespace: "default"},
		},
	}
	streamA := newMockConnectStream(infoA)
	doneA := make(chan error, 1)
	go func() { doneA <- handler.Connect(infoA, streamA) }()

	// Pre-register node-b managing pod-2
	infoB := &agentpb.AgentInfo{
		NodeName: "node-b",
		ManagedPods: []*agentpb.PodInfo{
			{PodName: "pod-2", Namespace: "default"},
		},
	}
	streamB := newMockConnectStream(infoB)
	doneB := make(chan error, 1)
	go func() { doneB <- handler.Connect(infoB, streamB) }()

	time.Sleep(50 * time.Millisecond)

	// Dispatch task for pod-2 (which resides on node-b)
	task := &agentpb.CaptureTask{
		TaskId:          "task-routed",
		TargetPod:       "pod-2",
		TargetNamespace: "default",
	}

	resp, err := handler.StartCapture(context.Background(), task)
	if err != nil {
		t.Fatalf("StartCapture error: %v", err)
	}
	if !resp.Accepted {
		t.Error("expected task accepted")
	}

	time.Sleep(50 * time.Millisecond)

	// Verify node-b received the command
	streamB.mu.Lock()
	sentB := len(streamB.sent)
	streamB.mu.Unlock()
	if sentB != 1 {
		t.Errorf("node-b received %d commands, want 1", sentB)
	}

	// Verify node-a did NOT receive the command
	streamA.mu.Lock()
	sentA := len(streamA.sent)
	streamA.mu.Unlock()
	if sentA != 0 {
		t.Errorf("node-a received %d commands, want 0", sentA)
	}

	// Verify task in store has t.NodeName = node-b
	gotTask := store.GetTask("task-routed")
	if gotTask == nil {
		t.Fatal("expected task in store")
	}
	if gotTask.NodeName != "node-b" {
		t.Errorf("task NodeName = %q, want node-b", gotTask.NodeName)
	}

	streamA.cancel()
	streamB.cancel()
	<-doneA
	<-doneB
}

func TestHandlerStartCapture_MultiPodPatternRouting(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	handler := NewAgentServiceHandler(store, hub)

	// node-a manages caster-v1-xxx
	infoA := &agentpb.AgentInfo{
		NodeName: "node-a",
		ManagedPods: []*agentpb.PodInfo{
			{PodName: "ntrip-caster-v1-abcde", Namespace: "default"},
			{PodName: "other-pod", Namespace: "default"},
		},
	}
	streamA := newMockConnectStream(infoA)
	doneA := make(chan error, 1)
	go func() { doneA <- handler.Connect(infoA, streamA) }()

	// node-b manages caster-v2-yyy
	infoB := &agentpb.AgentInfo{
		NodeName: "node-b",
		ManagedPods: []*agentpb.PodInfo{
			{PodName: "ntrip-caster-v2-fghij", Namespace: "default"},
		},
	}
	streamB := newMockConnectStream(infoB)
	doneB := make(chan error, 1)
	go func() { doneB <- handler.Connect(infoB, streamB) }()

	// node-c manages mysql
	infoC := &agentpb.AgentInfo{
		NodeName: "node-c",
		ManagedPods: []*agentpb.PodInfo{
			{PodName: "mysql-db-12345", Namespace: "default"},
		},
	}
	streamC := newMockConnectStream(infoC)
	doneC := make(chan error, 1)
	go func() { doneC <- handler.Connect(infoC, streamC) }()

	time.Sleep(50 * time.Millisecond)

	// Dispatch task for v2 caster specifically (ntrip-caster-v2*)
	task := &agentpb.CaptureTask{
		TaskId:          "task-canary",
		TargetPod:       "ntrip-caster-v2*",
		TargetNamespace: "default",
	}

	resp, err := handler.StartCapture(context.Background(), task)
	if err != nil {
		t.Fatalf("StartCapture error: %v", err)
	}
	if !resp.Accepted {
		t.Error("expected task accepted")
	}

	time.Sleep(50 * time.Millisecond)

	// node-b should receive the command
	streamB.mu.Lock()
	sentB := len(streamB.sent)
	streamB.mu.Unlock()
	if sentB != 1 {
		t.Errorf("node-b received %d commands, want 1", sentB)
	}

	// node-a and node-c should NOT receive the command
	streamA.mu.Lock()
	sentA := len(streamA.sent)
	streamA.mu.Unlock()
	if sentA != 0 {
		t.Errorf("node-a received %d commands, want 0", sentA)
	}

	streamC.mu.Lock()
	sentC := len(streamC.sent)
	streamC.mu.Unlock()
	if sentC != 0 {
		t.Errorf("node-c received %d commands, want 0", sentC)
	}

	streamA.cancel()
	streamB.cancel()
	streamC.cancel()
	<-doneA
	<-doneB
	<-doneC
}
