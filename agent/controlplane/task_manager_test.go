package controlplane

import (
	"testing"
	"time"

	"kyanos/agent/session"
	"kyanos/proto/agentpb"
)

func TestTaskManager_Start_Accept(t *testing.T) {
	clk := NewFakeClock(time.Now())
	tm := NewTaskManager(clk)

	resp := tm.Start(&agentpb.CaptureTask{
		TaskId:          "task-1",
		TargetPod:       "my-pod",
		TargetNamespace: "default",
	})

	if !resp.Accepted {
		t.Fatalf("expected accepted, got rejected: %s", resp.Reason)
	}
	if resp.Status != agentpb.Status_ACCEPTED {
		t.Fatalf("expected ACCEPTED status, got %v", resp.Status)
	}
	if resp.TaskId != "task-1" {
		t.Fatalf("expected task_id 'task-1', got %q", resp.TaskId)
	}
	if !tm.IsActive("task-1") {
		t.Fatal("task should be active after Start")
	}
}

func TestTaskManager_Start_RejectEmptyID(t *testing.T) {
	tm := NewTaskManager(nil)

	resp := tm.Start(&agentpb.CaptureTask{
		TaskId:    "",
		TargetPod: "my-pod",
	})

	if resp.Accepted {
		t.Fatal("expected rejection for empty task_id")
	}
	if resp.Reason == "" {
		t.Fatal("expected non-empty reason on rejection")
	}
	if resp.Status != agentpb.Status_REJECTED {
		t.Fatalf("expected REJECTED status, got %v", resp.Status)
	}
}

func TestTaskManager_Start_RejectNoScope(t *testing.T) {
	tm := NewTaskManager(nil)

	resp := tm.Start(&agentpb.CaptureTask{
		TaskId: "task-no-scope",
	})

	if resp.Accepted {
		t.Fatal("expected rejection for no scope")
	}
	if resp.Reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestTaskManager_Start_RejectDuplicate(t *testing.T) {
	tm := NewTaskManager(nil)

	tm.Start(&agentpb.CaptureTask{TaskId: "dup", TargetPod: "p"})
	resp := tm.Start(&agentpb.CaptureTask{TaskId: "dup", TargetPod: "p"})

	if resp.Accepted {
		t.Fatal("expected rejection for duplicate task_id")
	}
	if resp.Reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestTaskManager_Start_NilTask(t *testing.T) {
	tm := NewTaskManager(nil)
	resp := tm.Start(nil)

	if resp.Accepted {
		t.Fatal("expected rejection for nil task")
	}
}

func TestTaskManager_Stop_Active(t *testing.T) {
	tm := NewTaskManager(nil)
	tm.Start(&agentpb.CaptureTask{TaskId: "task-x", TargetPod: "pod-a"})

	resp := tm.Stop(&agentpb.StopRequest{TaskId: "task-x"})

	if resp.Status != agentpb.Status_STOPPED {
		t.Fatalf("expected STOPPED, got %v", resp.Status)
	}
	if resp.TaskId != "task-x" {
		t.Fatalf("expected task_id 'task-x', got %q", resp.TaskId)
	}
	if tm.IsActive("task-x") {
		t.Fatal("task should not be active after Stop")
	}
}

func TestTaskManager_Stop_NotFound(t *testing.T) {
	tm := NewTaskManager(nil)

	resp := tm.Stop(&agentpb.StopRequest{TaskId: "nonexistent"})

	if resp.Status != agentpb.Status_NOT_FOUND {
		t.Fatalf("expected NOT_FOUND, got %v", resp.Status)
	}
	if resp.Reason == "" {
		t.Fatal("expected non-empty reason for NOT_FOUND")
	}
}

func TestTaskManager_DurationAutoStop(t *testing.T) {
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := NewFakeClock(start)
	tm := NewTaskManager(clk)

	tm.Start(&agentpb.CaptureTask{
		TaskId:          "timed-task",
		TargetPod:       "pod-1",
		DurationSeconds: 60,
	})

	if !tm.IsActive("timed-task") {
		t.Fatal("task should be active before duration elapses")
	}

	// Advance just under the duration.
	clk.Advance(59 * time.Second)
	if !tm.IsActive("timed-task") {
		t.Fatal("task should still be active before 60s")
	}

	// Advance past the duration.
	clk.Advance(2 * time.Second)
	if tm.IsActive("timed-task") {
		t.Fatal("task should be auto-stopped after duration elapses")
	}
}

func TestTaskManager_ActiveTaskIDs(t *testing.T) {
	tm := NewTaskManager(nil)
	tm.Start(&agentpb.CaptureTask{TaskId: "b", TargetPod: "p"})
	tm.Start(&agentpb.CaptureTask{TaskId: "a", TargetPod: "p"})
	tm.Start(&agentpb.CaptureTask{TaskId: "c", TargetPod: "p"})

	ids := tm.ActiveTaskIDs()
	if len(ids) != 3 {
		t.Fatalf("expected 3 active tasks, got %d", len(ids))
	}
	// Should be sorted.
	if ids[0] != "a" || ids[1] != "b" || ids[2] != "c" {
		t.Fatalf("expected sorted [a b c], got %v", ids)
	}
}

func TestTaskManager_TaskIDForSession_PodMatch(t *testing.T) {
	tm := NewTaskManager(nil)
	tm.Start(&agentpb.CaptureTask{TaskId: "task-pod", TargetPod: "my-pod"})

	s := session.NewNTRIPSession("sess1", "mount", "user", "1.2.3.4", 5000, time.Now())
	s.ServerPod = "my-pod"

	taskID, ok := tm.TaskIDForSession(s)
	if !ok {
		t.Fatal("expected a match")
	}
	if taskID != "task-pod" {
		t.Fatalf("expected task-pod, got %q", taskID)
	}
}

func TestTaskManager_TaskIDForSession_NoMatch(t *testing.T) {
	tm := NewTaskManager(nil)
	tm.Start(&agentpb.CaptureTask{TaskId: "task-pod", TargetPod: "other-pod"})

	s := session.NewNTRIPSession("sess1", "mount", "user", "1.2.3.4", 5000, time.Now())
	s.ServerPod = "my-pod"

	_, ok := tm.TaskIDForSession(s)
	if ok {
		t.Fatal("expected no match")
	}
}

func TestTaskManager_TaskIDForSession_MostSpecific(t *testing.T) {
	tm := NewTaskManager(nil)
	// A namespace-scoped task.
	tm.Start(&agentpb.CaptureTask{TaskId: "task-ns", TargetNamespace: "default"})
	// A pod-scoped task (more specific).
	tm.Start(&agentpb.CaptureTask{TaskId: "task-pod", TargetPod: "my-pod"})

	s := session.NewNTRIPSession("sess1", "mount", "user", "1.2.3.4", 5000, time.Now())
	s.ServerPod = "my-pod"

	taskID, ok := tm.TaskIDForSession(s)
	if !ok {
		t.Fatal("expected a match")
	}
	if taskID != "task-pod" {
		t.Fatalf("expected most specific task-pod, got %q", taskID)
	}
}

func TestTaskManager_TaskIDForSession_NilSession(t *testing.T) {
	tm := NewTaskManager(nil)
	_, ok := tm.TaskIDForSession(nil)
	if ok {
		t.Fatal("expected no match for nil session")
	}
}

func TestTaskManager_StopCancelsTimer(t *testing.T) {
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := NewFakeClock(start)
	tm := NewTaskManager(clk)

	tm.Start(&agentpb.CaptureTask{
		TaskId:          "timer-cancel",
		TargetPod:       "pod",
		DurationSeconds: 60,
	})

	// Manually stop before duration elapses.
	tm.Stop(&agentpb.StopRequest{TaskId: "timer-cancel"})

	// Advance past the duration — should not panic or re-stop anything.
	clk.Advance(120 * time.Second)

	if tm.IsActive("timer-cancel") {
		t.Fatal("task should remain stopped")
	}
}

func TestTaskManager_Start_ExportOptions(t *testing.T) {
	tm := NewTaskManager(nil)

	resp := tm.Start(&agentpb.CaptureTask{
		TaskId:    "export-task",
		TargetPod: "pod",
		Export: &agentpb.ExportOptions{
			ExportPcap:   true,
			ExportParsed: true,
			CosBucket:    "my-bucket",
		},
	})

	if !resp.Accepted {
		t.Fatalf("expected accepted, got rejected: %s", resp.Reason)
	}
}
