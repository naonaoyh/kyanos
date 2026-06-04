// Package console — store_test.go
//
// Tests for MemoryStore: session CRUD, event recording, task management,
// agent management, filtering, and pagination.
package console

import (
	"testing"
	"time"
)

func TestMemoryStoreSaveAndGetSession(t *testing.T) {
	s := NewMemoryStore()
	rec := &SessionRecord{
		SessionID:  "sess-001",
		TaskID:     "task-1",
		Mountpoint: "MOUNT-A",
		Username:   "user001",
		ClientIP:   "10.0.0.1",
		ClientPort: 12345,
		ServerPod:  "ds-pod-7",
		StartTime:  time.Now(),
		DurationMs: 5000,
		Closed:     true,
		Score:      85,
	}
	s.SaveSession(rec)

	got := s.GetSession("sess-001")
	if got == nil {
		t.Fatal("expected session, got nil")
	}
	if got.Mountpoint != "MOUNT-A" {
		t.Errorf("mountpoint = %q, want MOUNT-A", got.Mountpoint)
	}
	if got.Score != 85 {
		t.Errorf("score = %d, want 85", got.Score)
	}
}

func TestMemoryStoreGetSessionNotFound(t *testing.T) {
	s := NewMemoryStore()
	if got := s.GetSession("nonexistent"); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestMemoryStoreSaveNilSession(t *testing.T) {
	s := NewMemoryStore()
	s.SaveSession(nil) // should not panic
}

func TestMemoryStoreListSessionsNoFilter(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()
	for i := 0; i < 5; i++ {
		s.SaveSession(&SessionRecord{
			SessionID: "sess-" + string(rune('a'+i)),
			TaskID:    "task-1",
			StartTime: now.Add(time.Duration(i) * time.Minute),
			Score:     int32(70 + i),
		})
	}
	sessions, total := s.ListSessions(SessionFilter{})
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(sessions) != 5 {
		t.Errorf("len(sessions) = %d, want 5", len(sessions))
	}
	// Verify descending order by start time.
	for i := 1; i < len(sessions); i++ {
		if sessions[i].StartTime.After(sessions[i-1].StartTime) {
			t.Error("sessions not sorted by start time descending")
		}
	}
}

func TestMemoryStoreListSessionsWithFilter(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()
	s.SaveSession(&SessionRecord{SessionID: "s1", Mountpoint: "MOUNT-A", Username: "alice", StartTime: now, Score: 90})
	s.SaveSession(&SessionRecord{SessionID: "s2", Mountpoint: "MOUNT-B", Username: "bob", StartTime: now, Score: 50})
	s.SaveSession(&SessionRecord{SessionID: "s3", Mountpoint: "MOUNT-A", Username: "alice", StartTime: now, Score: 70, Closed: true})

	// Filter by mountpoint.
	sessions, total := s.ListSessions(SessionFilter{Mountpoint: "MOUNT-A"})
	if total != 2 {
		t.Errorf("mountpoint filter: total = %d, want 2", total)
	}

	// Filter by username.
	sessions, total = s.ListSessions(SessionFilter{Username: "bob"})
	if total != 1 {
		t.Errorf("username filter: total = %d, want 1", total)
	}

	// Filter by closed status.
	closed := true
	sessions, total = s.ListSessions(SessionFilter{Closed: &closed})
	if total != 1 || len(sessions) != 1 {
		t.Errorf("closed filter: total = %d, want 1", total)
	}
	if len(sessions) > 0 && !sessions[0].Closed {
		t.Error("expected closed session")
	}

	// Filter by score range.
	minScore := int32(60)
	sessions, total = s.ListSessions(SessionFilter{MinScore: &minScore})
	if total != 2 {
		t.Errorf("minScore filter: total = %d, want 2", total)
	}
}

func TestMemoryStoreListSessionsPagination(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()
	for i := 0; i < 20; i++ {
		s.SaveSession(&SessionRecord{
			SessionID: "sess-" + string(rune('A'+i)),
			StartTime: now.Add(time.Duration(i) * time.Second),
		})
	}

	sessions, total := s.ListSessions(SessionFilter{Limit: 5})
	if total != 20 {
		t.Errorf("total = %d, want 20", total)
	}
	if len(sessions) != 5 {
		t.Errorf("len = %d, want 5", len(sessions))
	}

	sessions, total = s.ListSessions(SessionFilter{Limit: 5, Offset: 18})
	if total != 20 {
		t.Errorf("total = %d, want 20", total)
	}
	if len(sessions) != 2 {
		t.Errorf("len = %d, want 2", len(sessions))
	}

	// Offset beyond total.
	sessions, total = s.ListSessions(SessionFilter{Limit: 5, Offset: 100})
	if total != 20 {
		t.Errorf("total = %d, want 20", total)
	}
	if sessions != nil {
		t.Errorf("expected nil sessions for offset beyond total, got %d", len(sessions))
	}
}

func TestMemoryStoreRecordAndListEvents(t *testing.T) {
	s := NewMemoryStore()
	s.RecordEvent(&SessionEventRecord{
		SessionID:   "sess-001",
		TimestampNs: 1000,
		EventType:   "auth",
	})
	s.RecordEvent(&SessionEventRecord{
		SessionID:   "sess-001",
		TimestampNs: 2000,
		EventType:   "gga",
	})
	s.RecordEvent(&SessionEventRecord{
		SessionID:   "sess-001",
		TimestampNs: 1500, // out of order
		EventType:   "rtcm",
	})

	events := s.ListEvents("sess-001")
	if len(events) != 3 {
		t.Fatalf("len(events) = %d, want 3", len(events))
	}
	// Verify ascending order.
	for i := 1; i < len(events); i++ {
		if events[i].TimestampNs < events[i-1].TimestampNs {
			t.Error("events not sorted by timestamp ascending")
		}
	}
}

func TestMemoryStoreListEventsEmpty(t *testing.T) {
	s := NewMemoryStore()
	if events := s.ListEvents("nonexistent"); events != nil {
		t.Errorf("expected nil, got %d events", len(events))
	}
}

func TestMemoryStoreRecordNilEvent(t *testing.T) {
	s := NewMemoryStore()
	s.RecordEvent(nil) // should not panic
}

func TestMemoryStoreTaskCRUD(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()

	t1 := &Task{ID: "task-1", TargetPod: "pod-a", Status: TaskStatusRunning, CreatedAt: now}
	t2 := &Task{ID: "task-2", TargetPod: "pod-b", Status: TaskStatusPending, CreatedAt: now.Add(time.Second)}
	s.SaveTask(t1)
	s.SaveTask(t2)

	got := s.GetTask("task-1")
	if got == nil || got.TargetPod != "pod-a" {
		t.Errorf("GetTask(task-1) = %+v, want pod-a", got)
	}

	tasks := s.ListTasks()
	if len(tasks) != 2 {
		t.Errorf("ListTasks len = %d, want 2", len(tasks))
	}
	// Descending by creation time.
	if tasks[0].ID != "task-2" {
		t.Errorf("first task = %q, want task-2", tasks[0].ID)
	}

	if s.GetTask("nonexistent") != nil {
		t.Error("expected nil for nonexistent task")
	}
}

func TestMemoryStoreSaveNilTask(t *testing.T) {
	s := NewMemoryStore()
	s.SaveTask(nil) // should not panic
}

func TestMemoryStoreAgentCRUD(t *testing.T) {
	s := NewMemoryStore()
	a := &Agent{
		NodeName:     "node-1",
		AgentVersion: "v1.0",
		ManagedPods: []PodInfo{
			{PodName: "pod-a", Namespace: "default"},
		},
	}
	s.UpsertAgent(a)

	got := s.GetAgent("node-1")
	if got == nil {
		t.Fatal("expected agent, got nil")
	}
	if got.AgentVersion != "v1.0" {
		t.Errorf("version = %q, want v1.0", got.AgentVersion)
	}

	agents := s.ListAgents()
	if len(agents) != 1 {
		t.Errorf("ListAgents len = %d, want 1", len(agents))
	}
}

func TestMemoryStoreUpsertNilAgent(t *testing.T) {
	s := NewMemoryStore()
	s.UpsertAgent(nil) // should not panic
}

func TestMemoryStoreActiveSessionCount(t *testing.T) {
	s := NewMemoryStore()
	s.SaveSession(&SessionRecord{SessionID: "s1", Closed: false})
	s.SaveSession(&SessionRecord{SessionID: "s2", Closed: true})
	s.SaveSession(&SessionRecord{SessionID: "s3", Closed: false})

	if n := s.ActiveSessionCount(); n != 2 {
		t.Errorf("ActiveSessionCount = %d, want 2", n)
	}
}

func TestMemoryStoreSessionCountByTask(t *testing.T) {
	s := NewMemoryStore()
	s.SaveSession(&SessionRecord{SessionID: "s1", TaskID: "task-1"})
	s.SaveSession(&SessionRecord{SessionID: "s2", TaskID: "task-1"})
	s.SaveSession(&SessionRecord{SessionID: "s3", TaskID: "task-2"})

	if n := s.SessionCountByTask("task-1"); n != 2 {
		t.Errorf("SessionCountByTask(task-1) = %d, want 2", n)
	}
	if n := s.SessionCountByTask("nonexistent"); n != 0 {
		t.Errorf("SessionCountByTask(nonexistent) = %d, want 0", n)
	}
}

func TestMemoryStoreListSessionsTimeRange(t *testing.T) {
	s := NewMemoryStore()
	base := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	s.SaveSession(&SessionRecord{SessionID: "s1", StartTime: base})
	s.SaveSession(&SessionRecord{SessionID: "s2", StartTime: base.Add(time.Hour)})
	s.SaveSession(&SessionRecord{SessionID: "s3", StartTime: base.Add(2 * time.Hour)})

	since := base.Add(30 * time.Minute)
	until := base.Add(90 * time.Minute)
	_, total := s.ListSessions(SessionFilter{Since: &since, Until: &until})
	if total != 1 {
		t.Errorf("time range filter: total = %d, want 1", total)
	}
}
