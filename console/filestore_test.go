// Package console — filestore_test.go
package console

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewFileStore(t *testing.T) {
	tmpDir := t.TempDir()
	fs, err := NewFileStore(tmpDir)
	assert.NoError(t, err)
	assert.NotNil(t, fs)

	// Check if all subdirs are created
	subdirs := []string{"sessions", "events", "tasks", "agents"}
	for _, subdir := range subdirs {
		_, err := os.Stat(filepath.Join(tmpDir, subdir))
		assert.NoError(t, err)
	}
}

func TestFileStore_SessionCRUD(t *testing.T) {
	tmpDir := t.TempDir()
	fs, _ := NewFileStore(tmpDir)

	s1 := &SessionRecord{
		SessionID:  "sess-1",
		TaskID:     "task-1",
		Mountpoint: "MOUNT-A",
		Username:   "user1",
		NTRIPVer:   "1.0",
		ClientIP:   "192.168.1.100",
		StartTime:  time.Now().Truncate(time.Millisecond).UTC(),
		Closed:     false,
		Score:      95,
	}

	// 1. Get empty
	assert.Nil(t, fs.GetSession("sess-1"))

	// 2. Save
	fs.SaveSession(s1)

	// 3. Get and compare
	s1Ret := fs.GetSession("sess-1")
	assert.NotNil(t, s1Ret)
	assert.Equal(t, s1.SessionID, s1Ret.SessionID)
	assert.Equal(t, s1.Mountpoint, s1Ret.Mountpoint)
	assert.Equal(t, s1.StartTime, s1Ret.StartTime.UTC())
	assert.Equal(t, s1.Closed, s1Ret.Closed)

	// 4. Update
	s1.Closed = true
	s1.CloseTime = time.Now().Truncate(time.Millisecond).UTC()
	s1.DurationMs = 120000
	fs.SaveSession(s1)

	s1Ret2 := fs.GetSession("sess-1")
	assert.NotNil(t, s1Ret2)
	assert.True(t, s1Ret2.Closed)
	assert.Equal(t, s1.CloseTime, s1Ret2.CloseTime.UTC())
	assert.Equal(t, int64(120000), s1Ret2.DurationMs)
}

func TestFileStore_ListSessionsWithFilter(t *testing.T) {
	tmpDir := t.TempDir()
	fs, _ := NewFileStore(tmpDir)

	baseTime := time.Now().Truncate(time.Second).UTC()
	s1 := &SessionRecord{
		SessionID:  "sess-1",
		TaskID:     "task-1",
		Mountpoint: "MOUNT-A",
		Username:   "user1",
		ClientIP:   "192.168.1.1",
		StartTime:  baseTime.Add(-10 * time.Second),
		Closed:     false,
		Score:      90,
	}
	s2 := &SessionRecord{
		SessionID:  "sess-2",
		TaskID:     "task-1",
		Mountpoint: "MOUNT-B",
		Username:   "user2",
		ClientIP:   "192.168.1.2",
		StartTime:  baseTime.Add(-5 * time.Second),
		Closed:     true,
		Score:      60,
	}
	s3 := &SessionRecord{
		SessionID:  "sess-3",
		TaskID:     "task-2",
		Mountpoint: "MOUNT-A",
		Username:   "user1",
		ClientIP:   "192.168.1.3",
		StartTime:  baseTime,
		Closed:     true,
		Score:      80,
	}

	fs.SaveSession(s1)
	fs.SaveSession(s2)
	fs.SaveSession(s3)

	// Filter by TaskID
	list, total := fs.ListSessions(SessionFilter{TaskID: "task-1"})
	assert.Equal(t, 2, total)
	assert.Len(t, list, 2)
	assert.Equal(t, "sess-2", list[0].SessionID) // Sort: s2 is newer than s1

	// Filter by Username
	list, total = fs.ListSessions(SessionFilter{Username: "user1"})
	assert.Equal(t, 2, total)
	assert.Equal(t, "sess-3", list[0].SessionID) // Sort: s3 is newer than s1

	// Filter by Closed
	closedTrue := true
	list, total = fs.ListSessions(SessionFilter{Closed: &closedTrue})
	assert.Equal(t, 2, total)

	closedFalse := false
	list, total = fs.ListSessions(SessionFilter{Closed: &closedFalse})
	assert.Equal(t, 1, total)
	assert.Equal(t, "sess-1", list[0].SessionID)

	// Filter by Min/Max Score
	minScore := int32(70)
	maxScore := int32(85)
	list, total = fs.ListSessions(SessionFilter{MinScore: &minScore, MaxScore: &maxScore})
	assert.Equal(t, 1, total)
	assert.Equal(t, "sess-3", list[0].SessionID)
}

func TestFileStore_ListSessionsPagination(t *testing.T) {
	tmpDir := t.TempDir()
	fs, _ := NewFileStore(tmpDir)

	baseTime := time.Now().Truncate(time.Second).UTC()
	for i := 1; i <= 5; i++ {
		fs.SaveSession(&SessionRecord{
			SessionID:  fmt.Sprintf("sess-%d", i),
			TaskID:     "task-1",
			StartTime:  baseTime.Add(time.Duration(i) * time.Second),
			Closed:     true,
		})
	}

	// Limit = 2, Offset = 0
	list, total := fs.ListSessions(SessionFilter{Limit: 2, Offset: 0})
	assert.Equal(t, 5, total)
	assert.Len(t, list, 2)
	assert.Equal(t, "sess-5", list[0].SessionID)
	assert.Equal(t, "sess-4", list[1].SessionID)

	// Limit = 2, Offset = 2
	list, total = fs.ListSessions(SessionFilter{Limit: 2, Offset: 2})
	assert.Equal(t, 5, total)
	assert.Len(t, list, 2)
	assert.Equal(t, "sess-3", list[0].SessionID)
	assert.Equal(t, "sess-2", list[1].SessionID)

	// Limit = 2, Offset = 4
	list, total = fs.ListSessions(SessionFilter{Limit: 2, Offset: 4})
	assert.Equal(t, 5, total)
	assert.Len(t, list, 1)
	assert.Equal(t, "sess-1", list[0].SessionID)

	// Offset out of bounds
	list, total = fs.ListSessions(SessionFilter{Limit: 2, Offset: 10})
	assert.Equal(t, 5, total)
	assert.Nil(t, list)
}

func TestFileStore_EventTimeline(t *testing.T) {
	tmpDir := t.TempDir()
	fs, _ := NewFileStore(tmpDir)

	sessID := "sess-123"

	// List empty
	assert.Nil(t, fs.ListEvents(sessID))

	e1 := &SessionEventRecord{
		TaskID:      "task-1",
		SessionID:   sessID,
		TimestampNs: 1000,
		Timestamp:   time.Unix(0, 1000).UTC(),
		EventType:   "auth",
		EventData: AuthEventData{
			Method:     "basic",
			Success:    true,
			HTTPStatus: 200,
			Username:   "admin",
		},
	}
	e2 := &SessionEventRecord{
		TaskID:      "task-1",
		SessionID:   sessID,
		TimestampNs: 2000,
		Timestamp:   time.Unix(0, 2000).UTC(),
		EventType:   "gga",
		EventData: GGAEventData{
			Latitude:   31.2,
			Longitude:  121.4,
			FixQuality: 4,
			NumSats:    12,
		},
	}
	e3 := &SessionEventRecord{
		TaskID:      "task-1",
		SessionID:   sessID,
		TimestampNs: 1500, // Insert in middle to test sorting
		Timestamp:   time.Unix(0, 1500).UTC(),
		EventType:   "rtcm",
		EventData: RTCMEventData{
			MessageType: 1005,
			Size:        120,
			CRCValid:    true,
		},
	}

	fs.RecordEvent(e1)
	fs.RecordEvent(e2)
	fs.RecordEvent(e3)

	evts := fs.ListEvents(sessID)
	assert.Len(t, evts, 3)

	// Check sorting (1000, 1500, 2000)
	assert.Equal(t, int64(1000), evts[0].TimestampNs)
	assert.Equal(t, int64(1500), evts[1].TimestampNs)
	assert.Equal(t, int64(2000), evts[2].TimestampNs)

	// Check type reconstruction
	assert.Equal(t, "auth", evts[0].EventType)
	authData, ok := evts[0].EventData.(AuthEventData)
	assert.True(t, ok)
	assert.Equal(t, "admin", authData.Username)

	assert.Equal(t, "rtcm", evts[1].EventType)
	rtcmData, ok := evts[1].EventData.(RTCMEventData)
	assert.True(t, ok)
	assert.Equal(t, int32(1005), rtcmData.MessageType)

	assert.Equal(t, "gga", evts[2].EventType)
	ggaData, ok := evts[2].EventData.(GGAEventData)
	assert.True(t, ok)
	assert.Equal(t, 31.2, ggaData.Latitude)
}

func TestFileStore_TaskCRUD(t *testing.T) {
	tmpDir := t.TempDir()
	fs, _ := NewFileStore(tmpDir)

	t1 := &Task{
		ID:              "task-1",
		TargetPod:       "pod-a",
		TargetNamespace: "default",
		Status:          TaskStatusRunning,
		CreatedAt:       time.Now().Truncate(time.Second).UTC(),
	}
	t2 := &Task{
		ID:              "task-2",
		TargetPod:       "pod-b",
		TargetNamespace: "default",
		Status:          TaskStatusStopped,
		CreatedAt:       time.Now().Add(5 * time.Second).Truncate(time.Second).UTC(),
	}

	// 1. Get empty
	assert.Nil(t, fs.GetTask("task-1"))

	// 2. Save and Get
	fs.SaveTask(t1)
	t1Ret := fs.GetTask("task-1")
	assert.NotNil(t, t1Ret)
	assert.Equal(t, t1.TargetPod, t1Ret.TargetPod)
	assert.Equal(t, t1.CreatedAt, t1Ret.CreatedAt.UTC())

	// 3. List
	fs.SaveTask(t2)
	list := fs.ListTasks()
	assert.Len(t, list, 2)
	assert.Equal(t, "task-2", list[0].ID) // Newest first
}

func TestFileStore_AgentCRUD(t *testing.T) {
	tmpDir := t.TempDir()
	fs, _ := NewFileStore(tmpDir)

	a1 := &Agent{
		NodeName:     "node-1",
		AgentVersion: "v1.0.0",
		ConnectedAt:  time.Now().Truncate(time.Second).UTC(),
	}
	a2 := &Agent{
		NodeName:     "node-2",
		AgentVersion: "v1.0.0",
		ConnectedAt:  time.Now().Truncate(time.Second).UTC(),
	}

	// 1. Get empty
	assert.Nil(t, fs.GetAgent("node-1"))

	// 2. Save and Get
	fs.UpsertAgent(a1)
	a1Ret := fs.GetAgent("node-1")
	assert.NotNil(t, a1Ret)
	assert.Equal(t, a1.AgentVersion, a1Ret.AgentVersion)
	assert.False(t, a1Ret.LastStatusAt.IsZero())

	// 3. List
	fs.UpsertAgent(a2)
	list := fs.ListAgents()
	assert.Len(t, list, 2)
	assert.Equal(t, "node-1", list[0].NodeName) // Sorted by node name ascending
}

func TestFileStore_Aggregates(t *testing.T) {
	tmpDir := t.TempDir()
	fs, _ := NewFileStore(tmpDir)

	fs.SaveSession(&SessionRecord{SessionID: "sess-1", TaskID: "task-1", Closed: false})
	fs.SaveSession(&SessionRecord{SessionID: "sess-2", TaskID: "task-1", Closed: true})
	fs.SaveSession(&SessionRecord{SessionID: "sess-3", TaskID: "task-2", Closed: false})

	assert.Equal(t, 2, fs.ActiveSessionCount())
	assert.Equal(t, 2, fs.SessionCountByTask("task-1"))
	assert.Equal(t, 1, fs.SessionCountByTask("task-2"))
	assert.Equal(t, 0, fs.SessionCountByTask("task-nonexistent"))
}

func TestFileStore_DeleteAndCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	fs, _ := NewFileStore(tmpDir)

	now := time.Now().Truncate(time.Second).UTC()

	s1 := &SessionRecord{SessionID: "sess-old", Closed: true, StartTime: now.Add(-10 * 24 * time.Hour)}
	s2 := &SessionRecord{SessionID: "sess-new", Closed: true, StartTime: now.Add(-1 * 24 * time.Hour)}

	fs.SaveSession(s1)
	fs.SaveSession(s2)

	fs.RecordEvent(&SessionEventRecord{SessionID: "sess-old", EventType: "auth"})
	fs.RecordEvent(&SessionEventRecord{SessionID: "sess-new", EventType: "auth"})

	assert.FileExists(t, filepath.Join(tmpDir, "sessions", "sess-old.json"))
	assert.FileExists(t, filepath.Join(tmpDir, "events", "sess-old.events.jsonl"))

	err := fs.DeleteSession("sess-old")
	assert.NoError(t, err)

	assert.NoFileExists(t, filepath.Join(tmpDir, "sessions", "sess-old.json"))
	assert.NoFileExists(t, filepath.Join(tmpDir, "events", "sess-old.events.jsonl"))

	fs.SaveSession(s1)
	fs.RecordEvent(&SessionEventRecord{SessionID: "sess-old", EventType: "auth"})

	threshold := now.Add(-5 * 24 * time.Hour)
	count, err := fs.CleanupExpired(threshold)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)

	assert.NoFileExists(t, filepath.Join(tmpDir, "sessions", "sess-old.json"))
	assert.FileExists(t, filepath.Join(tmpDir, "sessions", "sess-new.json"))
}
