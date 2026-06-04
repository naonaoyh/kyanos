// Package console — filestore.go
//
// FileStore is a thread-safe, local file-based implementation of SessionStore.
// Sessions, Tasks, and Agents are stored as individual JSON files under their
// respective subdirectories. Session events are stored as line-delimited
// JSON (JSON Lines) to support high-performance incremental append operations.
package console

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileStore implements the SessionStore interface.
type FileStore struct {
	mu  sync.RWMutex
	dir string
}

// NewFileStore creates a new FileStore, automatically creating all required
// directory structures.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("storage directory cannot be empty")
	}

	subdirs := []string{"sessions", "events", "tasks", "agents"}
	for _, subdir := range subdirs {
		path := filepath.Join(dir, subdir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	}

	return &FileStore{dir: dir}, nil
}

// Compile-time check.
var _ SessionStore = (*FileStore)(nil)

// GetDir returns the root storage directory.
func (f *FileStore) GetDir() string {
	return f.dir
}

// escapeFilename prevents invalid file system characters by path-escaping identifiers.
func escapeFilename(name string) string {
	return url.PathEscape(name)
}

// --- Sessions ---

func (f *FileStore) SaveSession(rec *SessionRecord) {
	if rec == nil || rec.SessionID == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	filename := filepath.Join(f.dir, "sessions", escapeFilename(rec.SessionID)+".json")
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = os.WriteFile(filename, data, 0644)
}

func (f *FileStore) DeleteSession(id string) error {
	if id == "" {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	sessionFile := filepath.Join(f.dir, "sessions", escapeFilename(id)+".json")
	eventsFile := filepath.Join(f.dir, "events", escapeFilename(id)+".events.jsonl")

	err1 := os.Remove(sessionFile)
	err2 := os.Remove(eventsFile)

	if err1 != nil && !os.IsNotExist(err1) {
		return err1
	}
	if err2 != nil && !os.IsNotExist(err2) {
		return err2
	}
	return nil
}

// CleanupExpired deletes sessions starting before the given threshold time.
func (f *FileStore) CleanupExpired(before time.Time) (int, error) {
	// We read dir without holding lock across read operations to keep responsiveness.
	f.mu.RLock()
	files, err := os.ReadDir(filepath.Join(f.dir, "sessions"))
	f.mu.RUnlock()
	if err != nil {
		return 0, err
	}

	deletedCount := 0
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		path := filepath.Join(f.dir, "sessions", file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var s SessionRecord
		if err := json.Unmarshal(data, &s); err != nil {
			continue
		}

		if s.StartTime.Before(before) {
			if err := f.DeleteSession(s.SessionID); err == nil {
				deletedCount++
			}
		}
	}
	return deletedCount, nil
}

func (f *FileStore) GetSession(id string) *SessionRecord {
	if id == "" {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()

	filename := filepath.Join(f.dir, "sessions", escapeFilename(id)+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil
	}
	var rec SessionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil
	}
	return &rec
}

func (f *FileStore) ListSessions(sf SessionFilter) ([]*SessionRecord, int) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	files, err := os.ReadDir(filepath.Join(f.dir, "sessions"))
	if err != nil {
		return nil, 0
	}

	var matched []*SessionRecord
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		path := filepath.Join(f.dir, "sessions", file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var s SessionRecord
		if err := json.Unmarshal(data, &s); err != nil {
			continue
		}
		if f.matchSession(&s, sf) {
			matched = append(matched, &s)
		}
	}

	// Sort by start time descending.
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].StartTime.After(matched[j].StartTime)
	})

	total := len(matched)

	// Apply pagination.
	if sf.Offset > 0 {
		if sf.Offset >= len(matched) {
			return nil, total
		}
		matched = matched[sf.Offset:]
	}
	limit := sf.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > len(matched) {
		limit = len(matched)
	}
	return matched[:limit], total
}

func (f *FileStore) matchSession(s *SessionRecord, filter SessionFilter) bool {
	if filter.TaskID != "" && s.TaskID != filter.TaskID {
		return false
	}
	if filter.Mountpoint != "" && s.Mountpoint != filter.Mountpoint {
		return false
	}
	if filter.Username != "" && s.Username != filter.Username {
		return false
	}
	if filter.ServerPod != "" && s.ServerPod != filter.ServerPod {
		return false
	}
	if filter.NodeName != "" && s.NodeName != filter.NodeName {
		return false
	}
	if filter.Closed != nil {
		if *filter.Closed && !s.Closed {
			return false
		}
		if !*filter.Closed && s.Closed {
			return false
		}
	}
	if filter.MinScore != nil && s.Score < *filter.MinScore {
		return false
	}
	if filter.MaxScore != nil && s.Score > *filter.MaxScore {
		return false
	}
	if filter.Since != nil && s.StartTime.Before(*filter.Since) {
		return false
	}
	if filter.Until != nil && s.StartTime.After(*filter.Until) {
		return false
	}
	return true
}

// --- Events ---

func (f *FileStore) RecordEvent(rec *SessionEventRecord) {
	if rec == nil || rec.SessionID == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	filename := filepath.Join(f.dir, "events", escapeFilename(rec.SessionID)+".events.jsonl")
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_, _ = file.Write(append(data, '\n'))
}

func (f *FileStore) ListEvents(sessionID string) []*SessionEventRecord {
	if sessionID == "" {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()

	filename := filepath.Join(f.dir, "events", escapeFilename(sessionID)+".events.jsonl")
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()

	var evts []*SessionEventRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var temp struct {
			TaskID      string          `json:"task_id"`
			SessionID   string          `json:"session_id"`
			TimestampNs int64           `json:"timestamp_ns"`
			Timestamp   time.Time       `json:"timestamp"`
			PodName     string          `json:"pod_name,omitempty"`
			PodNS       string          `json:"pod_namespace,omitempty"`
			ClientIP    string          `json:"client_ip,omitempty"`
			ClientPort  uint32          `json:"client_port,omitempty"`
			EventType   string          `json:"event_type"`
			EventData   json.RawMessage `json:"event_data"`
		}

		if err := json.Unmarshal(line, &temp); err != nil {
			continue
		}

		rec := &SessionEventRecord{
			TaskID:      temp.TaskID,
			SessionID:   temp.SessionID,
			TimestampNs: temp.TimestampNs,
			Timestamp:   temp.Timestamp,
			PodName:     temp.PodName,
			PodNS:       temp.PodNS,
			ClientIP:    temp.ClientIP,
			ClientPort:  temp.ClientPort,
			EventType:   temp.EventType,
		}

		switch temp.EventType {
		case "auth":
			var d AuthEventData
			if json.Unmarshal(temp.EventData, &d) == nil {
				rec.EventData = d
			}
		case "gga":
			var d GGAEventData
			if json.Unmarshal(temp.EventData, &d) == nil {
				rec.EventData = d
			}
		case "rtcm":
			var d RTCMEventData
			if json.Unmarshal(temp.EventData, &d) == nil {
				rec.EventData = d
			}
		case "network":
			var d NetworkEventData
			if json.Unmarshal(temp.EventData, &d) == nil {
				rec.EventData = d
			}
		case "close":
			var d CloseEventData
			if json.Unmarshal(temp.EventData, &d) == nil {
				rec.EventData = d
			}
		default:
			rec.EventData = temp.EventData
		}

		evts = append(evts, rec)
	}

	sort.Slice(evts, func(i, j int) bool {
		return evts[i].TimestampNs < evts[j].TimestampNs
	})
	return evts
}

// --- Tasks ---

func (f *FileStore) SaveTask(t *Task) {
	if t == nil || t.ID == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	filename := filepath.Join(f.dir, "tasks", escapeFilename(t.ID)+".json")
	data, err := json.Marshal(t)
	if err != nil {
		return
	}
	_ = os.WriteFile(filename, data, 0644)
}

func (f *FileStore) GetTask(id string) *Task {
	if id == "" {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()

	filename := filepath.Join(f.dir, "tasks", escapeFilename(id)+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil
	}
	var t Task
	if err := json.Unmarshal(data, &t); err != nil {
		return nil
	}
	return &t
}

func (f *FileStore) ListTasks() []*Task {
	f.mu.RLock()
	defer f.mu.RUnlock()

	files, err := os.ReadDir(filepath.Join(f.dir, "tasks"))
	if err != nil {
		return nil
	}

	var out []*Task
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		path := filepath.Join(f.dir, "tasks", file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var t Task
		if err := json.Unmarshal(data, &t); err != nil {
			continue
		}
		out = append(out, &t)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// --- Agents ---

func (f *FileStore) UpsertAgent(a *Agent) {
	if a == nil || a.NodeName == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	a.LastStatusAt = time.Now()
	filename := filepath.Join(f.dir, "agents", escapeFilename(a.NodeName)+".json")
	data, err := json.Marshal(a)
	if err != nil {
		return
	}
	_ = os.WriteFile(filename, data, 0644)
}

func (f *FileStore) GetAgent(nodeName string) *Agent {
	if nodeName == "" {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()

	filename := filepath.Join(f.dir, "agents", escapeFilename(nodeName)+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil
	}
	var a Agent
	if err := json.Unmarshal(data, &a); err != nil {
		return nil
	}
	return &a
}

func (f *FileStore) ListAgents() []*Agent {
	f.mu.RLock()
	defer f.mu.RUnlock()

	files, err := os.ReadDir(filepath.Join(f.dir, "agents"))
	if err != nil {
		return nil
	}

	var out []*Agent
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		path := filepath.Join(f.dir, "agents", file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var a Agent
		if err := json.Unmarshal(data, &a); err != nil {
			continue
		}
		out = append(out, &a)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].NodeName < out[j].NodeName
	})
	return out
}

// --- Aggregates ---

func (f *FileStore) ActiveSessionCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	files, err := os.ReadDir(filepath.Join(f.dir, "sessions"))
	if err != nil {
		return 0
	}

	count := 0
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		path := filepath.Join(f.dir, "sessions", file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var s SessionRecord
		if err := json.Unmarshal(data, &s); err != nil {
			continue
		}
		if !s.Closed {
			count++
		}
	}
	return count
}

func (f *FileStore) SessionCountByTask(taskID string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	files, err := os.ReadDir(filepath.Join(f.dir, "sessions"))
	if err != nil {
		return 0
	}

	count := 0
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		path := filepath.Join(f.dir, "sessions", file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var s SessionRecord
		if err := json.Unmarshal(data, &s); err != nil {
			continue
		}
		if s.TaskID == taskID {
			count++
		}
	}
	return count
}
