// Package console — store.go
//
// SessionStore defines the persistence contract for the Console, and
// MemoryStore provides a thread-safe in-memory implementation suitable
// for development and testing. Production deployments would replace this
// with a ClickHouse/TimescaleDB-backed implementation.
package console

import (
	"sort"
	"sync"
	"time"
)

// SessionStore is the persistence interface for sessions, events, tasks,
// and agents. All methods must be safe for concurrent use.
type SessionStore interface {
	// --- Sessions ---

	// SaveSession upserts a session record (e.g., on session close with summary).
	SaveSession(rec *SessionRecord)

	// GetSession returns a single session by ID, or nil if not found.
	GetSession(id string) *SessionRecord

	// ListSessions returns sessions matching the filter, ordered by start
	// time descending. The total count of matching sessions is also returned.
	ListSessions(f SessionFilter) ([]*SessionRecord, int)

	// --- Events ---

	// RecordEvent appends an event to the session's timeline.
	RecordEvent(rec *SessionEventRecord)

	// ListEvents returns the event timeline for a session, ordered by
	// timestamp ascending.
	ListEvents(sessionID string) []*SessionEventRecord

	// --- Tasks ---

	// SaveTask upserts a task.
	SaveTask(t *Task)

	// GetTask returns a task by ID, or nil.
	GetTask(id string) *Task

	// ListTasks returns all tasks ordered by creation time descending.
	ListTasks() []*Task

	// --- Agents ---

	// UpsertAgent registers or updates an Agent's state.
	UpsertAgent(a *Agent)

	// GetAgent returns an Agent by node name, or nil.
	GetAgent(nodeName string) *Agent

	// ListAgents returns all known Agents.
	ListAgents() []*Agent

	// --- Aggregate queries ---

	// ActiveSessionCount returns the number of sessions where Closed == false.
	ActiveSessionCount() int

	// SessionCountByTask returns the number of sessions for a given task.
	SessionCountByTask(taskID string) int
}

// MemoryStore is a thread-safe in-memory implementation of SessionStore.
// Events and sessions are stored in append-only slices; filtering is done
// by linear scan. This is acceptable for development and moderate-scale
// testing (thousands of sessions). Production should use a database.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionRecord        // sessionID → record
	events   map[string][]*SessionEventRecord // sessionID → events
	tasks    map[string]*Task                 // taskID → task
	agents   map[string]*Agent                // nodeName → agent
}

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*SessionRecord),
		events:   make(map[string][]*SessionEventRecord),
		tasks:    make(map[string]*Task),
		agents:   make(map[string]*Agent),
	}
}

// Compile-time assertion.
var _ SessionStore = (*MemoryStore)(nil)

func (m *MemoryStore) SaveSession(rec *SessionRecord) {
	if rec == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[rec.SessionID] = rec
}

func (m *MemoryStore) GetSession(id string) *SessionRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

func (m *MemoryStore) ListSessions(f SessionFilter) ([]*SessionRecord, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect matching sessions.
	var matched []*SessionRecord
	for _, s := range m.sessions {
		if !m.matchSession(s, f) {
			continue
		}
		matched = append(matched, s)
	}

	// Sort by start time descending.
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].StartTime.After(matched[j].StartTime)
	})

	total := len(matched)

	// Apply pagination.
	if f.Offset > 0 {
		if f.Offset >= len(matched) {
			return nil, total
		}
		matched = matched[f.Offset:]
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > len(matched) {
		limit = len(matched)
	}
	return matched[:limit], total
}

func (m *MemoryStore) matchSession(s *SessionRecord, f SessionFilter) bool {
	if f.TaskID != "" && s.TaskID != f.TaskID {
		return false
	}
	if f.Mountpoint != "" && s.Mountpoint != f.Mountpoint {
		return false
	}
	if f.Username != "" && s.Username != f.Username {
		return false
	}
	if f.ServerPod != "" && s.ServerPod != f.ServerPod {
		return false
	}
	if f.NodeName != "" && s.NodeName != f.NodeName {
		return false
	}
	if f.Closed != nil {
		if *f.Closed && !s.Closed {
			return false
		}
		if !*f.Closed && s.Closed {
			return false
		}
	}
	if f.MinScore != nil && s.Score < *f.MinScore {
		return false
	}
	if f.MaxScore != nil && s.Score > *f.MaxScore {
		return false
	}
	if f.Since != nil && s.StartTime.Before(*f.Since) {
		return false
	}
	if f.Until != nil && s.StartTime.After(*f.Until) {
		return false
	}
	return true
}

func (m *MemoryStore) RecordEvent(rec *SessionEventRecord) {
	if rec == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[rec.SessionID] = append(m.events[rec.SessionID], rec)
}

func (m *MemoryStore) ListEvents(sessionID string) []*SessionEventRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	evts := m.events[sessionID]
	if len(evts) == 0 {
		return nil
	}
	// Return a copy sorted by timestamp ascending.
	out := make([]*SessionEventRecord, len(evts))
	copy(out, evts)
	sort.Slice(out, func(i, j int) bool {
		return out[i].TimestampNs < out[j].TimestampNs
	})
	return out
}

func (m *MemoryStore) SaveTask(t *Task) {
	if t == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks[t.ID] = t
}

func (m *MemoryStore) GetTask(id string) *Task {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tasks[id]
}

func (m *MemoryStore) ListTasks() []*Task {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

func (m *MemoryStore) UpsertAgent(a *Agent) {
	if a == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a.LastStatusAt = time.Now()
	m.agents[a.NodeName] = a
}

func (m *MemoryStore) GetAgent(nodeName string) *Agent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.agents[nodeName]
}

func (m *MemoryStore) ListAgents() []*Agent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Agent, 0, len(m.agents))
	for _, a := range m.agents {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].NodeName < out[j].NodeName
	})
	return out
}

func (m *MemoryStore) ActiveSessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, s := range m.sessions {
		if !s.Closed {
			n++
		}
	}
	return n
}

func (m *MemoryStore) SessionCountByTask(taskID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, s := range m.sessions {
		if s.TaskID == taskID {
			n++
		}
	}
	return n
}
