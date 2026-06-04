// Package console — api_test.go
//
// Integration tests for the REST API using net/http/httptest.
package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func setupAPI(t *testing.T) *APIHandler {
	t.Helper()
	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	return NewAPIHandler(store, handler, hub, reporter)
}

func TestAPIHealth(t *testing.T) {
	api := setupAPI(t)
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Errorf("status = %v", body["status"])
	}
}

func TestAPIListTasksEmpty(t *testing.T) {
	api := setupAPI(t)
	req := httptest.NewRequest("GET", "/api/v1/tasks", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	var body listResponse
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 0 {
		t.Errorf("total = %d, want 0", body.Total)
	}
}

func TestAPICreateAndGetTask(t *testing.T) {
	api := setupAPI(t)

	// Create task.
	body := `{"target_pod":"ds-pod-7","target_namespace":"gnss-prod","duration_seconds":3600}`
	req := httptest.NewRequest("POST", "/api/v1/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", w.Code)
	}

	var createResp map[string]any
	json.Unmarshal(w.Body.Bytes(), &createResp)
	taskID := createResp["task_id"].(string)
	if taskID == "" {
		t.Fatal("empty task_id")
	}

	// Get task.
	req = httptest.NewRequest("GET", "/api/v1/tasks/"+taskID, nil)
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("get status = %d, want 200", w.Code)
	}
}

func TestAPICreateTaskInvalidBody(t *testing.T) {
	api := setupAPI(t)
	req := httptest.NewRequest("POST", "/api/v1/tasks", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPICreateTaskMissingTarget(t *testing.T) {
	api := setupAPI(t)
	body := `{"duration_seconds":3600}`
	req := httptest.NewRequest("POST", "/api/v1/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPIGetTaskNotFound(t *testing.T) {
	api := setupAPI(t)
	req := httptest.NewRequest("GET", "/api/v1/tasks/nonexistent", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAPIStopTask(t *testing.T) {
	api := setupAPI(t)

	// Create then stop.
	body := `{"target_pod":"ds-pod-7","duration_seconds":60}`
	req := httptest.NewRequest("POST", "/api/v1/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	var createResp map[string]any
	json.Unmarshal(w.Body.Bytes(), &createResp)
	taskID := createResp["task_id"].(string)

	req = httptest.NewRequest("DELETE", "/api/v1/tasks/"+taskID, nil)
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestAPIListSessionsEmpty(t *testing.T) {
	api := setupAPI(t)
	req := httptest.NewRequest("GET", "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestAPIGetSessionNotFound(t *testing.T) {
	api := setupAPI(t)
	req := httptest.NewRequest("GET", "/api/v1/sessions/nonexistent", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAPIListSessionsWithFilter(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	api := NewAPIHandler(store, handler, hub, reporter)

	store.SaveSession(&SessionRecord{
		SessionID:  "s1",
		Mountpoint: "MOUNT-A",
		Username:   "alice",
		StartTime:  time.Now(),
		Score:      90,
	})
	store.SaveSession(&SessionRecord{
		SessionID:  "s2",
		Mountpoint: "MOUNT-B",
		Username:   "bob",
		StartTime:  time.Now(),
		Score:      50,
	})

	req := httptest.NewRequest("GET", "/api/v1/sessions?mountpoint=MOUNT-A", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	var body listResponse
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 1 {
		t.Errorf("total = %d, want 1", body.Total)
	}
}

func TestAPIGetSessionEvents(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	api := NewAPIHandler(store, handler, hub, reporter)

	store.RecordEvent(&SessionEventRecord{
		SessionID: "s1", TimestampNs: 1000, EventType: "auth",
	})
	store.RecordEvent(&SessionEventRecord{
		SessionID: "s1", TimestampNs: 2000, EventType: "gga",
	})

	req := httptest.NewRequest("GET", "/api/v1/sessions/s1/events", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	var body listResponse
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 2 {
		t.Errorf("total = %d, want 2", body.Total)
	}
}

func TestAPIGetSessionReport(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	api := NewAPIHandler(store, handler, hub, reporter)

	store.SaveSession(&SessionRecord{
		SessionID:      "s1",
		Mountpoint:     "MOUNT-A",
		Score:          85,
		LoginScore:     100,
		GGAScore:       90,
		RTCMScore:      80,
		NetworkScore:   75,
		StabilityScore: 85,
	})

	// HTML format.
	req := httptest.NewRequest("GET", "/api/v1/sessions/s1/report", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
	if !strings.Contains(w.Body.String(), "MOUNT-A") {
		t.Error("report missing mountpoint")
	}

	// JSON format.
	req = httptest.NewRequest("GET", "/api/v1/sessions/s1/report?format=json", nil)
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	var report ReportJSON
	json.Unmarshal(w.Body.Bytes(), &report)
	if report.Score != 85 {
		t.Errorf("score = %d, want 85", report.Score)
	}
}

func TestAPIGetSessionReportNotFound(t *testing.T) {
	api := setupAPI(t)
	req := httptest.NewRequest("GET", "/api/v1/sessions/nonexistent/report", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAPIListAgents(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	api := NewAPIHandler(store, handler, hub, reporter)

	store.UpsertAgent(&Agent{NodeName: "node-1", AgentVersion: "v1.0"})
	store.UpsertAgent(&Agent{NodeName: "node-2", AgentVersion: "v1.1"})

	req := httptest.NewRequest("GET", "/api/v1/agents", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	var body listResponse
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 2 {
		t.Errorf("total = %d, want 2", body.Total)
	}
}

func TestAPIGetAgentStatusNotFound(t *testing.T) {
	api := setupAPI(t)
	req := httptest.NewRequest("GET", "/api/v1/agents/nonexistent/status", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAPIGetTopology(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	api := NewAPIHandler(store, handler, hub, reporter)

	store.UpsertAgent(&Agent{
		NodeName:    "node-1",
		ManagedPods: []PodInfo{{PodName: "pod-a"}, {PodName: "pod-b"}},
	})

	req := httptest.NewRequest("GET", "/api/v1/topology", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	var topo TopologyView
	json.Unmarshal(w.Body.Bytes(), &topo)
	if len(topo.Nodes) != 1 {
		t.Errorf("nodes = %d, want 1", len(topo.Nodes))
	}
	if topo.Nodes[0].PodCount != 2 {
		t.Errorf("pod count = %d, want 2", topo.Nodes[0].PodCount)
	}
}

func TestAPIWSUpgradeNoUpgradeHeader(t *testing.T) {
	api := setupAPI(t)
	req := httptest.NewRequest("GET", "/api/v1/ws/sessions/s1", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPICreateTaskWithFilters(t *testing.T) {
	api := setupAPI(t)

	body := `{
		"target_pod":"ds-pod-7",
		"duration_seconds":3600,
		"mountpoints":["MOUNT-A","MOUNT-B"],
		"usernames":["user001"],
		"message_types":[1074,1124],
		"export_pcap":true,
		"export_parsed":true
	}`
	req := httptest.NewRequest("POST", "/api/v1/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", w.Code)
	}
}

func TestAPIListSessionsPaginationParams(t *testing.T) {
	api := setupAPI(t)
	req := httptest.NewRequest("GET", "/api/v1/sessions?limit=10&offset=0&min_score=50&max_score=100", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestAPISessionReportUnsupportedFormat(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	api := NewAPIHandler(store, handler, hub, reporter)

	store.SaveSession(&SessionRecord{SessionID: "s1"})

	req := httptest.NewRequest("GET", "/api/v1/sessions/s1/report?format=pdf", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPIUpdateTaskFilter(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	api := NewAPIHandler(store, handler, hub, reporter)

	// Create running task.
	taskID := "task-running"
	task := &Task{
		ID:        taskID,
		Status:    TaskStatusRunning,
		CreatedAt: time.Now(),
	}
	store.SaveTask(task)

	// Update filter.
	body := `{"mountpoints":["MOUNT-NEW"],"usernames":["user-new"],"message_types":[1005]}`
	req := httptest.NewRequest("POST", "/api/v1/tasks/"+taskID+"/filter", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var updatedTask Task
	json.Unmarshal(w.Body.Bytes(), &updatedTask)
	assert := func(cond bool, msg string) {
		if !cond {
			t.Error(msg)
		}
	}
	assert(updatedTask.NtripFilter != nil, "NtripFilter should not be nil")
	assert(updatedTask.NtripFilter.Mountpoints[0] == "MOUNT-NEW", "Mountpoint mismatch")

	// Try updating non-existent task.
	req = httptest.NewRequest("POST", "/api/v1/tasks/nonexistent/filter", strings.NewReader(body))
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	assert(w.Code == http.StatusNotFound, "should be 404 for nonexistent task")

	// Try updating stopped task.
	taskStopped := "task-stopped"
	store.SaveTask(&Task{ID: taskStopped, Status: TaskStatusStopped})
	req = httptest.NewRequest("POST", "/api/v1/tasks/"+taskStopped+"/filter", strings.NewReader(body))
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	assert(w.Code == http.StatusBadRequest, "should be 400 for non-running task")
}

func TestAPIStorageStatusAndCleanup(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	api := NewAPIHandler(store, handler, hub, reporter)

	// Check status
	req := httptest.NewRequest("GET", "/api/v1/storage/status", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var status map[string]any
	json.Unmarshal(w.Body.Bytes(), &status)
	if status["type"] != "memory" {
		t.Errorf("type = %v, want memory", status["type"])
	}

	// Trigger cleanup (MemoryStore does not implement CleanupExpired, should fail or Bad Request)
	req = httptest.NewRequest("POST", "/api/v1/storage/cleanup?days=5", nil)
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("cleanup status = %d, want 400 for memory store", w.Code)
	}
}

func TestAPIAnalytics(t *testing.T) {
	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	api := NewAPIHandler(store, handler, hub, reporter)

	// Add sessions with different scores
	store.SaveSession(&SessionRecord{
		SessionID: "s1", Closed: true, Score: 95, StartTime: time.Now(),
	})
	store.SaveSession(&SessionRecord{
		SessionID: "s2", Closed: true, Score: 75, StartTime: time.Now(),
		Issues: []SessionIssue{{Category: "RTCM", Severity: "warn", Description: "lost frames"}},
	})
	store.SaveSession(&SessionRecord{
		SessionID: "s3", Closed: true, Score: 30, StartTime: time.Now(),
		Issues: []SessionIssue{{Category: "NETWORK", Severity: "error", Description: "high rtt"}},
	})

	req := httptest.NewRequest("GET", "/api/v1/analytics", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var summary AnalyticsSummary
	json.Unmarshal(w.Body.Bytes(), &summary)

	assert := func(cond bool, msg string) {
		if !cond {
			t.Error(msg)
		}
	}

	assert(summary.TotalSessions == 3, "total sessions mismatch")
	assert(summary.AverageScore == (95.0+75.0+30.0)/3.0, "average score mismatch")
	assert(summary.ScoreDistribution["healthy"] == 1, "healthy count mismatch")
	assert(summary.ScoreDistribution["degraded"] == 1, "degraded count mismatch")
	assert(summary.ScoreDistribution["critical"] == 1, "critical count mismatch")
	assert(len(summary.TopIssues) == 2, "top issues count mismatch")
	assert(len(summary.WorstSessions) == 3, "worst sessions count mismatch")
	assert(summary.WorstSessions[0].SessionID == "s3", "worst session should be s3 first")
}
