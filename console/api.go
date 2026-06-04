// Package console — api.go
//
// REST API handlers for the Web Console. The API exposes:
//   - Task management: create, list, get, stop tasks
//   - Session queries: list (with filtering/pagination), get, events, report
//   - Cluster status: agents, topology
//   - WebSocket upgrade: session and task real-time subscriptions
//
// Uses Go 1.22+ net/http routing (path parameters via {param} syntax).
// All handlers return JSON. Error responses use {"error": "message"}.
package console

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"kyanos/proto/agentpb"
)

// APIHandler wraps the REST API routes. It holds references to the store,
// gRPC handler (for command dispatch), WS hub, and report generator.
type APIHandler struct {
	store    SessionStore
	grpc     *AgentServiceHandler
	hub      *WSHub
	reporter *DiagnosticReporter
	mux      *http.ServeMux
}

// NewAPIHandler creates the handler and registers all routes.
func NewAPIHandler(store SessionStore, grpc *AgentServiceHandler, hub *WSHub, reporter *DiagnosticReporter) *APIHandler {
	h := &APIHandler{
		store:    store,
		grpc:     grpc,
		hub:      hub,
		reporter: reporter,
		mux:      http.NewServeMux(),
	}
	h.registerRoutes()
	return h
}

// ServeHTTP implements http.Handler.
func (h *APIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *APIHandler) registerRoutes() {
	// Task management.
	h.mux.HandleFunc("POST /api/v1/tasks", h.createTask)
	h.mux.HandleFunc("GET /api/v1/tasks", h.listTasks)
	h.mux.HandleFunc("GET /api/v1/tasks/{id}", h.getTask)
	h.mux.HandleFunc("DELETE /api/v1/tasks/{id}", h.stopTask)
	h.mux.HandleFunc("POST /api/v1/tasks/{id}/filter", h.updateTaskFilter)

	// Session queries.
	h.mux.HandleFunc("GET /api/v1/sessions", h.listSessions)
	h.mux.HandleFunc("GET /api/v1/sessions/{id}", h.getSession)
	h.mux.HandleFunc("GET /api/v1/sessions/{id}/events", h.getSessionEvents)
	h.mux.HandleFunc("GET /api/v1/sessions/{id}/report", h.getSessionReport)

	// Cluster status.
	h.mux.HandleFunc("GET /api/v1/agents", h.listAgents)
	h.mux.HandleFunc("GET /api/v1/agents/{node}/status", h.getAgentStatus)
	h.mux.HandleFunc("GET /api/v1/topology", h.getTopology)

	// WebSocket upgrade.
	h.mux.HandleFunc("GET /api/v1/ws/sessions", h.wsSessions)
	h.mux.HandleFunc("GET /api/v1/ws/sessions/{id}", h.wsSession)
	h.mux.HandleFunc("GET /api/v1/ws/tasks/{id}", h.wsTask)

	// System & Analytics.
	h.mux.HandleFunc("GET /api/v1/storage/status", h.getStorageStatus)
	h.mux.HandleFunc("POST /api/v1/storage/cleanup", h.triggerStorageCleanup)
	h.mux.HandleFunc("GET /api/v1/analytics", h.getAnalytics)

	// Health check.
	h.mux.HandleFunc("GET /api/v1/health", h.health)
}

// --- JSON helpers ---

type errorResponse struct {
	Error string `json:"error"`
}

type listResponse struct {
	Items any `json:"items"`
	Total int `json:"total"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

// --- Task handlers ---

// createTaskRequest is the JSON body for POST /api/v1/tasks.
type createTaskRequest struct {
	TargetPod       string            `json:"target_pod"`
	TargetNamespace string            `json:"target_namespace"`
	PodLabels       map[string]string `json:"pod_labels,omitempty"`
	DurationSeconds int64             `json:"duration_seconds"`
	Mountpoints     []string          `json:"mountpoints,omitempty"`
	Usernames       []string          `json:"usernames,omitempty"`
	MessageTypes    []int32           `json:"message_types,omitempty"`
	ExportPCAP      bool              `json:"export_pcap"`
	ExportParsed    bool              `json:"export_parsed"`
	COSBucket       string            `json:"cos_bucket,omitempty"`
}

func (h *APIHandler) createTask(w http.ResponseWriter, r *http.Request) {
	var req createTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if req.TargetPod == "" && len(req.PodLabels) == 0 {
		writeError(w, http.StatusBadRequest, "target_pod or pod_labels required")
		return
	}

	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	captureTask := &agentpb.CaptureTask{
		TaskId:          taskID,
		TargetPod:       req.TargetPod,
		TargetNamespace: req.TargetNamespace,
		PodLabels:       req.PodLabels,
		DurationSeconds: req.DurationSeconds,
		NtripFilter: &agentpb.NTRIPFilterConfig{
			Mountpoints: req.Mountpoints,
			Usernames:   req.Usernames,
		},
		RtcmFilter: &agentpb.RTCMFilterConfig{
			MessageTypes: req.MessageTypes,
		},
		Export: &agentpb.ExportOptions{
			ExportPcap:   req.ExportPCAP,
			ExportParsed: req.ExportParsed,
			CosBucket:    req.COSBucket,
		},
	}

	resp, err := h.grpc.StartCapture(r.Context(), captureTask)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"task_id":  taskID,
		"accepted": resp.Accepted,
		"reason":   resp.Reason,
		"status":   resp.Status.String(),
	})
}

func (h *APIHandler) listTasks(w http.ResponseWriter, r *http.Request) {
	tasks := h.store.ListTasks()
	writeJSON(w, http.StatusOK, listResponse{Items: tasks, Total: len(tasks)})
}

func (h *APIHandler) getTask(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t := h.store.GetTask(id)
	if t == nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (h *APIHandler) stopTask(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	resp, err := h.grpc.StopCapture(r.Context(), &agentpb.StopRequest{TaskId: id})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task_id":  id,
		"accepted": resp.Accepted,
		"status":   resp.Status.String(),
		"reason":   resp.Reason,
	})
}

// --- Session handlers ---

func (h *APIHandler) listSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := SessionFilter{
		TaskID:     q.Get("task_id"),
		Mountpoint: q.Get("mountpoint"),
		Username:   q.Get("username"),
		ServerPod:  q.Get("server_pod"),
		NodeName:   q.Get("node"),
	}

	if v := q.Get("closed"); v != "" {
		closed := v == "true"
		f.Closed = &closed
	}
	if v := q.Get("min_score"); v != "" {
		if score, err := strconv.ParseInt(v, 10, 32); err == nil {
			s := int32(score)
			f.MinScore = &s
		}
	}
	if v := q.Get("max_score"); v != "" {
		if score, err := strconv.ParseInt(v, 10, 32); err == nil {
			s := int32(score)
			f.MaxScore = &s
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = &t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = &t
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Offset = n
		}
	}

	sessions, total := h.store.ListSessions(f)
	writeJSON(w, http.StatusOK, listResponse{Items: sessions, Total: total})
}

func (h *APIHandler) getSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s := h.store.GetSession(id)
	if s == nil {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *APIHandler) getSessionEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	events := h.store.ListEvents(id)
	writeJSON(w, http.StatusOK, listResponse{Items: events, Total: len(events)})
}

func (h *APIHandler) getSessionReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s := h.store.GetSession(id)
	if s == nil {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "html" || format == "" {
		html := h.reporter.FormatHTML(s, h.store)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(html))
	} else if format == "json" {
		writeJSON(w, http.StatusOK, h.reporter.FormatJSON(s, h.store))
	} else {
		writeError(w, http.StatusBadRequest, "unsupported format: "+format)
	}
}

// --- Cluster status handlers ---

func (h *APIHandler) listAgents(w http.ResponseWriter, r *http.Request) {
	agents := h.store.ListAgents()
	writeJSON(w, http.StatusOK, listResponse{Items: agents, Total: len(agents)})
}

func (h *APIHandler) getAgentStatus(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	a := h.store.GetAgent(node)
	if a == nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *APIHandler) getTopology(w http.ResponseWriter, r *http.Request) {
	agents := h.store.ListAgents()
	nodeMap := make(map[string]*NodeView)

	for _, a := range agents {
		pods := make([]string, len(a.ManagedPods))
		for i, p := range a.ManagedPods {
			pods[i] = p.PodName
		}
		nodeMap[a.NodeName] = &NodeView{
			Name:         a.NodeName,
			AgentVersion: a.AgentVersion,
			PodCount:     len(a.ManagedPods),
			Connected:    true,
			Pods:         pods,
		}
	}

	// Add disconnected agents from task records.
	for _, t := range h.store.ListTasks() {
		if t.NodeName != "" && nodeMap[t.NodeName] == nil {
			nodeMap[t.NodeName] = &NodeView{
				Name:      t.NodeName,
				Connected: false,
			}
		}
	}

	nodes := make([]NodeView, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, *n)
	}

	writeJSON(w, http.StatusOK, TopologyView{Nodes: nodes})
}

// --- WebSocket handlers ---

func (h *APIHandler) wsSessions(w http.ResponseWriter, r *http.Request) {
	h.handleWSUpgrade(w, r, "sessions")
}

func (h *APIHandler) wsSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.handleWSUpgrade(w, r, id)
}

func (h *APIHandler) wsTask(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.handleWSUpgrade(w, r, "task:"+id)
}

// handleWSUpgrade performs a basic WebSocket upgrade using the standard
// library. For production use, consider using gorilla/websocket which
// provides more robust WebSocket support.
func (h *APIHandler) handleWSUpgrade(w http.ResponseWriter, r *http.Request, topic string) {
	// Check for WebSocket upgrade headers.
	if !isWebSocketUpgrade(r) {
		writeError(w, http.StatusBadRequest, "expected WebSocket upgrade")
		return
	}

	// Use the standard library's HTTP hijacker for raw WebSocket.
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "server does not support hijacking")
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hijack failed: "+err.Error())
		return
	}
	defer conn.Close()

	// Perform WebSocket handshake (server side).
	// The key comes from the Sec-WebSocket-Key header.
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return
	}
	accept := computeWebSocketAccept(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	bufrw.WriteString(resp)
	bufrw.Flush()

	// Create a channel-based subscriber. The hub will push JSON frames
	// to this channel, and we forward them as WebSocket text frames.
	ch := make(chan []byte, 256)
	sub := NewChannelSubscriber(topic, ch)
	h.hub.Subscribe(topic, sub)
	defer h.hub.Unsubscribe(topic, sub)

	// Read pump: consume client messages (ping, close) and detect disconnect.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			_, err := conn.Read(buf)
			if err != nil {
				return
			}
			// We don't process client messages; just keep the connection alive.
		}
	}()

	// Write pump: forward hub messages to the WebSocket client.
	for {
		select {
		case data := <-ch:
			// Write as a WebSocket text frame (simplified).
			frame := buildWSTextFrame(data)
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, err := conn.Write(frame)
			if err != nil {
				return
			}
		case <-readDone:
			return
		}
	}
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// computeWebSocketAccept computes the Sec-WebSocket-Accept value.
func computeWebSocketAccept(key string) string {
	// WebSocket magic GUID per RFC 6455.
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.Sum([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h[:])
}

// buildWSTextFrame constructs a WebSocket text frame (opcode 0x1).
// This is a simplified implementation; production code should use
// gorilla/websocket for proper framing and control messages.
func buildWSTextFrame(data []byte) []byte {
	length := len(data)
	var header []byte
	header = append(header, 0x81) // FIN + text opcode
	if length < 126 {
		header = append(header, byte(length))
	} else if length < 65536 {
		header = append(header, 126, byte(length>>8), byte(length))
	} else {
		header = append(header, 127)
		for i := 7; i >= 0; i-- {
			header = append(header, byte(length>>(i*8)))
		}
	}
	return append(header, data...)
}

// --- Health check ---

func (h *APIHandler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "ok",
		"connected_agents": len(h.grpc.ConnectedAgents()),
		"active_sessions":  h.store.ActiveSessionCount(),
		"ws_subscribers":   h.hub.TotalSubscriberCount(),
	})
}

// --- Task Filter Update ---

type updateTaskFilterRequest struct {
	Mountpoints  []string `json:"mountpoints,omitempty"`
	Usernames    []string `json:"usernames,omitempty"`
	MessageTypes []int32  `json:"message_types,omitempty"`
}

func (h *APIHandler) updateTaskFilter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t := h.store.GetTask(id)
	if t == nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if t.Status != TaskStatusRunning {
		writeError(w, http.StatusBadRequest, "cannot update filter on a non-running task")
		return
	}

	var req updateTaskFilterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	t.NtripFilter = &NtripFilterView{
		Mountpoints: req.Mountpoints,
		Usernames:   req.Usernames,
	}
	t.RtcmFilter = &RtcmFilterView{
		MessageTypes: req.MessageTypes,
	}
	h.store.SaveTask(t)

	update := &agentpb.FilterUpdate{
		TaskId: id,
		NtripFilter: &agentpb.NTRIPFilterConfig{
			Mountpoints: req.Mountpoints,
			Usernames:   req.Usernames,
		},
		RtcmFilter: &agentpb.RTCMFilterConfig{
			MessageTypes: req.MessageTypes,
		},
	}
	h.grpc.SendFilterUpdate(update)

	writeJSON(w, http.StatusOK, t)
}

// --- Storage Status & Manual Cleanup ---

func (h *APIHandler) getStorageStatus(w http.ResponseWriter, r *http.Request) {
	type storageStatus struct {
		Type            string `json:"type"`
		SessionsCount   int    `json:"sessions_count"`
		EventsFileCount int    `json:"events_file_count"`
		TotalSizeBytes  int64  `json:"total_size_bytes"`
		StorageDir      string `json:"storage_dir,omitempty"`
	}

	status := storageStatus{
		Type:          "memory",
		SessionsCount: h.store.ActiveSessionCount(),
	}

	if fs, ok := h.store.(interface{ GetDir() string }); ok {
		dir := fs.GetDir()
		status.Type = "file"
		status.StorageDir = dir

		var totalSize int64
		var sessCount, evtsCount int

		_ = filepath.Walk(filepath.Join(dir, "sessions"), func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				sessCount++
				totalSize += info.Size()
			}
			return nil
		})

		_ = filepath.Walk(filepath.Join(dir, "events"), func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				evtsCount++
				totalSize += info.Size()
			}
			return nil
		})

		status.SessionsCount = sessCount
		status.EventsFileCount = evtsCount
		status.TotalSizeBytes = totalSize
	} else if memStore, ok := h.store.(*MemoryStore); ok {
		memStore.mu.RLock()
		status.SessionsCount = len(memStore.sessions)
		status.EventsFileCount = len(memStore.events)
		memStore.mu.RUnlock()
	}

	writeJSON(w, http.StatusOK, status)
}

func (h *APIHandler) triggerStorageCleanup(w http.ResponseWriter, r *http.Request) {
	daysStr := r.URL.Query().Get("days")
	days := 7
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	cleaner, ok := h.store.(interface {
		CleanupExpired(before time.Time) (int, error)
	})
	if !ok {
		writeError(w, http.StatusBadRequest, "the current store does not support file cleanup")
		return
	}

	threshold := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	count, err := cleaner.CleanupExpired(threshold)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cleanup failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"cleaned_sessions_count": count,
		"threshold_time":         threshold.Format(time.RFC3339),
	})
}

// --- Analytics ---

func (h *APIHandler) getAnalytics(w http.ResponseWriter, r *http.Request) {
	sessions, _ := h.store.ListSessions(SessionFilter{Limit: 2000})

	var totalScore float64
	var count int
	dist := map[string]int{
		"healthy":  0,
		"degraded": 0,
		"poor":     0,
		"critical": 0,
	}

	issueMap := make(map[string]int)

	for _, s := range sessions {
		totalScore += float64(s.Score)
		count++

		switch {
		case s.Score >= 80:
			dist["healthy"]++
		case s.Score >= 60:
			dist["degraded"]++
		case s.Score >= 40:
			dist["poor"]++
		default:
			dist["critical"]++
		}

		for _, issue := range s.Issues {
			issueMap[issue.Category]++
		}
	}

	avgScore := 0.0
	if count > 0 {
		avgScore = totalScore / float64(count)
	}

	var topIssues []IssueCount
	for cat, cnt := range issueMap {
		topIssues = append(topIssues, IssueCount{Category: cat, Count: cnt})
	}
	sort.Slice(topIssues, func(i, j int) bool {
		return topIssues[i].Count > topIssues[j].Count
	})
	if len(topIssues) > 10 {
		topIssues = topIssues[:10]
	}

	var closedSessions []*SessionRecord
	for _, s := range sessions {
		if s.Closed {
			closedSessions = append(closedSessions, s)
		}
	}
	sort.Slice(closedSessions, func(i, j int) bool {
		return closedSessions[i].Score < closedSessions[j].Score
	})
	worstSessions := closedSessions
	if len(worstSessions) > 5 {
		worstSessions = worstSessions[:5]
	}

	agents := h.store.ListAgents()
	agentStats := make([]AgentPerfStats, len(agents))
	for i, a := range agents {
		activeSess := 0
		for _, s := range sessions {
			if !s.Closed && s.NodeName == a.NodeName {
				activeSess++
			}
		}

		agentStats[i] = AgentPerfStats{
			NodeName:      a.NodeName,
			Connected:     true,
			ActiveSession: activeSess,
			DiscardedEvts: a.DiscardedEvts,
		}
	}

	summary := AnalyticsSummary{
		TotalSessions:     count,
		ActiveSessions:    h.store.ActiveSessionCount(),
		AverageScore:      avgScore,
		ScoreDistribution: dist,
		TopIssues:         topIssues,
		WorstSessions:     worstSessions,
		AgentStats:        agentStats,
	}

	writeJSON(w, http.StatusOK, summary)
}
