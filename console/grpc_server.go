// Package console — grpc_server.go
//
// AgentServiceHandler implements the agentpb.AgentServiceServer interface,
// serving as the Console-side gRPC endpoint. Agents connect via the
// Connect RPC (server stream), stream events via ReportEvents (client
// stream), and receive commands (start/stop capture, filter updates).
//
// The handler is the bridge between the gRPC transport and the Console's
// SessionStore, WSHub, and TaskManager.
package console

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"kyanos/proto/agentpb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// CommandSink is the interface used by the handler to push commands to
// a connected Agent's Connect stream. In production this is backed by
// the gRPC server stream; in tests it can be a buffered channel.
type CommandSink interface {
	Send(cmd *agentpb.ControlCommand) error
}

// agentConn tracks a single connected Agent's state.
type agentConn struct {
	info        *agentpb.AgentInfo
	cmdSink     CommandSink
	connectedAt time.Time
	mu          sync.Mutex
}

// AgentServiceHandler implements agentpb.AgentServiceServer.
type AgentServiceHandler struct {
	agentpb.UnimplementedAgentServiceServer

	store SessionStore
	hub   *WSHub

	mu     sync.RWMutex
	agents map[string]*agentConn // nodeName → conn

	// taskCommands maps taskID → pending commands to send on next Connect
	// stream activity. This allows dispatching commands even when the
	// command channel is not actively being read.
	taskCommands map[string]*agentpb.ControlCommand
}

// NewAgentServiceHandler creates the handler with the given store and hub.
func NewAgentServiceHandler(store SessionStore, hub *WSHub) *AgentServiceHandler {
	return &AgentServiceHandler{
		store:        store,
		hub:          hub,
		agents:       make(map[string]*agentConn),
		taskCommands: make(map[string]*agentpb.ControlCommand),
	}
}

// Compile-time interface check.
var _ agentpb.AgentServiceServer = (*AgentServiceHandler)(nil)

// Connect implements the server-streaming registration RPC. The Agent
// sends its AgentInfo once, then receives a stream of ControlCommands.
// The stream stays open until the Agent disconnects or the server shuts
// down.
func (h *AgentServiceHandler) Connect(info *agentpb.AgentInfo, stream agentpb.AgentService_ConnectServer) error {
	if info == nil || info.NodeName == "" {
		return status.Error(codes.InvalidArgument, "node_name is required")
	}

	nodeName := info.NodeName
	conn := &agentConn{
		info:        info,
		cmdSink:     stream,
		connectedAt: time.Now(),
	}

	// Register agent.
	h.mu.Lock()
	h.agents[nodeName] = conn
	h.mu.Unlock()

	h.store.UpsertAgent(&Agent{
		NodeName:     nodeName,
		AgentVersion: info.AgentVersion,
		ManagedPods:  PodInfosFromProto(info.ManagedPods),
		ConnectedAt:  conn.connectedAt,
		LastStatusAt: conn.connectedAt,
	})

	// Send any pending commands for this agent's tasks.
	h.mu.RLock()
	for _, cmd := range h.taskCommands {
		_ = stream.Send(cmd) // best effort
	}
	h.mu.RUnlock()

	// Block until the stream context is done (Agent disconnected).
	<-stream.Context().Done()

	// Unregister agent.
	h.mu.Lock()
	if existing, ok := h.agents[nodeName]; ok && existing == conn {
		delete(h.agents, nodeName)
	}
	h.mu.Unlock()

	return stream.Context().Err()
}

// ReportEvents implements the client-streaming event upload RPC. The
// Agent streams SessionEvents and the Console acknowledges receipt.
func (h *AgentServiceHandler) ReportEvents(stream agentpb.AgentService_ReportEventsServer) error {
	var received uint64
	for {
		evt, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&agentpb.EventAck{Received: received})
		}
		if err != nil {
			return err
		}

		// Convert and store event.
		rec := EventRecordFromProto(evt)
		if rec != nil {
			h.store.RecordEvent(rec)

			// Broadcast to per-session WebSocket subscribers.
			h.hub.BroadcastSessionEvent(evt.SessionId, rec)

			// Broadcast to global "sessions" topic so SessionExplorer
			// can update in real time.
			if sessRec := h.store.GetSession(evt.SessionId); sessRec != nil {
				h.hub.BroadcastSessionListChange("updated", sessRec)
			}
		}

		// If this is a close event with a summary, persist the session.
		if closeEvt, ok := evt.Event.(*agentpb.SessionEvent_Close); ok {
			if closeEvt.Close.Summary != nil {
				// Determine node name from peer info or pod info.
				nodeName := ""
				if evt.Pod != nil {
					nodeName = evt.Pod.NodeName
				}
				if nodeName == "" {
					nodeName = h.peerNodeName(stream.Context())
				}
				sessionRec := SessionRecordFromSummary(closeEvt.Close.Summary, evt.TaskId, nodeName)
				if sessionRec != nil {
					h.store.SaveSession(sessionRec)
					h.hub.BroadcastSessionUpdate(evt.SessionId, sessionRec)
					h.hub.BroadcastSessionListChange("closed", sessionRec)

					// Update task session count.
					if t := h.store.GetTask(evt.TaskId); t != nil {
						t.SessionCount = h.store.SessionCountByTask(evt.TaskId)
						h.store.SaveTask(t)
					}
				}
			}
		}

		received++
	}
}

// ReportStatus handles periodic agent health and managed-pod reports.
func (h *AgentServiceHandler) ReportStatus(ctx context.Context, s *agentpb.AgentStatus) (*agentpb.StatusAck, error) {
	if s == nil || s.NodeName == "" {
		return nil, status.Error(codes.InvalidArgument, "node_name is required")
	}

	h.mu.RLock()
	conn, ok := h.agents[s.NodeName]
	h.mu.RUnlock()

	if ok {
		h.store.UpsertAgent(&Agent{
			NodeName:      s.NodeName,
			ManagedPods:   PodInfosFromProto(s.ManagedPods),
			DiscardedEvts: s.DiscardedEvents,
			ConnectedAt:   conn.connectedAt,
		})
	}

	return &agentpb.StatusAck{Ok: true}, nil
}

// StartCapture dispatches a capture task to the appropriate Agent.
func (h *AgentServiceHandler) StartCapture(ctx context.Context, task *agentpb.CaptureTask) (*agentpb.TaskResponse, error) {
	if task == nil || task.TaskId == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}

	// Persist the task.
	t := &Task{
		ID:              task.TaskId,
		TargetPod:       task.TargetPod,
		TargetNamespace: task.TargetNamespace,
		PodLabels:       task.PodLabels,
		DurationSeconds: task.DurationSeconds,
		Status:          TaskStatusRunning,
		CreatedAt:       time.Now(),
		StartedAt:       time.Now(),
		ExportPCAP:      task.Export != nil && task.Export.ExportPcap,
		ExportParsed:    task.Export != nil && task.Export.ExportParsed,
		COSBucket:       task.GetExport().GetCosBucket(),
	}
	if task.NtripFilter != nil {
		t.NtripFilter = &NtripFilterView{
			Mountpoints: task.NtripFilter.Mountpoints,
			Usernames:   task.NtripFilter.Usernames,
		}
	}
	if task.RtcmFilter != nil {
		t.RtcmFilter = &RtcmFilterView{
			MessageTypes: task.RtcmFilter.MessageTypes,
		}
	}
	h.store.SaveTask(t)

	// Build the command and try to send it immediately.
	cmd := &agentpb.ControlCommand{
		Command: &agentpb.ControlCommand_StartCapture{
			StartCapture: task,
		},
	}

	h.mu.RLock()
	var sent bool

	// Node/Pod Affinity routing.
	targetNodes := make(map[string]bool)
	if task.TargetPod != "" {
		agents := h.store.ListAgents()
		for _, a := range agents {
			for _, p := range a.ManagedPods {
				// Match pod name (supports wildcard pattern) and optionally namespace
				if matchWildcard(task.TargetPod, p.PodName) && (task.TargetNamespace == "" || p.Namespace == task.TargetNamespace) {
					targetNodes[a.NodeName] = true
				}
			}
		}
	}

	// Try to route directly to matched affinity Node Agent connections.
	if len(targetNodes) > 0 {
		for targetNodeName := range targetNodes {
			if conn, ok := h.agents[targetNodeName]; ok {
				conn.mu.Lock()
				err := conn.cmdSink.Send(cmd)
				conn.mu.Unlock()
				if err == nil {
					sent = true
					t.NodeName = targetNodeName
				}
			}
		}
	}

	// Broadcast backup / fallback if not sent.
	if !sent {
		for _, conn := range h.agents {
			conn.mu.Lock()
			err := conn.cmdSink.Send(cmd)
			conn.mu.Unlock()
			if err == nil {
				sent = true
				t.NodeName = conn.info.NodeName
			}
		}
	}

	// If no agent connected or accepted, queue the command for later delivery.
	if !sent {
		h.taskCommands[task.TaskId] = cmd
	}
	h.mu.RUnlock()

	if sent {
		h.store.SaveTask(t)
		h.hub.BroadcastTaskStatus(task.TaskId, t)
		return &agentpb.TaskResponse{
			TaskId:   task.TaskId,
			Accepted: true,
			Status:   agentpb.Status_ACCEPTED,
		}, nil
	}

	return &agentpb.TaskResponse{
		TaskId:   task.TaskId,
		Accepted: true,
		Reason:   "queued: no agent currently connected",
		Status:   agentpb.Status_ACCEPTED,
	}, nil
}

// StopCapture stops an in-progress capture task.
func (h *AgentServiceHandler) StopCapture(ctx context.Context, req *agentpb.StopRequest) (*agentpb.TaskResponse, error) {
	if req == nil || req.TaskId == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}

	t := h.store.GetTask(req.TaskId)
	if t == nil {
		return &agentpb.TaskResponse{
			TaskId:   req.TaskId,
			Accepted: false,
			Reason:   "task not found",
			Status:   agentpb.Status_NOT_FOUND,
		}, nil
	}

	cmd := &agentpb.ControlCommand{
		Command: &agentpb.ControlCommand_StopCapture{
			StopCapture: req,
		},
	}

	h.mu.RLock()
	for _, conn := range h.agents {
		conn.mu.Lock()
		_ = conn.cmdSink.Send(cmd)
		conn.mu.Unlock()
	}
	h.mu.RUnlock()

	// Remove from pending commands.
	h.mu.Lock()
	delete(h.taskCommands, req.TaskId)
	h.mu.Unlock()

	t.Status = TaskStatusStopped
	t.StoppedAt = time.Now()
	h.store.SaveTask(t)
	h.hub.BroadcastTaskStatus(req.TaskId, t)

	return &agentpb.TaskResponse{
		TaskId:   req.TaskId,
		Accepted: true,
		Status:   agentpb.Status_STOPPED,
	}, nil
}

// SendFilterUpdate dispatches a filter update command to connected agents.
func (h *AgentServiceHandler) SendFilterUpdate(update *agentpb.FilterUpdate) {
	cmd := &agentpb.ControlCommand{
		Command: &agentpb.ControlCommand_UpdateFilter{
			UpdateFilter: update,
		},
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, conn := range h.agents {
		conn.mu.Lock()
		_ = conn.cmdSink.Send(cmd)
		conn.mu.Unlock()
	}
}

// ConnectedAgents returns the list of currently connected agent node names.
func (h *AgentServiceHandler) ConnectedAgents() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]string, 0, len(h.agents))
	for name := range h.agents {
		out = append(out, name)
	}
	return out
}

// peerNodeName tries to extract a node name from the gRPC peer info.
// This is a best-effort heuristic; in production, the node name comes
// from the AgentInfo registration or the PodInfo in the event.
func (h *AgentServiceHandler) peerNodeName(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return ""
	}
	return p.Addr.String()
}

// matchWildcard returns true if value matches the wildcard pattern.
func matchWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(value, prefix)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(value, suffix)
	}
	return pattern == value
}
