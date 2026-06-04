// Package controlplane implements the Phase 7 gRPC control-plane subsystem for
// the Kyanos Agent. Every capability in this package is additive and gated on
// gRPC mode; when the control plane is disabled the Agent behaves exactly as the
// standalone CLI tool.
//
// This file implements the TaskManager: it tracks active CaptureTask instances
// by task_id, validates incoming tasks, arms duration timers via an injectable
// Clock, maps sessions to their owning task, and handles stop requests.
package controlplane

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"kyanos/agent/export"
	"kyanos/agent/session"
	"kyanos/common"
	"kyanos/proto/agentpb"
)

// activeTask holds the runtime state of a single in-progress capture task.
type activeTask struct {
	// Task identity and scope.
	TaskID          string
	TargetPod       string
	TargetNamespace string
	PodLabels       map[string]string

	// Filter configuration handles (retained for later use by FilterController).
	NtripFilter *agentpb.NTRIPFilterConfig
	RtcmFilter  *agentpb.RTCMFilterConfig

	// Export options for this task's output.
	Export *agentpb.ExportOptions

	// Export handles
	PcapNgExp *export.PcapNgWriter

	// Duration management.
	DurationSeconds int64
	StartTime       time.Time
	Timer           Timer // nil when no duration is set; stops the task on fire
}


// TaskManager tracks active CaptureTask instances by task_id. It validates
// incoming tasks, arms injectable-clock duration timers that auto-stop tasks,
// maps sessions to their owning task, and processes stop requests.
//
// All methods are safe for concurrent use.
type TaskManager struct {
	mu           sync.Mutex
	clock        Clock
	tasks        map[string]*activeTask
	ipToNameFunc func() map[string]string
}

// NewTaskManager creates a TaskManager that uses the given clock for duration
// timers. If clock is nil, a real clock is used.
func NewTaskManager(clock Clock) *TaskManager {
	if clock == nil {
		clock = NewRealClock()
	}
	return &TaskManager{
		clock: clock,
		tasks: make(map[string]*activeTask),
	}
}

// SetIPToNameFunc registers a callback to resolve Pod IP to Pod Name.
func (m *TaskManager) SetIPToNameFunc(fn func() map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipToNameFunc = fn
}

// handleUploadAndCleanup is triggered asynchronously when a file part is closed.
// If a cosBucket is configured, it uploads the file and deletes the local copy.
func (m *TaskManager) handleUploadAndCleanup(taskID, localPath, cosBucket string) {
	if cosBucket == "" {
		return
	}
	region := os.Getenv("COS_REGION")
	if region == "" {
		region = "ap-guangzhou"
	}

	uploader, err := export.NewCOSUploader(export.COSUploaderConfig{
		Bucket:    cosBucket,
		Region:    region,
		Prefix:    "captures/" + taskID,
		DeleteRaw: true,
	})
	if err != nil {
		common.AgentLog.Errorf("TaskManager: failed to create COSUploader for task %q: %v", taskID, err)
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if _, err := uploader.Upload(ctx, localPath); err != nil {
			common.AgentLog.Errorf("TaskManager: failed to upload %q to COS for task %q: %v", localPath, taskID, err)
		}
	}()
}


// Start validates the given CaptureTask and, if valid, records it as active with
// its scope, filter handles, and export options. It returns an accepting
// TaskResponse on success. Invalid tasks (empty task_id, duplicate task_id, or
// tasks with no targeting scope) are rejected with a descriptive reason.
//
// If the task specifies a positive duration_seconds, a timer is armed on the
// injectable clock that will automatically stop the task when it fires.
//
// Requirements: 3.1, 3.3, 3.4, 3.5, 3.8
func (m *TaskManager) Start(task *agentpb.CaptureTask) *agentpb.TaskResponse {
	if task == nil {
		return rejectResponse("", "capture task is nil")
	}

	taskID := task.GetTaskId()

	// Validate: task_id must be non-empty.
	if taskID == "" {
		return rejectResponse("", "task_id is empty")
	}

	// Validate: task must have at least one targeting scope field.
	if !hasScope(task) {
		return rejectResponse(taskID, "task has no targeting scope: at least one of target_pod, target_namespace, or pod_labels must be specified")
	}

	// Initialize PCAP-NG exporter pre-lock to avoid holding lock during File I/O
	var pcapNgExp *export.PcapNgWriter
	if task.GetExport().GetExportPcap() {
		basePath := fmt.Sprintf("./captures/task-%s.pcapng", taskID)
		var ipMap map[string]string
		if m.ipToNameFunc != nil {
			ipMap = m.ipToNameFunc()
		}

		rotator, err := export.NewRotateWriter(export.RotateWriterConfig{
			BasePath: basePath,
			MaxSize:  100 * 1024 * 1024, // 100MB
			MaxDuration: 1 * time.Hour,
			HeaderGenerator: func() []byte {
				m.mu.Lock()
				fn := m.ipToNameFunc
				m.mu.Unlock()
				var currentIpMap map[string]string
				if fn != nil {
					currentIpMap = fn()
				}
				return export.GetGlobalHeaderBytes(currentIpMap)
			},
			OnRotate: func(closedPath string) {
				m.handleUploadAndCleanup(taskID, closedPath, task.GetExport().GetCosBucket())
			},
		})
		if err != nil {
			return rejectResponse(taskID, fmt.Sprintf("failed to initialize PCAP-NG exporter: %v", err))
		}

		writer, err := export.NewPcapNgWriter(rotator, ipMap)
		if err != nil {
			rotator.Close()
			return rejectResponse(taskID, fmt.Sprintf("failed to initialize PCAP-NG writer: %v", err))
		}
		pcapNgExp = writer
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate: task_id must not already be active.
	if _, exists := m.tasks[taskID]; exists {
		if pcapNgExp != nil {
			pcapNgExp.Close()
			os.Remove(fmt.Sprintf("./captures/task-%s.pcapng", taskID))
		}
		return rejectResponse(taskID, fmt.Sprintf("task_id %q is already active", taskID))
	}

	at := &activeTask{
		TaskID:          taskID,
		TargetPod:       task.GetTargetPod(),
		TargetNamespace: task.GetTargetNamespace(),
		PodLabels:       task.GetPodLabels(),
		NtripFilter:     task.GetNtripFilter(),
		RtcmFilter:      task.GetRtcmFilter(),
		Export:          task.GetExport(),
		PcapNgExp:       pcapNgExp,
		DurationSeconds: task.GetDurationSeconds(),
		StartTime:       m.clock.Now(),
	}

	// Arm a duration timer if a positive duration is specified (Req 3.5).
	if at.DurationSeconds > 0 {
		dur := time.Duration(at.DurationSeconds) * time.Second
		at.Timer = m.clock.AfterFunc(dur, func() {
			m.autoStop(taskID)
		})
	}

	m.tasks[taskID] = at

	return acceptResponse(taskID)
}


// Stop deactivates an active task and returns a STOPPED TaskResponse. If the
// task_id is not active, it returns a NOT_FOUND response.
//
// Requirements: 3.6, 3.7
func (m *TaskManager) Stop(req *agentpb.StopRequest) *agentpb.TaskResponse {
	if req == nil {
		return notFoundResponse("")
	}

	taskID := req.GetTaskId()

	m.mu.Lock()
	defer m.mu.Unlock()

	return m.stopLocked(taskID)
}

// TaskIDForSession returns the task_id of the active task whose scope matches
// the given session. If no active task matches, the second return value is
// false.
//
// Matching logic: a session matches a task if the task's scope is satisfied:
//   - If task specifies target_pod, the session's ServerPod must equal it.
//   - If task specifies target_namespace, the session's ServerPod or ServerNode
//     context must be in that namespace (we compare against ServerPod prefix
//     convention or fall back to matching if namespace is not empty).
//   - If task specifies pod_labels, all labels must match (label matching
//     requires PodResolver integration; for now any session matches a
//     labels-only scope since the kernel-side cgroup whitelist already filters
//     by the resolved pods).
//
// When multiple tasks match, the most specific match wins (target_pod >
// target_namespace > labels-only).
//
// Requirement: 3.9
func (m *TaskManager) TaskIDForSession(s *session.NTRIPSession) (string, bool) {
	if s == nil {
		return "", false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var bestTask string
	bestScore := -1

	for _, at := range m.tasks {
		score := matchScore(at, s)
		if score >= 0 && score > bestScore {
			bestScore = score
			bestTask = at.TaskID
		}
	}

	if bestScore < 0 {
		return "", false
	}
	return bestTask, true
}

// ActiveTaskIDs returns a sorted slice of all currently active task IDs.
func (m *TaskManager) ActiveTaskIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	ids := make([]string, 0, len(m.tasks))
	for id := range m.tasks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// IsActive reports whether the given task_id is currently tracked as active.
func (m *TaskManager) IsActive(taskID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.tasks[taskID]
	return ok
}

// autoStop is the callback invoked by a duration timer when it fires. It stops
// the task under the lock, which is safe because the fake clock fires callbacks
// synchronously and the real clock fires them on a separate goroutine.
func (m *TaskManager) autoStop(taskID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked(taskID)
}

// stopLocked deactivates the task identified by taskID while the caller holds
// m.mu. It cancels any pending duration timer and removes the task from the
// active set. Returns a STOPPED response on success or NOT_FOUND if the task
// is not active.
func (m *TaskManager) stopLocked(taskID string) *agentpb.TaskResponse {
	at, exists := m.tasks[taskID]
	if !exists {
		return notFoundResponse(taskID)
	}

	// Cancel the duration timer if it hasn't already fired.
	if at.Timer != nil {
		at.Timer.Stop()
	}

	// Close PCAP-NG exporter if active
	if at.PcapNgExp != nil {
		if err := at.PcapNgExp.Close(); err != nil {
			common.AgentLog.Errorf("TaskManager: failed to close PCAP-NG exporter for task %q: %v", taskID, err)
		}
	}

	delete(m.tasks, taskID)

	return stoppedResponse(taskID)
}

// ---------------------------------------------------------------------------
// Scope matching helpers
// ---------------------------------------------------------------------------

// hasScope returns true if the task specifies at least one targeting scope
// field (target_pod, target_namespace, or pod_labels).
func hasScope(task *agentpb.CaptureTask) bool {
	if task.GetTargetPod() != "" {
		return true
	}
	if task.GetTargetNamespace() != "" {
		return true
	}
	if len(task.GetPodLabels()) > 0 {
		return true
	}
	return false
}

// matchScore determines how well a session matches a task's scope. Returns -1
// if the session does not match the task's scope. Higher scores indicate more
// specific matches:
//   - 2: target_pod matches
//   - 1: target_namespace matches (no pod specified or pod also matches)
//   - 0: labels-only scope (always matches since cgroup whitelist already filters)
func matchScore(at *activeTask, s *session.NTRIPSession) int {
	// If the task targets a specific pod, the session must be served by that pod.
	if at.TargetPod != "" {
		if s.ServerPod != at.TargetPod {
			return -1
		}
		return 2
	}

	// If the task targets a namespace, match if the session has no pod identity
	// (we assume it's in scope since cgroup filtering handles it) or future
	// pod-resolver integration will fill in namespace.
	if at.TargetNamespace != "" {
		// For now, namespace matching relies on the cgroup whitelist having
		// already filtered events at the kernel level. Sessions that reach here
		// are assumed to be in the target namespace.
		return 1
	}

	// Labels-only scope: if the task only specifies pod_labels, the cgroup
	// whitelist has already ensured only matching pods emit events, so any
	// session reaching here matches.
	if len(at.PodLabels) > 0 {
		return 0
	}

	// No scope — should not happen for validated tasks, but return no match.
	return -1
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

func acceptResponse(taskID string) *agentpb.TaskResponse {
	return &agentpb.TaskResponse{
		TaskId:   taskID,
		Accepted: true,
		Status:   agentpb.Status_ACCEPTED,
	}
}

func rejectResponse(taskID, reason string) *agentpb.TaskResponse {
	return &agentpb.TaskResponse{
		TaskId:   taskID,
		Accepted: false,
		Reason:   reason,
		Status:   agentpb.Status_REJECTED,
	}
}

func stoppedResponse(taskID string) *agentpb.TaskResponse {
	return &agentpb.TaskResponse{
		TaskId: taskID,
		Status: agentpb.Status_STOPPED,
	}
}

func notFoundResponse(taskID string) *agentpb.TaskResponse {
	return &agentpb.TaskResponse{
		TaskId: taskID,
		Reason: fmt.Sprintf("task_id %q is not active", taskID),
		Status: agentpb.Status_NOT_FOUND,
	}
}

// GetPcapNgExpForConn returns the PcapNgExp and task ID for the active task matching the connection.
// If no active task matches, it returns (nil, "", false).
func (m *TaskManager) GetPcapNgExpForConn(s *session.NTRIPSession) (*export.PcapNgWriter, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var bestTask *activeTask
	bestScore := -1

	for _, at := range m.tasks {
		score := matchScore(at, s)
		if score >= 0 && score > bestScore {
			bestScore = score
			bestTask = at
		}
	}

	if bestScore < 0 || bestTask == nil {
		return nil, "", false
	}
	return bestTask.PcapNgExp, bestTask.TaskID, true
}
