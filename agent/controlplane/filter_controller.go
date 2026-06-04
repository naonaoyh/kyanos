// Package controlplane implements the Phase 7 gRPC control-plane subsystem for
// the Kyanos Agent. Every capability in this package is additive and gated on
// gRPC mode; when the control plane is disabled the Agent behaves exactly as the
// standalone CLI tool.
//
// This file implements the FilterController: it compiles NTRIPFilterConfig and
// RTCMFilterConfig protobuf messages into the existing protocol.ProtocolFilter
// implementations, manages an immutable filterState snapshot, and applies
// FilterUpdate commands atomically using a validate-then-commit pattern.
//
// Requirements: 3.2, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7
package controlplane

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"kyanos/agent/protocol"
	"kyanos/agent/protocol/ntrip"
	"kyanos/agent/protocol/rtcm"
	"kyanos/proto/agentpb"
)

// filterState is an immutable snapshot of the active filter configuration. The
// FilterController builds a new filterState from the current one for each update
// and swaps it atomically under a mutex (validate-then-commit). Components that
// read filter state get a consistent view without locking.
type filterState struct {
	// messageFilter is the compiled user-space ProtocolFilter used to accept or
	// reject parsed protocol records.
	messageFilter protocol.ProtocolFilter

	// cgroups is the desired Cgroup_Whitelist set — the cgroup IDs that the BPF
	// map should contain for kernel-side filtering.
	cgroups map[uint64]struct{}

	// taskParams holds per-task parameter overrides keyed by task_id. When a
	// FilterUpdate changes task parameters (e.g. duration_seconds), the change
	// is recorded here.
	taskParams map[string]taskParam
}

// taskParam holds the mutable per-task parameters that a FilterUpdate can change.
type taskParam struct {
	DurationSeconds int64
	NtripFilter     *agentpb.NTRIPFilterConfig
	RtcmFilter      *agentpb.RTCMFilterConfig
}

// FilterApplyFunc is the callback invoked to swap the active user-space
// MessageFilter in the capture pipeline. It receives the newly compiled filter.
type FilterApplyFunc func(protocol.ProtocolFilter)

// FilterController applies FilterUpdate commands atomically and serially. It
// compiles NTRIPFilterConfig/RTCMFilterConfig into the existing
// protocol.ProtocolFilter, reconciles the cgroup whitelist via the BPF map
// abstraction, and updates per-task parameters on the TaskManager.
//
// Concurrency: all updates are serialized by mu (Requirement 5.7). On
// validation failure the state is left unchanged (Requirement 5.5). On
// partial-failure during application (e.g. BPF map push fails after the
// user-space filter was already swapped), an error naming the changed
// components is returned (Requirement 5.6).
type FilterController struct {
	mu sync.Mutex

	// current is the active immutable filter state snapshot.
	current filterState

	// apply swaps the active user-space MessageFilter in the capture pipeline.
	apply FilterApplyFunc

	// whitelist abstracts the BPF map for cgroup ID reconciliation.
	whitelist CgroupWhitelist

	// resolver maps Pod names to cgroup IDs for whitelist reconciliation.
	resolver *PodResolver

	// tasks provides access to the TaskManager for updating task parameters.
	tasks *TaskManager
}

// FilterControllerConfig holds construction parameters for a FilterController.
type FilterControllerConfig struct {
	// Apply is the callback to swap the active user-space MessageFilter.
	Apply FilterApplyFunc
	// Whitelist abstracts the BPF map (may be nil for environments without BPF).
	Whitelist CgroupWhitelist
	// Resolver maps Pod names to cgroup IDs (may be nil if Pod resolution is disabled).
	Resolver *PodResolver
	// Tasks is the active TaskManager (may be nil if task-param updates are not needed).
	Tasks *TaskManager
	// InitialFilter is the initial user-space filter (defaults to NoopFilter if nil).
	InitialFilter protocol.ProtocolFilter
}

// NewFilterController constructs a FilterController from the given
// configuration. The controller starts with the provided initial filter state.
func NewFilterController(cfg FilterControllerConfig) *FilterController {
	initial := cfg.InitialFilter
	if initial == nil {
		initial = protocol.NoopFilter{}
	}

	return &FilterController{
		current: filterState{
			messageFilter: initial,
			cgroups:       make(map[uint64]struct{}),
			taskParams:    make(map[string]taskParam),
		},
		apply:     cfg.Apply,
		whitelist: cfg.Whitelist,
		resolver:  cfg.Resolver,
		tasks:     cfg.Tasks,
	}
}

// ApplyUpdate validates the given FilterUpdate and, on success, atomically
// swaps the active filter state. The method implements validate-then-commit:
//
//  1. Validate: compile the new filter configuration, resolve pod names to
//     cgroup IDs, and verify task-param targets. Any failure here leaves state
//     unchanged and returns a descriptive error (Requirement 5.5).
//
//  2. Commit: swap the user-space MessageFilter, reconcile the cgroup whitelist,
//     and update task parameters. If a component fails during commit (partial
//     failure), the already-applied components remain in effect and the error
//     names which components changed (Requirement 5.6).
//
// Concurrent calls are serialized by the mutex (Requirement 5.7).
func (f *FilterController) ApplyUpdate(u *agentpb.FilterUpdate) error {
	if u == nil {
		return errors.New("filter update is nil")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// -----------------------------------------------------------------------
	// Phase 1: Validate — build the next state without mutating anything.
	// -----------------------------------------------------------------------

	next := f.current // copy the immutable snapshot

	// 1a. Compile the new message filter if filter configs are provided.
	var newFilter protocol.ProtocolFilter
	hasFilterChange := u.GetNtripFilter() != nil || u.GetRtcmFilter() != nil
	if hasFilterChange {
		compiled, err := compileFilter(u.GetNtripFilter(), u.GetRtcmFilter())
		if err != nil {
			return fmt.Errorf("filter validation failed: %w", err)
		}
		newFilter = compiled
		next.messageFilter = compiled
	}

	// 1b. Resolve pod add/remove to cgroup IDs for whitelist reconciliation.
	var addCgroups, removeCgroups map[uint64]struct{}
	hasCgroupChange := len(u.GetAddPods()) > 0 || len(u.GetRemovePods()) > 0
	if hasCgroupChange {
		var err error
		addCgroups, err = f.resolvePodsToCgroups(u.GetAddPods())
		if err != nil {
			return fmt.Errorf("filter validation failed: cannot resolve add_pods: %w", err)
		}
		removeCgroups, err = f.resolvePodsToCgroups(u.GetRemovePods())
		if err != nil {
			return fmt.Errorf("filter validation failed: cannot resolve remove_pods: %w", err)
		}
		// Compute the desired set for validation (does not mutate current).
		diff := ReconcileCgroups(f.current.cgroups, addCgroups, removeCgroups)
		next.cgroups = diff.Desired
	}

	// 1c. Validate task-param update target (if task_id is specified).
	hasTaskParamChange := false
	if u.GetTaskId() != "" && (u.GetDurationSeconds() != 0 || u.GetNtripFilter() != nil || u.GetRtcmFilter() != nil) {
		hasTaskParamChange = true
		if f.tasks != nil && !f.tasks.IsActive(u.GetTaskId()) {
			return fmt.Errorf("filter validation failed: task_id %q is not active", u.GetTaskId())
		}
	}

	// Build the new task params map (copy-on-write).
	if hasTaskParamChange {
		newParams := make(map[string]taskParam, len(f.current.taskParams))
		for k, v := range f.current.taskParams {
			newParams[k] = v
		}
		tp := newParams[u.GetTaskId()]
		if u.GetDurationSeconds() != 0 {
			tp.DurationSeconds = u.GetDurationSeconds()
		}
		if u.GetNtripFilter() != nil {
			tp.NtripFilter = u.GetNtripFilter()
		}
		if u.GetRtcmFilter() != nil {
			tp.RtcmFilter = u.GetRtcmFilter()
		}
		newParams[u.GetTaskId()] = tp
		next.taskParams = newParams
	}

	// -----------------------------------------------------------------------
	// Phase 2: Commit — apply changes. Track which components succeed so that
	// partial-failure error messages name the changed components.
	// -----------------------------------------------------------------------

	var changed []string
	var commitErrs []error

	// 2a. Swap user-space MessageFilter.
	if hasFilterChange && newFilter != nil {
		if f.apply != nil {
			f.apply(newFilter)
		}
		f.current.messageFilter = newFilter
		changed = append(changed, "message_filter")
	}

	// 2b. Reconcile cgroup whitelist.
	if hasCgroupChange {
		if f.whitelist != nil {
			_, err := ApplyCgroupWhitelist(f.whitelist, f.current.cgroups, addCgroups, removeCgroups)
			if err != nil {
				commitErrs = append(commitErrs, fmt.Errorf("cgroup_whitelist: %w", err))
			} else {
				changed = append(changed, "cgroup_whitelist")
			}
		}
		// Update the desired set in state regardless of push errors — the
		// user-space view of the desired cgroups is authoritative.
		f.current.cgroups = next.cgroups
		if !containsString(changed, "cgroup_whitelist") {
			changed = append(changed, "cgroup_whitelist(desired_only)")
		}
	}

	// 2c. Update task parameters.
	if hasTaskParamChange {
		f.current.taskParams = next.taskParams
		changed = append(changed, "task_params")
	}

	// If any commit-phase errors occurred, report them with the list of
	// already-changed components (Requirement 5.6).
	if len(commitErrs) > 0 {
		return fmt.Errorf("partial filter update failure (changed: %s): %w",
			strings.Join(changed, ", "), errors.Join(commitErrs...))
	}

	return nil
}

// CurrentFilter returns the currently active user-space ProtocolFilter. This is
// safe to call concurrently with ApplyUpdate; the caller receives a consistent
// snapshot (the filter value is itself immutable once compiled).
func (f *FilterController) CurrentFilter() protocol.ProtocolFilter {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current.messageFilter
}

// CurrentCgroups returns a copy of the desired cgroup whitelist set.
func (f *FilterController) CurrentCgroups() map[uint64]struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	cpy := make(map[uint64]struct{}, len(f.current.cgroups))
	for k, v := range f.current.cgroups {
		cpy[k] = v
	}
	return cpy
}

// CurrentTaskParams returns the task parameters for the given task_id.
func (f *FilterController) CurrentTaskParams(taskID string) (taskParam, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tp, ok := f.current.taskParams[taskID]
	return tp, ok
}

// ---------------------------------------------------------------------------
// Filter compilation
// ---------------------------------------------------------------------------

// compileFilter compiles NTRIPFilterConfig and/or RTCMFilterConfig protobuf
// messages into the corresponding protocol.ProtocolFilter implementation. If
// both configs are provided, an NTRIP filter is preferred (since NTRIP embeds
// RTCM as a sub-stream and its filter handles RTCM frames via
// NTRIPFilter.filterRTCMFrame). If only RTCMFilterConfig is provided, a
// standalone RTCMFilter is compiled.
//
// Returns an error if the configuration is invalid (e.g., unsupported version
// strings). A nil config for both produces a NoopFilter.
func compileFilter(ntripCfg *agentpb.NTRIPFilterConfig, rtcmCfg *agentpb.RTCMFilterConfig) (protocol.ProtocolFilter, error) {
	if ntripCfg == nil && rtcmCfg == nil {
		return protocol.NoopFilter{}, nil
	}

	// If NTRIP config is provided, compile an NTRIPFilter (which also handles
	// RTCM frames in the NTRIP stream).
	if ntripCfg != nil {
		f, err := compileNTRIPFilter(ntripCfg, rtcmCfg)
		if err != nil {
			return nil, err
		}
		return f, nil
	}

	// Only RTCM config provided — compile a standalone RTCMFilter.
	f, err := compileRTCMFilter(rtcmCfg)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// compileNTRIPFilter compiles an NTRIPFilterConfig (and optional companion
// RTCMFilterConfig) into an ntrip.NTRIPFilter.
func compileNTRIPFilter(cfg *agentpb.NTRIPFilterConfig, rtcmCfg *agentpb.RTCMFilterConfig) (*ntrip.NTRIPFilter, error) {
	f := &ntrip.NTRIPFilter{
		TargetMountPoints: cfg.GetMountpoints(),
		TargetUsernames:   cfg.GetUsernames(),
		ErrorsOnly:        cfg.GetErrorsOnly(),
		GGAOnly:           cfg.GetGgaOnly(),
	}

	// Compile version strings to NTRIPVersion enum values.
	if len(cfg.GetVersions()) > 0 {
		versions, err := parseNTRIPVersions(cfg.GetVersions())
		if err != nil {
			return nil, err
		}
		f.TargetVersions = versions
	}

	// If a companion RTCM config is provided, apply CRC-errors-only to the
	// NTRIP filter (which handles embedded RTCM frames).
	if rtcmCfg != nil {
		f.CRCErrorsOnly = rtcmCfg.GetCrcErrorsOnly()
	}

	f.InitExtensions()

	return f, nil
}

// compileRTCMFilter compiles an RTCMFilterConfig into an rtcm.RTCMFilter.
func compileRTCMFilter(cfg *agentpb.RTCMFilterConfig) (rtcm.RTCMFilter, error) {
	f := rtcm.RTCMFilter{
		CRCErrorsOnly: cfg.GetCrcErrorsOnly(),
	}

	// Convert []int32 message types to []int.
	if len(cfg.GetMessageTypes()) > 0 {
		msgTypes := make([]int, len(cfg.GetMessageTypes()))
		for i, mt := range cfg.GetMessageTypes() {
			if mt < 0 {
				return rtcm.RTCMFilter{}, fmt.Errorf("invalid RTCM message type: %d (must be non-negative)", mt)
			}
			msgTypes[i] = int(mt)
		}
		f.TargetMessageTypes = msgTypes
	}

	return f, nil
}

// parseNTRIPVersions converts version strings (e.g., "NTRIPv1", "NTRIPv2",
// "v1", "v2", "1", "2") into ntrip.NTRIPVersion values.
func parseNTRIPVersions(versions []string) ([]ntrip.NTRIPVersion, error) {
	result := make([]ntrip.NTRIPVersion, 0, len(versions))
	for _, v := range versions {
		parsed, err := parseNTRIPVersion(v)
		if err != nil {
			return nil, err
		}
		result = append(result, parsed)
	}
	return result, nil
}

// parseNTRIPVersion parses a single version string into a ntrip.NTRIPVersion.
func parseNTRIPVersion(s string) (ntrip.NTRIPVersion, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ntripv1", "v1", "1":
		return ntrip.NTRIPv1, nil
	case "ntripv2", "v2", "2":
		return ntrip.NTRIPv2, nil
	default:
		return ntrip.NTRIPVersionUnknown, fmt.Errorf("unsupported NTRIP version %q: expected one of NTRIPv1, NTRIPv2, v1, v2, 1, 2", s)
	}
}

// ---------------------------------------------------------------------------
// Pod-to-cgroup resolution helper
// ---------------------------------------------------------------------------

// resolvePodsToCgroups resolves a list of Pod names to a cgroup ID set using the
// PodResolver's cache. If the resolver is nil or in fallback mode, an empty set
// is returned (no cgroup-level filtering). Unknown pods are silently skipped
// (they may not be cached yet); validation is lenient here because the cgroup
// whitelist is a best-effort optimization — the kernel will just pass more
// events through, and user-space filtering still applies.
func (f *FilterController) resolvePodsToCgroups(podNames []string) (map[uint64]struct{}, error) {
	if len(podNames) == 0 {
		return nil, nil
	}

	if f.resolver == nil || f.resolver.InFallback() {
		// No pod resolution available — return empty set. The user-space filter
		// still applies; we just can't optimize at the kernel level.
		return make(map[uint64]struct{}), nil
	}

	result := make(map[uint64]struct{})
	for _, podName := range podNames {
		// Walk the resolver cache to find cgroup IDs for this pod.
		// The PodResolver caches by cgroup ID → PodInfo, so we need to do a
		// reverse lookup. This is O(cache size) per pod but acceptable for the
		// small sets involved in FilterUpdate operations.
		f.resolver.mu.RLock()
		for cgID, info := range f.resolver.cache {
			if info != nil && info.GetPodName() == podName {
				result[cgID] = struct{}{}
			}
		}
		f.resolver.mu.RUnlock()
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
