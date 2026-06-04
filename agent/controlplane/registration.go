// Package controlplane implements the Agent-side gRPC control-plane subsystem
// (Phase 7).
//
// This file implements registration and status projection: building the
// AgentInfo message for the initial handshake and producing AgentStatus messages
// when the managed-pod set or discard count changes.
package controlplane

import "kyanos/proto/agentpb"

// buildAgentInfo constructs the registration payload for the Console handshake.
// The Agent is uniquely identified by nodeName (Requirement 2.6, 9.1).
//
// Parameters:
//   - nodeName: the Kubernetes node name; serves as the unique Agent identity.
//   - version: the Agent software version string.
//   - managedPods: the current set of Pods managed by this Agent (from PodResolver).
//
// Returns a fully populated *agentpb.AgentInfo ready for the Connect RPC.
// (Requirements 2.1, 2.6, 9.1)
func buildAgentInfo(nodeName, version string, managedPods []*agentpb.PodInfo) *agentpb.AgentInfo {
	return &agentpb.AgentInfo{
		NodeName:     nodeName,
		AgentVersion: version,
		ManagedPods:  managedPods,
	}
}

// buildStatus compares the current managed-pod set and discard count against a
// previously reported state and returns an *agentpb.AgentStatus only if there
// is a change. If the state has not changed, nil is returned, indicating no
// status report is needed.
//
// Parameters:
//   - nodeName: the Kubernetes node name (Agent identity).
//   - currentPods: the current set of managed Pods (from PodResolver).
//   - discardedEvents: the cumulative number of events discarded by the EventBuffer.
//   - prev: the previously reported AgentStatus (nil on first call, meaning any
//     non-empty state constitutes a change).
//
// Returns a new *agentpb.AgentStatus if the state differs from prev, or nil if
// there is no change to report.
// (Requirements 2.4, 2.6, 9.1)
func buildStatus(
	nodeName string,
	currentPods []*agentpb.PodInfo,
	discardedEvents uint64,
	prev *agentpb.AgentStatus,
) *agentpb.AgentStatus {
	if !statusChanged(currentPods, discardedEvents, prev) {
		return nil
	}
	return &agentpb.AgentStatus{
		NodeName:        nodeName,
		ManagedPods:     currentPods,
		DiscardedEvents: discardedEvents,
	}
}

// statusChanged reports whether the current state differs from the previously
// reported status. A nil prev always indicates a change (first report).
func statusChanged(currentPods []*agentpb.PodInfo, discardedEvents uint64, prev *agentpb.AgentStatus) bool {
	if prev == nil {
		return true
	}
	if discardedEvents != prev.GetDiscardedEvents() {
		return true
	}
	prevPods := prev.GetManagedPods()
	if len(currentPods) != len(prevPods) {
		return true
	}
	// Build a set of pod identities from the previous report for O(n) comparison.
	type podKey struct {
		name      string
		namespace string
	}
	prevSet := make(map[podKey]struct{}, len(prevPods))
	for _, p := range prevPods {
		prevSet[podKey{name: p.GetPodName(), namespace: p.GetNamespace()}] = struct{}{}
	}
	for _, p := range currentPods {
		if _, ok := prevSet[podKey{name: p.GetPodName(), namespace: p.GetNamespace()}]; !ok {
			return true
		}
	}
	return false
}
