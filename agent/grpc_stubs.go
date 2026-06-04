// Package agent provides the main Agent lifecycle (SetupAgent) and wiring.
//
// This file contains no-op stub implementations of the controlplane interfaces
// that depend on live systems (K8s API, container runtime, /proc, BPF map).
// These stubs allow the gRPC control-plane wiring in SetupAgent to compile and
// run on the current environment; the concrete implementations are deferred-
// verification items that will be wired once the Linux/TKE environment is
// available. See docs/ROADMAP_NEXT.md for the deferred backlog.
package agent

import (
	"context"

	"kyanos/agent/controlplane"
	"kyanos/proto/agentpb"
)

// Compile-time interface assertions.
var (
	_ controlplane.PodLister       = noopPodLister{}
	_ controlplane.ContainerLister = noopContainerLister{}
	_ controlplane.CgroupMapper    = noopCgroupMapper{}
	_ controlplane.CgroupWhitelist = noopCgroupWhitelist{}
)

// noopPodLister is a no-op PodLister that returns an empty Pod list. It is
// used when the concrete K8s API client is not yet available (deferred).
type noopPodLister struct{}

func (noopPodLister) ListPods(_ context.Context, _, _ string) ([]*agentpb.PodInfo, error) {
	return nil, nil
}

// noopContainerLister is a no-op ContainerLister that returns no container IDs.
// Used when the concrete CRI client is not yet available (deferred).
type noopContainerLister struct{}

func (noopContainerLister) ContainerIDs(_ context.Context, _, _ string) ([]string, error) {
	return nil, nil
}

// noopCgroupMapper is a no-op CgroupMapper that returns no cgroup IDs. Used
// when the concrete /proc traversal is not yet available (deferred).
type noopCgroupMapper struct{}

func (noopCgroupMapper) CgroupIDs(_ context.Context, _ []string) ([]uint64, error) {
	return nil, nil
}

// noopCgroupWhitelist is a no-op CgroupWhitelist implementation. Used when
// the concrete BPF-map-backed implementation is not available (deferred).
type noopCgroupWhitelist struct{}

func (noopCgroupWhitelist) Update(_ uint64) error { return nil }
func (noopCgroupWhitelist) Delete(_ uint64) error { return nil }
