package controlplane

import (
	"context"
	"fmt"
	"sync"

	"kyanos/common"
	"kyanos/proto/agentpb"
)

// PodLister abstracts the Kubernetes API used to list Pods matching a namespace
// and label selector. The concrete implementation wraps a K8s client; tests
// inject fakes. (Requirement 6.1)
type PodLister interface {
	// ListPods returns PodInfo records for every Pod matching the given namespace
	// and label selector. ContainerIds and CgroupIds may be partially filled at
	// this stage (only the K8s-reported container statuses are known). The caller
	// enriches them via ContainerLister and CgroupMapper.
	ListPods(ctx context.Context, namespace, selector string) ([]*agentpb.PodInfo, error)
}

// ContainerLister abstracts the container runtime (CRI/Docker/containerd) used
// to map a Pod's containers to their runtime container identifiers. The concrete
// implementation queries the local container runtime socket; tests inject fakes.
// (Requirement 6.2)
type ContainerLister interface {
	// ContainerIDs returns the runtime container identifiers for the given Pod.
	// The returned slice corresponds to the running containers that belong to the
	// Pod identified by podName in the given namespace.
	ContainerIDs(ctx context.Context, podName, namespace string) ([]string, error)
}

// CgroupMapper abstracts the /proc cgroup traversal that maps container
// identifiers to their kernel cgroup IDs. The concrete implementation walks
// /proc/<pid>/cgroup; tests inject fakes. (Requirement 6.3)
type CgroupMapper interface {
	// CgroupIDs maps a set of container identifiers to their corresponding kernel
	// cgroup IDs. The mapping is performed by inspecting /proc cgroup information
	// for processes belonging to the containers.
	CgroupIDs(ctx context.Context, containerIDs []string) ([]uint64, error)
}

// PodResolver maps kernel-level identifiers (cgroup IDs) to Kubernetes Pod
// metadata. It lists Pods by namespace+selector, obtains container IDs via the
// container runtime, maps those to cgroup IDs via /proc, and pushes the
// resulting whitelist to the BPF map for kernel-side filtering.
//
// The resolver maintains an in-memory cache of cgroup ID → PodInfo so that
// Lookup is fast and lock-free for reads. All live dependencies (K8s API, CRI,
// /proc, BPF map) sit behind interfaces for testability.
//
// Lifecycle:
//   - Call ResolveTargets at startup (before BPF attach) to populate the cache
//     and push the initial Cgroup_Whitelist.
//   - Call Lookup from hot-path event attribution (lock-free read via RWMutex).
//   - If K8s is unreachable at startup, the resolver enters fallback mode
//     (container-id filtering) for the process lifetime (Requirement 6.8).
type PodResolver struct {
	k8s       PodLister       // K8s API: list pods by ns + labels (Req 6.1)
	runtime   ContainerLister // CRI/container runtime: container IDs (Req 6.2)
	cgroups   CgroupMapper    // /proc cgroup traversal (Req 6.3)
	whitelist CgroupWhitelist // BPF map push (Req 6.4)
	namespace string          // target namespace for resolution
	selector  string          // target label selector for resolution

	mu       sync.RWMutex
	cache    map[uint64]*agentpb.PodInfo // cgroup id → PodInfo
	fallback bool                        // K8s unreachable → container-id mode (Req 6.8)
}

// PodResolverConfig holds the construction parameters for a PodResolver.
type PodResolverConfig struct {
	K8s       PodLister
	Runtime   ContainerLister
	Cgroups   CgroupMapper
	Whitelist CgroupWhitelist
	Namespace string
	Selector  string
}

// NewPodResolver constructs a PodResolver from the given configuration. All
// interface fields must be non-nil; the caller is responsible for providing real
// or fake implementations. The resolver starts in non-fallback mode; fallback is
// entered only if K8s is unreachable during ResolveTargets.
func NewPodResolver(cfg PodResolverConfig) *PodResolver {
	return &PodResolver{
		k8s:       cfg.K8s,
		runtime:   cfg.Runtime,
		cgroups:   cfg.Cgroups,
		whitelist: cfg.Whitelist,
		namespace: cfg.Namespace,
		selector:  cfg.Selector,
		cache:     make(map[uint64]*agentpb.PodInfo),
	}
}

// ResolveTargets performs the full Pod resolution pipeline:
//  1. Lists Pods matching namespace+selector via the K8s API (Req 6.1).
//  2. For each Pod, obtains container IDs from the container runtime (Req 6.2).
//  3. Maps container IDs to cgroup IDs via /proc traversal (Req 6.3).
//  4. Pushes the resolved cgroup IDs to the BPF map as the Cgroup_Whitelist (Req 6.4).
//
// On K8s-unreachable at startup: emits a descriptive error and enters fallback
// mode (container-id filtering) for the process lifetime (Req 6.8). The caller
// should check InFallback() and skip further resolution calls.
//
// On BPF map push failure: emits a descriptive error and continues with the
// successfully resolved status rather than terminating (Req 6.5). The cache is
// still populated so Lookup works.
func (p *PodResolver) ResolveTargets(ctx context.Context) error {
	// Step 1: List pods from K8s API.
	pods, err := p.k8s.ListPods(ctx, p.namespace, p.selector)
	if err != nil {
		// K8s unreachable at startup: fall back to container-id mode for the
		// process lifetime (Requirement 6.8).
		p.mu.Lock()
		p.fallback = true
		p.mu.Unlock()
		common.AgentLog.Errorf("PodResolver: K8s API unreachable, falling back to container-id mode: %v", err)
		return fmt.Errorf("K8s API unreachable, entered fallback mode: %w", err)
	}

	// Steps 2–3: For each pod, resolve container IDs → cgroup IDs.
	newCache := make(map[uint64]*agentpb.PodInfo)
	var allCgroupIDs []uint64

	for _, pod := range pods {
		// Step 2: Get container IDs from the container runtime.
		containerIDs, err := p.runtime.ContainerIDs(ctx, pod.GetPodName(), pod.GetNamespace())
		if err != nil {
			common.AgentLog.Warnf("PodResolver: failed to get container IDs for pod %s/%s: %v",
				pod.GetNamespace(), pod.GetPodName(), err)
			continue
		}
		pod.ContainerIds = containerIDs

		// Step 3: Map container IDs to cgroup IDs.
		cgroupIDs, err := p.cgroups.CgroupIDs(ctx, containerIDs)
		if err != nil {
			common.AgentLog.Warnf("PodResolver: failed to map cgroup IDs for pod %s/%s: %v",
				pod.GetNamespace(), pod.GetPodName(), err)
			continue
		}
		pod.CgroupIds = cgroupIDs

		// Populate cache entries: each cgroup ID maps back to this pod's info.
		for _, cgID := range cgroupIDs {
			newCache[cgID] = pod
		}
		allCgroupIDs = append(allCgroupIDs, cgroupIDs...)
	}

	// Update the cache atomically.
	p.mu.Lock()
	p.cache = newCache
	p.mu.Unlock()

	// Step 4: Push the Cgroup_Whitelist to the BPF map.
	// Build the desired set from all resolved cgroup IDs and reconcile against
	// an empty current set (full replacement on initial resolve).
	add := CgroupSetFromSlice(allCgroupIDs)
	_, pushErr := ApplyCgroupWhitelist(p.whitelist, nil, add, nil)
	if pushErr != nil {
		// BPF map push failure: emit error and continue with the resolved
		// status (Requirement 6.5). The cache is populated, Lookup works.
		common.AgentLog.Errorf("PodResolver: BPF map push failed (continuing with resolved status): %v", pushErr)
	}

	return nil
}

// Lookup returns the cached PodInfo for the given cgroup ID. If the cgroup ID
// is present in the cache, the PodInfo is returned with ok=true. If absent, ok
// is false and the caller should treat the identifier as unresolved — processing
// continues without termination (Requirement 6.7).
//
// Lookup is safe for concurrent use and does not block writers for extended
// periods (uses RWMutex read lock).
func (p *PodResolver) Lookup(cgroupID uint64) (*agentpb.PodInfo, bool) {
	p.mu.RLock()
	info, ok := p.cache[cgroupID]
	p.mu.RUnlock()
	return info, ok
}

// InFallback reports whether the resolver has entered fallback mode due to K8s
// being unreachable at startup. In fallback mode the Agent uses the existing
// container-id based filtering for the process lifetime (Requirement 6.8).
func (p *PodResolver) InFallback() bool {
	p.mu.RLock()
	fb := p.fallback
	p.mu.RUnlock()
	return fb
}
