// Package controlplane implements the Phase 7 gRPC control-plane subsystem for
// the Kyanos Agent. Every capability in this package is additive and gated on
// gRPC mode; when the control plane is disabled the Agent behaves exactly as the
// standalone CLI tool.
//
// This file provides the user-space Cgroup_Whitelist reconciliation logic
// (Requirements 5.1 and 6.4). The kernel-side BPF map is abstracted behind the
// CgroupWhitelist interface so the reconciliation logic compiles and is fully
// testable on the current (non-Linux) environment. The concrete map-backed
// implementation is wired separately once the BPF binding is regenerated.
package controlplane

import (
	"errors"
	"fmt"
	"sort"
)

// CgroupWhitelist abstracts the kernel-side BPF map that holds the set of cgroup
// IDs the eBPF program is allowed to emit events for (the Cgroup_Whitelist). The
// interface is intentionally minimal — just the two map operations the
// reconciliation logic needs — so the user-space logic does not depend on a live
// kernel. The concrete BPF-map-backed implementation is provided separately.
type CgroupWhitelist interface {
	// Update inserts or overwrites the whitelist entry for the given cgroup ID.
	Update(cgroupID uint64) error
	// Delete removes the whitelist entry for the given cgroup ID.
	Delete(cgroupID uint64) error
}

// CgroupDiff is the result of reconciling a desired Cgroup_Whitelist against the
// current contents of the BPF map. ToAdd and ToDelete together form the minimal
// set of map operations required to move from the current set to Desired; both
// slices are sorted ascending for deterministic application and testing.
type CgroupDiff struct {
	// Desired is the reconciled target set: (current ∪ add) \ remove.
	Desired map[uint64]struct{}
	// ToAdd are the cgroup IDs present in Desired but absent from current; each
	// needs a CgroupWhitelist.Update call.
	ToAdd []uint64
	// ToDelete are the cgroup IDs present in current but absent from Desired;
	// each needs a CgroupWhitelist.Delete call.
	ToDelete []uint64
}

// CgroupSetFromSlice builds a cgroup-ID set from a slice, de-duplicating ids.
// A nil or empty slice yields an empty (non-nil) set.
func CgroupSetFromSlice(ids []uint64) map[uint64]struct{} {
	set := make(map[uint64]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

// ReconcileCgroups computes the desired Cgroup_Whitelist set (current ∪ add) \
// remove together with the minimal Update/Delete diff needed to bring current to
// that set. It is pure: it does not mutate any of its input maps and performs no
// I/O. Any of the inputs may be nil (treated as the empty set).
//
// The diff is minimal: an entry is only added when it is in the desired set but
// not already present in current, and only deleted when it is present in current
// but not in the desired set. Entries that are unchanged are left untouched.
func ReconcileCgroups(current, add, remove map[uint64]struct{}) CgroupDiff {
	desired := make(map[uint64]struct{}, len(current)+len(add))
	for id := range current {
		desired[id] = struct{}{}
	}
	for id := range add {
		desired[id] = struct{}{}
	}
	for id := range remove {
		delete(desired, id)
	}

	var toAdd, toDelete []uint64
	for id := range desired {
		if _, ok := current[id]; !ok {
			toAdd = append(toAdd, id)
		}
	}
	for id := range current {
		if _, ok := desired[id]; !ok {
			toDelete = append(toDelete, id)
		}
	}
	sortUint64(toAdd)
	sortUint64(toDelete)

	return CgroupDiff{Desired: desired, ToAdd: toAdd, ToDelete: toDelete}
}

// ApplyCgroupWhitelist reconciles current toward (current ∪ add) \ remove and
// applies the resulting minimal diff to the BPF map via w. It attempts every
// operation even if some fail, returning the computed diff and a joined error
// describing all failures (nil when every operation succeeds). Continuing past a
// failed map operation supports the resilience requirement that a partial push
// failure is reported but does not abort reconciliation (Requirement 6.5).
func ApplyCgroupWhitelist(w CgroupWhitelist, current, add, remove map[uint64]struct{}) (CgroupDiff, error) {
	diff := ReconcileCgroups(current, add, remove)

	var errs []error
	for _, id := range diff.ToAdd {
		if err := w.Update(id); err != nil {
			errs = append(errs, fmt.Errorf("update cgroup %d: %w", id, err))
		}
	}
	for _, id := range diff.ToDelete {
		if err := w.Delete(id); err != nil {
			errs = append(errs, fmt.Errorf("delete cgroup %d: %w", id, err))
		}
	}

	return diff, errors.Join(errs...)
}

func sortUint64(s []uint64) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}
