// Package controlplane implements the Phase 7 gRPC control-plane subsystem.
//
// This file provides the concrete BPF-map-backed CgroupWhitelist implementation
// (Requirements 5.1 and 6.4). It follows the writeFilterNsIdsToMap precedent:
// the map is obtained via bpf.GetMapFromObjs using the generated field name
// "FilterCgroupMap". Because regenerating Go bindings requires `make build-bpf`
// on a Linux host, this file compiles but the map field will only be present in
// the generated structs after the next BPF code generation pass.
//
// Live-kernel filtering is a deferred-verification item.
package controlplane

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// BPFCgroupWhitelist is the concrete CgroupWhitelist backed by the
// filter_cgroup_map eBPF hash map. It implements Update and Delete by
// forwarding to the cilium/ebpf Map operations, matching the pattern used
// by writeFilterNsIdsToMap in bpf/loader/container.go.
type BPFCgroupWhitelist struct {
	m *ebpf.Map
}

// NewBPFCgroupWhitelist creates a BPFCgroupWhitelist wrapping the given eBPF map.
// The map must be the filter_cgroup_map (BPF_MAP_TYPE_HASH, key=u64, value=u8).
// Returns an error if m is nil.
func NewBPFCgroupWhitelist(m *ebpf.Map) (*BPFCgroupWhitelist, error) {
	if m == nil {
		return nil, errors.New("controlplane: filter_cgroup_map is nil (BPF bindings may need regeneration via make build-bpf)")
	}
	return &BPFCgroupWhitelist{m: m}, nil
}

// Update inserts or overwrites the whitelist entry for the given cgroup ID.
// The value stored is a dummy uint8(0), matching the BPF map value_size of 1.
func (b *BPFCgroupWhitelist) Update(cgroupID uint64) error {
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, cgroupID)
	value := uint8(0)
	if err := b.m.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("filter_cgroup_map update cgroup %d: %w", cgroupID, err)
	}
	return nil
}

// Delete removes the whitelist entry for the given cgroup ID. Returns an error
// if the map operation fails (e.g., key not found is treated as a non-fatal
// condition by the caller in ApplyCgroupWhitelist).
func (b *BPFCgroupWhitelist) Delete(cgroupID uint64) error {
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, cgroupID)
	if err := b.m.Delete(key); err != nil {
		return fmt.Errorf("filter_cgroup_map delete cgroup %d: %w", cgroupID, err)
	}
	return nil
}
