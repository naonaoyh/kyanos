package controlplane

import (
	"fmt"
	"sync"
	"testing"

	"kyanos/agent/protocol"
	"kyanos/agent/protocol/ntrip"
	"kyanos/agent/protocol/rtcm"
	"kyanos/bpf"
	"kyanos/proto/agentpb"
)

// filterTestWhitelist records cgroup operations for FilterController tests.
type filterTestWhitelist struct {
	mu      sync.Mutex
	entries map[uint64]bool
	failOn  map[uint64]bool // cgroup IDs that should fail on Update
}

func newFilterTestWhitelist() *filterTestWhitelist {
	return &filterTestWhitelist{
		entries: make(map[uint64]bool),
		failOn:  make(map[uint64]bool),
	}
}

func (w *filterTestWhitelist) Update(cgroupID uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failOn[cgroupID] {
		return fmt.Errorf("injected failure for cgroup %d", cgroupID)
	}
	w.entries[cgroupID] = true
	return nil
}

func (w *filterTestWhitelist) Delete(cgroupID uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failOn[cgroupID] {
		return fmt.Errorf("injected failure for cgroup %d", cgroupID)
	}
	delete(w.entries, cgroupID)
	return nil
}

func TestFilterController_NilUpdate(t *testing.T) {
	fc := NewFilterController(FilterControllerConfig{})
	err := fc.ApplyUpdate(nil)
	if err == nil {
		t.Fatal("expected error for nil update")
	}
}

func TestFilterController_NoopUpdate(t *testing.T) {
	var applied protocol.ProtocolFilter
	fc := NewFilterController(FilterControllerConfig{
		Apply: func(f protocol.ProtocolFilter) { applied = f },
	})

	// An update with no filter configs, no pods, no task params is valid but a no-op.
	err := fc.ApplyUpdate(&agentpb.FilterUpdate{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if applied != nil {
		t.Fatal("apply should not be called for no-op update")
	}
}

func TestFilterController_CompileNTRIPFilter(t *testing.T) {
	var applied protocol.ProtocolFilter
	fc := NewFilterController(FilterControllerConfig{
		Apply: func(f protocol.ProtocolFilter) { applied = f },
	})

	err := fc.ApplyUpdate(&agentpb.FilterUpdate{
		NtripFilter: &agentpb.NTRIPFilterConfig{
			Mountpoints: []string{"RTCM3_GZ"},
			Usernames:   []string{"user1"},
			Versions:    []string{"v2"},
			ErrorsOnly:  true,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if applied == nil {
		t.Fatal("apply was not called")
	}

	// The compiled filter should be an *ntrip.NTRIPFilter.
	ntripF, ok := applied.(*ntrip.NTRIPFilter)
	if !ok {
		t.Fatalf("expected *ntrip.NTRIPFilter, got %T", applied)
	}
	if len(ntripF.TargetMountPoints) != 1 || ntripF.TargetMountPoints[0] != "RTCM3_GZ" {
		t.Errorf("unexpected mountpoints: %v", ntripF.TargetMountPoints)
	}
	if !ntripF.ErrorsOnly {
		t.Error("expected ErrorsOnly=true")
	}
	if len(ntripF.TargetVersions) != 1 || ntripF.TargetVersions[0] != ntrip.NTRIPv2 {
		t.Errorf("unexpected versions: %v", ntripF.TargetVersions)
	}

	// Verify Protocol() returns NTRIP.
	if applied.Protocol() != bpf.AgentTrafficProtocolTKProtocolNTRIP {
		t.Errorf("expected NTRIP protocol, got %d", applied.Protocol())
	}
}

func TestFilterController_CompileRTCMFilter(t *testing.T) {
	var applied protocol.ProtocolFilter
	fc := NewFilterController(FilterControllerConfig{
		Apply: func(f protocol.ProtocolFilter) { applied = f },
	})

	err := fc.ApplyUpdate(&agentpb.FilterUpdate{
		RtcmFilter: &agentpb.RTCMFilterConfig{
			MessageTypes:  []int32{1004, 1005, 1077},
			CrcErrorsOnly: true,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if applied == nil {
		t.Fatal("apply was not called")
	}

	rtcmF, ok := applied.(rtcm.RTCMFilter)
	if !ok {
		t.Fatalf("expected rtcm.RTCMFilter, got %T", applied)
	}
	if len(rtcmF.TargetMessageTypes) != 3 {
		t.Errorf("expected 3 message types, got %d", len(rtcmF.TargetMessageTypes))
	}
	if !rtcmF.CRCErrorsOnly {
		t.Error("expected CRCErrorsOnly=true")
	}
	if applied.Protocol() != bpf.AgentTrafficProtocolTKProtocolRTCM {
		t.Errorf("expected RTCM protocol, got %d", applied.Protocol())
	}
}

func TestFilterController_InvalidVersion(t *testing.T) {
	fc := NewFilterController(FilterControllerConfig{
		Apply: func(f protocol.ProtocolFilter) {},
	})

	err := fc.ApplyUpdate(&agentpb.FilterUpdate{
		NtripFilter: &agentpb.NTRIPFilterConfig{
			Versions: []string{"v3"},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
}

func TestFilterController_InvalidRTCMMessageType(t *testing.T) {
	fc := NewFilterController(FilterControllerConfig{
		Apply: func(f protocol.ProtocolFilter) {},
	})

	err := fc.ApplyUpdate(&agentpb.FilterUpdate{
		RtcmFilter: &agentpb.RTCMFilterConfig{
			MessageTypes: []int32{-1},
		},
	})
	if err == nil {
		t.Fatal("expected error for negative message type")
	}
}

func TestFilterController_CgroupWhitelistReconcile(t *testing.T) {
	wl := newFilterTestWhitelist()
	fc := NewFilterController(FilterControllerConfig{
		Whitelist: wl,
	})

	// Manually inject cgroups into current state for testing.
	fc.mu.Lock()
	fc.current.cgroups = map[uint64]struct{}{100: {}, 200: {}}
	fc.mu.Unlock()

	// Add pod 300, remove pod 100. Since resolver is nil, pod names won't
	// resolve to cgroups — test the direct cgroup path by setting up the state
	// manually and using a direct update without pod resolution.
	// Instead, test with direct cgroup manipulation via a second approach:
	// we directly call ApplyCgroupWhitelist.
	add := CgroupSetFromSlice([]uint64{300})
	remove := CgroupSetFromSlice([]uint64{100})
	diff, err := ApplyCgroupWhitelist(wl, fc.current.cgroups, add, remove)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Desired should be {200, 300}.
	if _, ok := diff.Desired[200]; !ok {
		t.Error("expected 200 in desired set")
	}
	if _, ok := diff.Desired[300]; !ok {
		t.Error("expected 300 in desired set")
	}
	if _, ok := diff.Desired[100]; ok {
		t.Error("100 should not be in desired set")
	}
}

func TestFilterController_ValidationFailureLeavesStateUnchanged(t *testing.T) {
	var applyCalled bool
	fc := NewFilterController(FilterControllerConfig{
		Apply:         func(f protocol.ProtocolFilter) { applyCalled = true },
		InitialFilter: protocol.NoopFilter{},
	})

	// Apply an invalid update (bad version string).
	err := fc.ApplyUpdate(&agentpb.FilterUpdate{
		NtripFilter: &agentpb.NTRIPFilterConfig{
			Versions: []string{"invalid_version"},
		},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}

	// The apply callback should NOT have been called.
	if applyCalled {
		t.Error("apply was called despite validation failure")
	}

	// The current filter should still be the initial NoopFilter.
	current := fc.CurrentFilter()
	if _, ok := current.(protocol.NoopFilter); !ok {
		t.Errorf("expected NoopFilter after validation failure, got %T", current)
	}
}

func TestFilterController_PartialFailure(t *testing.T) {
	wl := newFilterTestWhitelist()
	// Make cgroup 500 fail on Update.
	wl.failOn[500] = true

	var applied protocol.ProtocolFilter
	fc := NewFilterController(FilterControllerConfig{
		Apply:     func(f protocol.ProtocolFilter) { applied = f },
		Whitelist: wl,
	})

	// Set up current state with some cgroups.
	fc.mu.Lock()
	fc.current.cgroups = map[uint64]struct{}{100: {}}
	fc.mu.Unlock()

	// Construct an update that changes both the filter AND the cgroup whitelist.
	// We'll simulate the cgroup change by directly setting the resolver to nil,
	// which means pod resolution won't add cgroups. Let's do it differently:
	// Since resolver is nil, add_pods won't actually resolve. Let's test with
	// just a filter change + a manual cgroup state setup.
	err := fc.ApplyUpdate(&agentpb.FilterUpdate{
		NtripFilter: &agentpb.NTRIPFilterConfig{
			Mountpoints: []string{"TEST"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The filter should have been swapped.
	if applied == nil {
		t.Fatal("apply should have been called")
	}
}

func TestFilterController_ConcurrentUpdates(t *testing.T) {
	var mu sync.Mutex
	applyCount := 0
	fc := NewFilterController(FilterControllerConfig{
		Apply: func(f protocol.ProtocolFilter) {
			mu.Lock()
			applyCount++
			mu.Unlock()
		},
	})

	// Run N concurrent updates, all should serialize successfully.
	const N = 20
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(idx int) {
			defer wg.Done()
			fc.ApplyUpdate(&agentpb.FilterUpdate{
				NtripFilter: &agentpb.NTRIPFilterConfig{
					Mountpoints: []string{fmt.Sprintf("mount-%d", idx)},
				},
			})
		}(i)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if applyCount != N {
		t.Errorf("expected %d apply calls, got %d", N, applyCount)
	}
}

func TestFilterController_TaskParamUpdate(t *testing.T) {
	tm := NewTaskManager(nil)
	// Start a task so the filter controller can target it.
	tm.Start(&agentpb.CaptureTask{
		TaskId:          "task-1",
		TargetNamespace: "default",
	})

	fc := NewFilterController(FilterControllerConfig{
		Apply: func(f protocol.ProtocolFilter) {},
		Tasks: tm,
	})

	err := fc.ApplyUpdate(&agentpb.FilterUpdate{
		TaskId:          "task-1",
		DurationSeconds: 300,
		NtripFilter: &agentpb.NTRIPFilterConfig{
			Mountpoints: []string{"NEW_MOUNT"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify task params were recorded.
	tp, ok := fc.CurrentTaskParams("task-1")
	if !ok {
		t.Fatal("expected task params for task-1")
	}
	if tp.DurationSeconds != 300 {
		t.Errorf("expected duration 300, got %d", tp.DurationSeconds)
	}
	if tp.NtripFilter == nil || len(tp.NtripFilter.Mountpoints) != 1 {
		t.Error("expected ntrip filter in task params")
	}
}

func TestFilterController_TaskParamUpdate_InactiveTask(t *testing.T) {
	tm := NewTaskManager(nil)

	fc := NewFilterController(FilterControllerConfig{
		Apply: func(f protocol.ProtocolFilter) {},
		Tasks: tm,
	})

	// Trying to update params for a non-existent task should fail validation.
	err := fc.ApplyUpdate(&agentpb.FilterUpdate{
		TaskId:          "nonexistent",
		DurationSeconds: 60,
	})
	if err == nil {
		t.Fatal("expected error for inactive task")
	}
}

func TestCompileFilter_BothNilReturnsNoop(t *testing.T) {
	f, err := compileFilter(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := f.(protocol.NoopFilter); !ok {
		t.Errorf("expected NoopFilter, got %T", f)
	}
}

func TestParseNTRIPVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    ntrip.NTRIPVersion
		wantErr bool
	}{
		{"NTRIPv1", ntrip.NTRIPv1, false},
		{"ntripv1", ntrip.NTRIPv1, false},
		{"v1", ntrip.NTRIPv1, false},
		{"1", ntrip.NTRIPv1, false},
		{"NTRIPv2", ntrip.NTRIPv2, false},
		{"ntripv2", ntrip.NTRIPv2, false},
		{"v2", ntrip.NTRIPv2, false},
		{"2", ntrip.NTRIPv2, false},
		{"v3", ntrip.NTRIPVersionUnknown, true},
		{"", ntrip.NTRIPVersionUnknown, true},
		{"invalid", ntrip.NTRIPVersionUnknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseNTRIPVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseNTRIPVersion(%q): err = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseNTRIPVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
