package agent_test

import (
	"fmt"
	"kyanos/bpf"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
)

// TestBPFSmokeTest isolates BPF loading from agent startup to pinpoint hangs.
func TestBPFSmokeTest(t *testing.T) {
	fmt.Println("[DIAG-1] BTF check...")
	hasBTF := bpf.IsKernelSupportHasBTF()
	fmt.Printf("[DIAG-1]   Kernel BTF available: %v\n", hasBTF)

	fmt.Println("[DIAG-2] RemoveMemlock...")
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Printf("[DIAG-2]   RemoveMemlock: %v (non-fatal)\n", err)
	} else {
		fmt.Println("[DIAG-2]   OK")
	}

	fmt.Println("[DIAG-3] Loading BPF collection spec from embedded bytecode...")
	spec, err := bpf.LoadAgent()
	if err != nil {
		t.Fatalf("LoadAgent() failed: %v", err)
	}
	fmt.Printf("[DIAG-3]   OK: %d programs, %d maps in spec\n", len(spec.Programs), len(spec.Maps))

	fmt.Println("[DIAG-4] LoadAndAssign into kernel (up to 120s)...")
	objs := &bpf.AgentObjects{}
	collOpts := &ebpf.CollectionOptions{}
	if hasBTF {
		btfSpec, btfErr := btf.LoadKernelSpec()
		if btfErr == nil {
			collOpts.Programs.KernelTypes = btfSpec
			fmt.Println("[DIAG-4]   Using kernel BTF for CO-RE")
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- spec.LoadAndAssign(objs, collOpts)
	}()

	for i := 0; i < 12; i++ {
		select {
		case err := <-done:
			if err != nil {
				fmt.Printf("[DIAG-4]   FAILED after %ds: %v\n", (i+1)*10, err)
				t.Fatalf("LoadAndAssign failed: %v", err)
			}
			fmt.Printf("[DIAG-4]   SUCCESS after ~%ds!\n", (i+1)*10)
			objs.Close()
			fmt.Println("[DIAG] BPF smoke test PASSED - BPF loading works fine")
			return
		case <-time.After(10 * time.Second):
			fmt.Printf("[DIAG-4]   Still loading... (%ds elapsed)\n", (i+1)*10)
		}
	}
	t.Fatal("LoadAndAssign timed out after 120 seconds")
}

// TestAgentPreBPFInit tests the agent initialization steps BEFORE BPF loading.
func TestAgentPreBPFInit(t *testing.T) {
	fmt.Println("[DIAG-A] common.IsEnableBPF()...")
	// We import common through the ac alias in other test files,
	// but here we call it through the agent package
	fmt.Println("[DIAG-A]   (needs agent/common import, checking via /proc/config.gz)")

	fmt.Println("[DIAG-B] HasPermission (CAP_BPF check)...")
	// This is ac.HasPermission() - we can't easily call it without importing ac
	fmt.Println("[DIAG-B]   (needs agent/common import)")

	fmt.Println("[DIAG-C] Checking PID and process info...")
	fmt.Printf("[DIAG-C]   PID: %d, PPID: %d\n", os.Getpid(), os.Getppid())

	fmt.Println("[DIAG-D] Checking /proc/config.gz for BPF support...")
	data, err := os.ReadFile("/proc/config.gz")
	if err != nil {
		fmt.Printf("[DIAG-D]   Cannot read /proc/config.gz: %v\n", err)
	} else {
		fmt.Printf("[DIAG-D]   /proc/config.gz: %d bytes\n", len(data))
	}

	fmt.Println("[DIAG-E] Checking /sys/kernel/btf/vmlinux...")
	info, err := os.Stat("/sys/kernel/btf/vmlinux")
	if err != nil {
		fmt.Printf("[DIAG-E]   Not found: %v\n", err)
	} else {
		fmt.Printf("[DIAG-E]   Found: %d bytes\n", info.Size())
	}

	fmt.Println("[DIAG] Pre-BPF init checks PASSED")
}
