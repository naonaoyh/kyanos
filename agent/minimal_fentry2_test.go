package agent_test

import (
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// TestMinimalFentry2 - simplest possible fentry test
func TestMinimalFentry2(t *testing.T) {
	// Simplest possible fentry program: just return 0
	// asm.Instructions for: r0 = 0; return;
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"test_fentry": {
				Name:         "test_fentry",
				Type:         ebpf.Tracing,
				AttachType:   ebpf.AttachTraceFEntry,
				AttachTo:     "__sys_connect",
				License:      "GPL",
				Instructions: insns,
			},
		},
	}

	// Load with verbose verifier log
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	})
	if err != nil {
		t.Fatalf("Failed to load minimal fentry BPF: %v", err)
	}
	defer coll.Close()

	fmt.Println("[MIN2] BPF loaded successfully")

	prog := coll.Programs["test_fentry"]
	if prog == nil {
		t.Fatal("program not found")
	}

	// Get program info
	info, _ := prog.Info()
	fmt.Printf("[MIN2] Program info: type=%v name=%s\n", info.Type, info.Name)

	// Attach
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		t.Fatalf("AttachTracing failed: %v", err)
	}
	defer l.Close()

	fmt.Println("[MIN2] Attached to __sys_connect via fentry!")

	// Check link info
	out, _ := exec.Command("bpftool", "link", "list").CombinedOutput()
	fmt.Printf("[MIN2] Links:\n%s\n", string(out))

	// Check prog run_cnt
	out, _ = exec.Command("bash", "-c", "bpftool prog show name test_fentry 2>&1").CombinedOutput()
	fmt.Printf("[MIN2] Prog before:\n%s\n", string(out))

	// Make a connection
	fmt.Println("[MIN2] Making connection...")
	exec.Command("bash", "-c", "curl -s --connect-timeout 5 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(500 * time.Millisecond)

	// Check prog run_cnt AFTER
	out, _ = exec.Command("bash", "-c", "bpftool prog show name test_fentry 2>&1").CombinedOutput()
	fmt.Printf("[MIN2] Prog after:\n%s\n", string(out))

	// Also try tracepoint
	fmt.Println("\n[MIN2] === Now trying tracepoint ===")
	spec2 := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"test_tp": {
				Name:       "test_tp",
				Type:       ebpf.TracePoint,
				License:    "GPL",
				Instructions: asm.Instructions{
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				},
			},
		},
	}
	coll2, err := ebpf.NewCollection(spec2)
	if err != nil {
		t.Fatalf("Tracepoint load failed: %v", err)
	}
	defer coll2.Close()

	prog2 := coll2.Programs["test_tp"]
	l2, err := link.Tracepoint("syscalls", "sys_enter_connect", prog2, nil)
	if err != nil {
		t.Fatalf("Tracepoint attach failed: %v", err)
	}
	defer l2.Close()

	fmt.Println("[MIN2] Tracepoint attached!")

	out, _ = exec.Command("bash", "-c", "bpftool prog show name test_tp 2>&1").CombinedOutput()
	fmt.Printf("[MIN2] TP prog before:\n%s\n", string(out))

	exec.Command("bash", "-c", "curl -s --connect-timeout 5 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(500 * time.Millisecond)

	out, _ = exec.Command("bash", "-c", "bpftool prog show name test_tp 2>&1").CombinedOutput()
	fmt.Printf("[MIN2] TP prog after:\n%s\n", string(out))

	fmt.Println("[MIN2] Done")
}
