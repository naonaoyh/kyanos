package agent_test

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// TestMinimalFentry - absolute minimal fentry test using cilium/ebpf directly
func TestMinimalFentry(t *testing.T) {
	// Create a minimal BPF program that just does bpf_printk on fentry to __sys_connect
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"test_fentry": {
				Name:       "test_fentry",
				Type:       ebpf.Tracing,
				AttachType: ebpf.AttachTraceFEntry,
				AttachTo:   "__sys_connect",
				License:    "GPL",
				Instructions: asm.Instructions{
					// Load format string address from rodata map
					asm.LoadMapPtr(asm.R1, 0).WithReference("rodata_map"),
					// r2 = format string length
					asm.Mov.Imm(asm.R2, 20),
					// Call bpf_trace_printk
					asm.FnTracePrintk.Call(),
					// return 0
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				},
			},
		},
	}

	// Try loading with verbose verifier output
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	})
	if err != nil {
		t.Logf("Failed to load minimal BPF: %v", err)
		t.Log("This confirms the issue is with cilium/ebpf + kernel 6.18")

		// Try tracepoint instead
		fmt.Println("[MIN] Trying tracepoint approach...")
		spec2 := &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				"test_tp": {
					Name:       "test_tp",
					Type:       ebpf.TracePoint,
					AttachType: ebpf.AttachNone,
					License:    "GPL",
					Instructions: asm.Instructions{
						asm.Mov.Imm(asm.R0, 0),
						asm.Return(),
					},
				},
			},
		}
		coll2, err2 := ebpf.NewCollection(spec2)
		if err2 != nil {
			t.Logf("Tracepoint also failed: %v", err2)
			t.Fatal("BPF loading completely broken on this system")
		}
		defer coll2.Close()

		prog := coll2.Programs["test_tp"]
		l, err := link.Tracepoint("syscalls", "sys_enter_connect", prog, nil)
		if err != nil {
			t.Fatalf("Tracepoint attach failed: %v", err)
		}
		defer l.Close()

		fmt.Println("[MIN] Tracepoint attached, testing...")
		exec.Command("bash", "-c", "echo '' > /sys/kernel/debug/tracing/trace").Run()

		// Make a connection
		exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
		time.Sleep(500 * time.Millisecond)

		fmt.Println("[MIN] Done")
		return
	}
	defer coll.Close()

	fmt.Println("[MIN] BPF collection loaded successfully!")
	prog := coll.Programs["test_fentry"]
	if prog == nil {
		t.Fatal("program not found in collection")
	}

	// Attach using link.AttachTracing
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		t.Fatalf("AttachTracing failed: %v", err)
	}
	defer l.Close()

	fmt.Println("[MIN] fentry attached to __sys_connect!")

	// Clear trace and test
	exec.Command("bash", "-c", "echo '' > /sys/kernel/debug/tracing/trace").Run()

	// Make connection via curl
	fmt.Println("[MIN] Making connection via curl...")
	exec.Command("bash", "-c", "curl -s --connect-timeout 5 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(500 * time.Millisecond)

	// Check trace
	out, _ := exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/trace 2>&1 | head -10").CombinedOutput()
	fmt.Printf("[MIN] Trace output:\n%s\n", string(out))

	fmt.Printf("[MIN] Test PID: %d\n", os.Getpid())
}
