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

// TestMinimalFentry3 - minimal fentry WITH bpf_printk
func TestMinimalFentry3(t *testing.T) {
	// Program: bpf_printk("HIT\n", 5); return 0;
	// bpf_trace_printk(fmt, fmt_size) where fmt is inline
	insns := asm.Instructions{
		// r1 = pointer to format string (use LoadImm for inline string)
		// Store "HIT\n\0" on stack
		asm.Mov.Imm(asm.R1, 0x0a544948), // "HIT\n" in little-endian (H=0x48, I=0x49, T=0x54, \n=0x0a)
		asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
		// Store null terminator
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
		// r1 = pointer to format string on stack
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -8),
		// r2 = format string size
		asm.Mov.Imm(asm.R2, 5), // "HIT\n\0" = 5 bytes
		// call bpf_trace_printk
		asm.FnTracePrintk.Call(),
		// return 0
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"test_fentry3": {
				Name:         "test_fentry3",
				Type:         ebpf.Tracing,
				AttachType:   ebpf.AttachTraceFEntry,
				AttachTo:     "__sys_connect",
				License:      "GPL",
				Instructions: insns,
			},
		},
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("Failed to load BPF: %v", err)
	}
	defer coll.Close()

	fmt.Println("[MIN3] BPF loaded")

	prog := coll.Programs["test_fentry3"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		t.Fatalf("Attach failed: %v", err)
	}
	defer l.Close()

	fmt.Println("[MIN3] Attached to __sys_connect")

	// Clear trace pipe
	exec.Command("bash", "-c", "echo '' > /sys/kernel/debug/tracing/trace").Run()

	// Make connection
	fmt.Println("[MIN3] Making connection...")
	exec.Command("bash", "-c", "curl -s --connect-timeout 5 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(1 * time.Second)

	// Check trace
	out, _ := exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/trace 2>&1 | grep HIT | head -5").CombinedOutput()
	traceOut := string(out)
	fmt.Printf("[MIN3] Trace output: '%s'\n", traceOut)

	if len(traceOut) > 0 {
		fmt.Println("[MIN3] SUCCESS: Minimal fentry program FIRED!")
	} else {
		fmt.Println("[MIN3] FAILURE: Minimal fentry program did NOT fire")

		// Also check ALL trace output
		out2, _ := exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/trace 2>&1 | head -20").CombinedOutput()
		fmt.Printf("[MIN3] Full trace:\n%s\n", string(out2))
	}

	// Verify with bpftrace at the same time
	fmt.Println("\n[MIN3] Verifying with bpftrace...")
	exec.Command("bash", "-c", "echo '' > /sys/kernel/debug/tracing/trace").Run()

	bpftraceCmd := exec.Command("bash", "-c",
		"timeout 8 bpftrace -e 'fentry:__sys_connect { printf(\"BPFTRACE_HIT\\n\"); }' 2>&1 &")
	bpftraceCmd.Start()
	time.Sleep(2 * time.Second)

	exec.Command("bash", "-c", "curl -s --connect-timeout 5 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(2 * time.Second)
	bpftraceCmd.Wait()

	out, _ = exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/trace 2>&1 | grep -E 'HIT|BPFTRACE' | head -10").CombinedOutput()
	fmt.Printf("[MIN3] Combined trace:\n%s\n", string(out))
}
