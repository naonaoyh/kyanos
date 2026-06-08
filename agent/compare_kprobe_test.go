package agent_test

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// TestCompareKprobe - Compare cilium/ebpf kprobe with bpftrace kprobe
func TestCompareKprobe(t *testing.T) {
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R1, 0x0a544948),
		asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -8),
		asm.Mov.Imm(asm.R2, 5),
		asm.FnTracePrintk.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	// Step 1: Load cilium/ebpf kprobe
	fmt.Println("=== Step 1: cilium/ebpf kprobe ===")
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"cilium_kp": {
				Name:       "cilium_kp",
				Type:       ebpf.Kprobe,
				AttachType: ebpf.AttachNone,
				License:    "GPL",
				Instructions: insns,
			},
		},
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["cilium_kp"]
	info, _ := prog.Info()
	id, _ := info.ID()
	fmt.Printf("cilium/ebpf prog ID: %d\n", id)

	kp, err := link.Kprobe("__sys_connect", prog, nil)
	if err != nil {
		t.Fatalf("Attach failed: %v", err)
	}
	defer kp.Close()

	// Dump full prog info
	out, _ := exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1", id)).CombinedOutput()
	fmt.Printf("prog show:\n%s\n", string(out))

	out, _ = exec.Command("bash", "-c", "bpftool link show 2>&1").CombinedOutput()
	fmt.Printf("link show:\n%s\n", string(out))

	// Clear trace and test
	exec.Command("bash", "-c", "echo > /sys/kernel/tracing/trace").Run()
	exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(500 * time.Millisecond)

	out, _ = exec.Command("bash", "-c", "cat /sys/kernel/tracing/trace 2>&1").CombinedOutput()
	traceOut := string(out)
	ciliumHits := strings.Count(traceOut, "bpf_trace_printk: HIT")
	fmt.Printf("cilium/ebpf kprobe hits: %d\n", ciliumHits)

	// Step 2: Also start bpftrace kprobe at the same time
	fmt.Println("\n=== Step 2: bpftrace kprobe (while cilium kprobe is active) ===")
	exec.Command("bash", "-c", "echo > /sys/kernel/tracing/trace").Run()

	bpftraceCmd := exec.Command("bash", "-c",
		`timeout 8 bpftrace -e 'kprobe:__sys_connect { printf("BPFTRACE_HIT\n"); }' 2>&1`)
	bpftraceOut, _ := bpftraceCmd.CombinedOutput()
	fmt.Printf("bpftrace loaded:\n%s\n", string(bpftraceOut))

	// Check bpftool while bpftrace is running
	// Actually bpftrace already exited. Let me run it in background
	exec.Command("bash", "-c", "echo > /sys/kernel/tracing/trace").Run()

	btCmd := exec.Command("bash", "-c",
		`timeout 8 bpftrace -e 'kprobe:__sys_connect { printf("BPFTRACE_HIT\n"); }' > /tmp/bt_out.txt 2>&1 &`)
	btCmd.Run()
	time.Sleep(2 * time.Second)

	// Show all links and progs
	out, _ = exec.Command("bash", "-c", "bpftool link show 2>&1").CombinedOutput()
	fmt.Printf("links during both:\n%s\n", string(out))

	out, _ = exec.Command("bash", "-c", "bpftool prog show 2>&1 | grep -i kprobe").CombinedOutput()
	fmt.Printf("progs during both:\n%s\n", string(out))

	// Trigger connect
	exec.Command("bash", "-c", "echo > /sys/kernel/tracing/trace").Run()
	exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(1 * time.Second)

	// Check trace
	out, _ = exec.Command("bash", "-c", "cat /sys/kernel/tracing/trace 2>&1").CombinedOutput()
	traceOut = string(out)
	ciliumHits2 := strings.Count(traceOut, "bpf_trace_printk: HIT")
	btHits := strings.Count(traceOut, "BPFTRACE_HIT")
	fmt.Printf("cilium/ebpf hits: %d\n", ciliumHits2)
	fmt.Printf("bpftrace hits: %d\n", btHits)
	fmt.Printf("full trace:\n%s\n", traceOut)

	// Wait for bpftrace to finish
	time.Sleep(5 * time.Second)
	out, _ = exec.Command("bash", "-c", "cat /tmp/bt_out.txt 2>&1").CombinedOutput()
	fmt.Printf("bpftrace final output:\n%s\n", string(out))

	// Step 3: Compare the BPF program flags
	fmt.Println("\n=== Step 3: Detailed program comparison ===")
	out, _ = exec.Command("bash", "-c", "bpftool prog show 2>&1 | grep kprobe").CombinedOutput()
	fmt.Printf("All kprobe progs:\n%s\n", string(out))
}
