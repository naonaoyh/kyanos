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

// TestMinimalFentry4 - Deep diagnostics on why fentry doesn't fire
func TestMinimalFentry4(t *testing.T) {
	// Step 1: Check kernel config for BPF tracing support
	fmt.Println("=== Step 1: Kernel BPF config ===")
	for _, cfg := range []string{
		"CONFIG_BPF", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_JIT",
		"CONFIG_HAVE_BPF_JIT", "CONFIG_BPF_EVENTS",
		"CONFIG_FTRACE", "CONFIG_FUNCTION_TRACER",
		"CONFIG_DYNAMIC_FTRACE", "CONFIG_BPF_KPROBE_OVERRIDE",
		"CONFIG_DEBUG_INFO_BTF",
	} {
		out, _ := exec.Command("bash", "-c", fmt.Sprintf("zcat /proc/config.gz 2>/dev/null | grep '^%s=' || cat /boot/config-$(uname -r) 2>/dev/null | grep '^%s=' || echo '%s=NOT_FOUND'", cfg, cfg, cfg)).CombinedOutput()
		fmt.Printf("  %s\n", strings.TrimSpace(string(out)))
	}

	// Step 2: Check ftrace/tracing state
	fmt.Println("\n=== Step 2: Tracing state ===")
	out, _ := exec.Command("bash", "-c", "cat /sys/kernel/tracing/tracing_on 2>/dev/null || cat /sys/kernel/debug/tracing/tracing_on 2>/dev/null").CombinedOutput()
	fmt.Printf("  tracing_on: %s\n", strings.TrimSpace(string(out)))

	out, _ = exec.Command("bash", "-c", "cat /sys/kernel/tracing/current_tracer 2>/dev/null").CombinedOutput()
	fmt.Printf("  current_tracer: %s\n", strings.TrimSpace(string(out)))

	// Step 3: Check available filter functions (does __sys_connect exist?)
	fmt.Println("\n=== Step 3: __sys_connect in ftrace ===")
	out, _ = exec.Command("bash", "-c", "grep -c '__sys_connect' /sys/kernel/tracing/available_filter_functions 2>/dev/null || echo 'NOT_FOUND'").CombinedOutput()
	fmt.Printf("  available_filter_functions: %s\n", strings.TrimSpace(string(out)))

	out, _ = exec.Command("bash", "-c", "grep '__sys_connect' /sys/kernel/tracing/available_filter_functions 2>/dev/null | head -3").CombinedOutput()
	fmt.Printf("  match: %s\n", strings.TrimSpace(string(out)))

	// Step 4: Check BTF for __sys_connect
	fmt.Println("\n=== Step 4: BTF info ===")
	out, _ = exec.Command("bash", "-c", "bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep '__sys_connect' | head -5").CombinedOutput()
	fmt.Printf("  BTF __sys_connect: %s\n", strings.TrimSpace(string(out)))

	// Step 5: Load and attach fentry, then dump everything
	fmt.Println("\n=== Step 5: Load fentry program ===")

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

	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"test_fentry4": {
				Name:         "test_fentry4",
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

	prog := coll.Programs["test_fentry4"]

	// Dump program info
	info, err := prog.Info()
	if err != nil {
		t.Fatalf("Info failed: %v", err)
	}
	fmt.Printf("  Program type: %v\n", info.Type)

	id, _ := info.ID()
	fmt.Printf("  Program ID: %d\n", id)
	fmt.Printf("  Name: %s\n", info.Name)
	fmt.Printf("  Tag: %s\n", info.Tag)

	// Check xlated instructions
	out, _ = exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1", id)).CombinedOutput()
	fmt.Printf("  bpftool prog show:\n%s\n", string(out))

	out, _ = exec.Command("bash", "-c", fmt.Sprintf("bpftool prog dump xlated id %d 2>&1", id)).CombinedOutput()
	fmt.Printf("  xlated:\n%s\n", string(out))

	// Attach
	fmt.Println("\n=== Step 6: Attach ===")
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		t.Fatalf("Attach failed: %v", err)
	}
	defer l.Close()
	fmt.Println("  Attached successfully")

	// Check link info
	out, _ = exec.Command("bash", "-c", "bpftool link show 2>&1 | head -30").CombinedOutput()
	fmt.Printf("  bpftool link show:\n%s\n", string(out))

	// Check prog run count before
	out, _ = exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1 | grep -o 'run_cnt [0-9]*'", id)).CombinedOutput()
	runCntBefore := strings.TrimSpace(string(out))
	fmt.Printf("  run_cnt before: %s\n", runCntBefore)

	// Clear trace and trigger
	exec.Command("bash", "-c", "echo '' > /sys/kernel/debug/tracing/trace").Run()

	// Trigger connect
	fmt.Println("\n=== Step 7: Trigger ===")
	fmt.Println("  Running curl...")
	curlOut, _ := exec.Command("bash", "-c", "curl -s --connect-timeout 5 http://www.baidu.com > /dev/null 2>&1; echo exit=$?").CombinedOutput()
	fmt.Printf("  curl: %s\n", strings.TrimSpace(string(curlOut)))
	time.Sleep(500 * time.Millisecond)

	// Check run count after
	out, _ = exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1 | grep -o 'run_cnt [0-9]*'", id)).CombinedOutput()
	runCntAfter := strings.TrimSpace(string(out))
	fmt.Printf("  run_cnt after: %s\n", runCntAfter)

	// Check trace
	out, _ = exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/trace 2>&1 | head -20").CombinedOutput()
	fmt.Printf("  trace_pipe:\n%s\n", string(out))

	// Step 8: Try kprobe as comparison
	fmt.Println("\n=== Step 8: Kprobe comparison ===")
	kprobeSpec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"test_kprobe4": {
				Name:         "test_kprobe4",
				Type:         ebpf.Kprobe,
				AttachType:   ebpf.AttachNone,
				License:      "GPL",
				Instructions: insns, // Same bpf_printk instructions
			},
		},
	}

	kcoll, kerr := ebpf.NewCollection(kprobeSpec)
	if kerr != nil {
		fmt.Printf("  Kprobe load failed: %v\n", kerr)
	} else {
		defer kcoll.Close()
		kprog := kcoll.Programs["test_kprobe4"]

		kinfo, _ := kprog.Info()
		kid, _ := kinfo.ID()
		fmt.Printf("  Kprobe prog ID: %d\n", kid)

		kp, kerr := link.Kprobe("__sys_connect", kprog, nil)
		if kerr != nil {
			fmt.Printf("  Kprobe attach failed: %v\n", kerr)
		} else {
			defer kp.Close()
			fmt.Println("  Kprobe attached")

			exec.Command("bash", "-c", "echo '' > /sys/kernel/debug/tracing/trace").Run()

			// Check run count before
			out, _ = exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1 | grep -o 'run_cnt [0-9]*'", kid)).CombinedOutput()
			fmt.Printf("  kprobe run_cnt before: %s\n", strings.TrimSpace(string(out)))

			exec.Command("bash", "-c", "curl -s --connect-timeout 5 http://www.baidu.com > /dev/null 2>&1").Run()
			time.Sleep(500 * time.Millisecond)

			// Check run count after
			out, _ = exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1 | grep -o 'run_cnt [0-9]*'", kid)).CombinedOutput()
			fmt.Printf("  kprobe run_cnt after: %s\n", strings.TrimSpace(string(out)))

			out, _ = exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/trace 2>&1 | head -20").CombinedOutput()
			fmt.Printf("  kprobe trace:\n%s\n", string(out))
		}
	}

	// Step 9: Check if raw tracepoint works
	fmt.Println("\n=== Step 9: Raw tracepoint comparison ===")
	rawTpSpec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"test_rawtp4": {
				Name:         "test_rawtp4",
				Type:         ebpf.RawTracepoint,
				License:      "GPL",
				Instructions: insns,
			},
		},
	}

	rtcoll, rterr := ebpf.NewCollection(rawTpSpec)
	if rterr != nil {
		fmt.Printf("  Raw TP load failed: %v\n", rterr)
	} else {
		defer rtcoll.Close()
		rtprog := rtcoll.Programs["test_rawtp4"]

		rtinfo, _ := rtprog.Info()
		rtid, _ := rtinfo.ID()
		fmt.Printf("  Raw TP prog ID: %d\n", rtid)

		rtp, rterr := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "sys_enter",
			Program: rtprog,
		})
		if rterr != nil {
			fmt.Printf("  Raw TP attach failed: %v\n", rterr)
		} else {
			defer rtp.Close()
			fmt.Println("  Raw TP attached to sys_enter")

			exec.Command("bash", "-c", "echo '' > /sys/kernel/debug/tracing/trace").Run()

			out, _ = exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1 | grep -o 'run_cnt [0-9]*'", rtid)).CombinedOutput()
			fmt.Printf("  rawtp run_cnt before: %s\n", strings.TrimSpace(string(out)))

			exec.Command("bash", "-c", "curl -s --connect-timeout 5 http://www.baidu.com > /dev/null 2>&1").Run()
			time.Sleep(500 * time.Millisecond)

			out, _ = exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1 | grep -o 'run_cnt [0-9]*'", rtid)).CombinedOutput()
			fmt.Printf("  rawtp run_cnt after: %s\n", strings.TrimSpace(string(out)))

			out, _ = exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/trace 2>&1 | head -20").CombinedOutput()
			fmt.Printf("  rawtp trace:\n%s\n", string(out))
		}
	}

	// Final verdict
	fmt.Println("\n=== VERDICT ===")
	if runCntBefore != runCntAfter {
		fmt.Println("  FENTRY: Program WAS executed (run_cnt changed)")
	} else {
		fmt.Println("  FENTRY: Program was NOT executed (run_cnt unchanged)")
	}
}
