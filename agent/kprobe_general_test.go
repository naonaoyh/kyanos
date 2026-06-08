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

func bpfPrintkInsns2() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Imm(asm.R1, 0x0a544948), // "HIT\n"
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
}

// TestKprobeGeneral - Test if cilium/ebpf kprobe works on ANY function
func TestKprobeGeneral(t *testing.T) {
	// Test various kernel functions
	funcs := []string{
		"vfs_read",
		"vfs_write",
		"do_sys_openat2",
		"tcp_v4_connect",
		"tcp_sendmsg",
		"__x64_sys_connect",
		"do_filp_open",
	}

	for _, funcName := range funcs {
		fmt.Printf("\n=== kprobe on %s ===\n", funcName)

		// Check if function exists
		out, _ := exec.Command("bash", "-c", fmt.Sprintf("grep ' %s$' /proc/kallsyms 2>/dev/null || echo 'NOT_IN_KALLSYMS'", funcName)).CombinedOutput()
		kallsymsEntry := strings.TrimSpace(string(out))
		fmt.Printf("  kallsyms: %s\n", kallsymsEntry)

		if strings.Contains(kallsymsEntry, "NOT_IN_KALLSYMS") {
			fmt.Printf("  SKIP: function not found\n")
			continue
		}

		spec := &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				"test_kp": {
					Name:       "test_kp",
					Type:       ebpf.Kprobe,
					AttachType: ebpf.AttachNone,
					License:    "GPL",
					Instructions: bpfPrintkInsns2(),
				},
			},
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			fmt.Printf("  LOAD FAILED: %v\n", err)
			continue
		}

		prog := coll.Programs["test_kp"]
		info, _ := prog.Info()
		_ = info

		kp, err := link.Kprobe(funcName, prog, nil)
		if err != nil {
			fmt.Printf("  ATTACH FAILED: %v\n", err)
			coll.Close()
			continue
		}

		exec.Command("bash", "-c", "echo '' > /sys/kernel/debug/tracing/trace").Run()

		// Trigger various syscalls
		switch {
		case strings.Contains(funcName, "connect"):
			exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
		case strings.Contains(funcName, "read") || strings.Contains(funcName, "open") || strings.Contains(funcName, "filp"):
			exec.Command("bash", "-c", "cat /etc/hostname > /dev/null 2>&1").Run()
		case strings.Contains(funcName, "write"):
			exec.Command("bash", "-c", "echo test > /tmp/test_write && rm /tmp/test_write").Run()
		case strings.Contains(funcName, "sendmsg"):
			exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
		default:
			exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
			exec.Command("bash", "-c", "cat /etc/hostname > /dev/null 2>&1").Run()
		}

		time.Sleep(300 * time.Millisecond)

		out, _ = exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/trace 2>&1 | grep 'bpf_trace_printk: HIT' | wc -l").CombinedOutput()
		hits := strings.TrimSpace(string(out))

		out, _ = exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/trace 2>&1 | grep 'bpf_trace_printk: HIT' | head -3").CombinedOutput()
		traceLines := strings.TrimSpace(string(out))

		fmt.Printf("  hits: %s\n", hits)
		if traceLines != "" {
			fmt.Printf("  samples:\n%s\n", traceLines)
		}

		if hits != "0" && hits != "" {
			fmt.Printf("  >>> kprobe on %s WORKS! <<<\n", funcName)
		} else {
			fmt.Printf("  >>> kprobe on %s DID NOT FIRE <<<\n", funcName)
		}

		kp.Close()
		coll.Close()
	}

	// Check kprobe_events state
	fmt.Println("\n=== Check perf_event state ===")
	out1, _ := exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || cat /sys/kernel/tracing/kprobe_events 2>/dev/null").CombinedOutput()
	fmt.Printf("  kprobe_events: %s\n", strings.TrimSpace(string(out1)))

	out2, _ := exec.Command("bash", "-c", "ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/ 2>/dev/null").CombinedOutput()
	fmt.Printf("  sys_enter_connect dir: %s\n", strings.TrimSpace(string(out2)))
}
