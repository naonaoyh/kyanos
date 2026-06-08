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

func bpfPrintkInsns() asm.Instructions {
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

func clearTrace() {
	exec.Command("bash", "-c", "echo '' > /sys/kernel/debug/tracing/trace").Run()
}

func getTrace() string {
	out, _ := exec.Command("bash", "-c", "cat /sys/kernel/debug/tracing/trace 2>&1").CombinedOutput()
	return string(out)
}

func countHits(trace string) int {
	return strings.Count(trace, "bpf_trace_printk: HIT")
}

func triggerConnect() {
	exec.Command("bash", "-c", "curl -s --connect-timeout 5 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(500 * time.Millisecond)
}

func getRunCnt(id uint32) string {
	out, _ := exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1", id)).CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "run_cnt") || strings.Contains(line, "run_time") {
			return strings.TrimSpace(line)
		}
	}
	// Try alternative format
	out2, _ := exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1", id)).CombinedOutput()
	return strings.TrimSpace(string(out2))
}

// TestFentryTarget - Test which function is actually called for connect()
func TestFentryTarget(t *testing.T) {
	// First: verify connect() actually happens with strace
	fmt.Println("=== Verify connect syscall with strace ===")
	out, _ := exec.Command("bash", "-c", "strace -e trace=connect -f curl -s --connect-timeout 5 http://www.baidu.com 2>&1 | head -20").CombinedOutput()
	fmt.Printf("strace output:\n%s\n", string(out))

	// Also check which __sys_connect variant exists in kallsyms
	fmt.Println("=== Check kallsyms ===")
	out, _ = exec.Command("bash", "-c", "grep '__sys_connect' /proc/kallsyms 2>/dev/null").CombinedOutput()
	fmt.Printf("kallsyms:\n%s\n", string(out))

	// Check BTF for all connect-related functions
	fmt.Println("=== BTF connect functions ===")
	out, _ = exec.Command("bash", "-c", "bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep -i 'connect' | grep FUNC | head -20").CombinedOutput()
	fmt.Printf("%s\n", string(out))

	// Test different target functions
	targets := []struct {
		name       string
		funcName   string
		progType   ebpf.ProgramType
		attachType ebpf.AttachType
	}{
		{"fentry:__sys_connect", "__sys_connect", ebpf.Tracing, ebpf.AttachTraceFEntry},
		{"fentry:__sys_connect_file", "__sys_connect_file", ebpf.Tracing, ebpf.AttachTraceFEntry},
		{"fentry:ksys_connect", "ksys_connect", ebpf.Tracing, ebpf.AttachTraceFEntry},
		{"kprobe:__sys_connect", "__sys_connect", ebpf.Kprobe, ebpf.AttachNone},
		{"kprobe:__sys_connect_file", "__sys_connect_file", ebpf.Kprobe, ebpf.AttachNone},
		{"kprobe:ksys_connect", "ksys_connect", ebpf.Kprobe, ebpf.AttachNone},
	}

	for _, target := range targets {
		fmt.Printf("\n=== Testing %s ===\n", target.name)

		spec := &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				"test_prog": {
					Name:         "test_prog",
					Type:         target.progType,
					AttachType:   target.attachType,
					AttachTo:     target.funcName,
					License:      "GPL",
					Instructions: bpfPrintkInsns(),
				},
			},
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			fmt.Printf("  LOAD FAILED: %v\n", err)
			continue
		}

		prog := coll.Programs["test_prog"]
		info, _ := prog.Info()
		id, _ := info.ID()
		fmt.Printf("  Loaded prog ID: %d\n", id)

		var l link.Link
		switch target.progType {
		case ebpf.Tracing:
			l, err = link.AttachTracing(link.TracingOptions{
				Program:    prog,
				AttachType: target.attachType,
			})
		case ebpf.Kprobe:
			l, err = link.Kprobe(target.funcName, prog, nil)
		}

		if err != nil {
			fmt.Printf("  ATTACH FAILED: %v\n", err)
			coll.Close()
			continue
		}

		clearTrace()
		triggerConnect()
		trace := getTrace()
		hits := countHits(trace)

		progInfo := getRunCnt(uint32(id))
		fmt.Printf("  HITS: %d\n", hits)
		fmt.Printf("  prog info: %s\n", progInfo)

		if hits > 0 {
			fmt.Printf("  >>> SUCCESS: %s FIRED! <<<\n", target.name)
		} else {
			fmt.Printf("  >>> FAILURE: %s did NOT fire <<<\n", target.name)
		}

		l.Close()
		coll.Close()
	}

	// Also test tracepoint (not raw tracepoint)
	fmt.Println("\n=== Testing tracepoint sys_enter_connect ===")
	tpSpec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"test_tp": {
				Name:         "test_tp",
				Type:         ebpf.TracePoint,
				AttachType:   ebpf.AttachNone,
				License:      "GPL",
				Instructions: bpfPrintkInsns(),
			},
		},
	}

	tpColl, tpErr := ebpf.NewCollection(tpSpec)
	if tpErr != nil {
		fmt.Printf("  TP LOAD FAILED: %v\n", tpErr)
	} else {
		defer tpColl.Close()
		tpProg := tpColl.Programs["test_tp"]

		tpLink, tpErr := link.Tracepoint("syscalls", "sys_enter_connect", tpProg, nil)
		if tpErr != nil {
			fmt.Printf("  TP ATTACH FAILED: %v\n", tpErr)
		} else {
			defer tpLink.Close()

			clearTrace()
			triggerConnect()
			trace := getTrace()
			hits := countHits(trace)
			fmt.Printf("  HITS: %d\n", hits)
			if hits > 0 {
				fmt.Println("  >>> SUCCESS: tracepoint FIRED! <<<")
			} else {
				fmt.Println("  >>> FAILURE: tracepoint did NOT fire <<<")
			}
		}
	}
}
