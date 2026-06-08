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
	"github.com/cilium/ebpf/ringbuf"
)

// TestFentryRingbuf - Test fentry with ring buffer
func TestFentryRingbuf(t *testing.T) {
	// Create ring buffer
	rbSpec := &ebpf.MapSpec{
		Name:       "fentry_rb",
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	}
	rb, err := ebpf.NewMap(rbSpec)
	if err != nil {
		t.Fatalf("Ringbuf create failed: %v", err)
	}
	defer rb.Close()

	// Fentry BPF program: write to ring buffer
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R1, 0x12345678),
		asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
		asm.LoadMapPtr(asm.R1, rb.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.Mov.Imm(asm.R3, 4),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	progSpec := &ebpf.ProgramSpec{
		Name:         "fentry_rb",
		Type:         ebpf.Tracing,
		AttachType:   ebpf.AttachTraceFEntry,
		AttachTo:     "__sys_connect",
		License:      "GPL",
		Instructions: insns,
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		t.Fatalf("Program load failed: %v", err)
	}
	defer prog.Close()

	info, _ := prog.Info()
	id, _ := info.ID()
	fmt.Printf("fentry prog ID: %d\n", id)

	// Attach fentry
	fe, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		t.Fatalf("Fentry attach failed: %v", err)
	}
	defer fe.Close()
	fmt.Println("fentry attached")

	out, _ := exec.Command("bash", "-c", "bpftool link show 2>&1 | tail -5").CombinedOutput()
	fmt.Printf("link: %s\n", strings.TrimSpace(string(out)))

	// Create ringbuf reader
	rd, err := ringbuf.NewReader(rb)
	if err != nil {
		t.Fatalf("Ringbuf reader failed: %v", err)
	}
	defer rd.Close()

	// Trigger
	fmt.Println("triggering connect...")
	exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()

	rd.SetDeadline(time.Now().Add(2 * time.Second))
	record, err := rd.Read()
	if err != nil {
		fmt.Printf("Ringbuf read: %v\n", err)
		fmt.Println("  >>> FAILURE: fentry program did NOT fire <<<")
	} else {
		fmt.Printf("Ringbuf record: %d bytes: %v\n", len(record.RawSample), record.RawSample)
		if len(record.RawSample) >= 4 {
			val := uint32(record.RawSample[0]) | uint32(record.RawSample[1])<<8 |
				uint32(record.RawSample[2])<<16 | uint32(record.RawSample[3])<<24
			if val == 0x12345678 {
				fmt.Println("  >>> SUCCESS! Fentry fired and wrote to ringbuf! <<<")
			} else {
				fmt.Printf("  >>> Got value 0x%X (expected 0x12345678) <<<\n", val)
			}
		}
	}

	out, _ = exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1", id)).CombinedOutput()
	fmt.Printf("prog info: %s\n", strings.TrimSpace(string(out)))

	// Now also test fentry + fexit (like kyanos actually does)
	fmt.Println("\n=== Test: fentry + fexit with ringbuf ===")
	testFentryFexitRingbuf(t, rb)
}

func testFentryFexitRingbuf(t *testing.T, rb *ebpf.Map) {
	// Fexit program that writes to ring buffer
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R1, 0x0BCDEF01),
		asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
		asm.LoadMapPtr(asm.R1, rb.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.Mov.Imm(asm.R3, 4),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	progSpec := &ebpf.ProgramSpec{
		Name:         "fexit_rb",
		Type:         ebpf.Tracing,
		AttachType:   ebpf.AttachTraceFExit,
		AttachTo:     "__sys_connect",
		License:      "GPL",
		Instructions: insns,
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		fmt.Printf("Fexit program load failed: %v\n", err)
		return
	}
	defer prog.Close()

	fe, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		fmt.Printf("Fexit attach failed: %v\n", err)
		return
	}
	defer fe.Close()

	info, _ := prog.Info()
	id, _ := info.ID()
	fmt.Printf("fexit prog ID: %d\n", id)

	rd, err := ringbuf.NewReader(rb)
	if err != nil {
		fmt.Printf("Ringbuf reader failed: %v\n", err)
		return
	}
	defer rd.Close()

	fmt.Println("triggering connect for fexit...")
	exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()

	rd.SetDeadline(time.Now().Add(2 * time.Second))
	record, err := rd.Read()
	if err != nil {
		fmt.Printf("Ringbuf read: %v\n", err)
		fmt.Println("  >>> FAILURE: fexit program did NOT fire <<<")
	} else {
		if len(record.RawSample) >= 4 {
			val := uint32(record.RawSample[0]) | uint32(record.RawSample[1])<<8 |
				uint32(record.RawSample[2])<<16 | uint32(record.RawSample[3])<<24
			if val == 0x0BCDEF01 {
				fmt.Println("  >>> SUCCESS! Fexit fired and wrote to ringbuf! <<<")
			} else {
				fmt.Printf("  >>> Got value 0x%X (expected 0x0BCDEF01) <<<\n", val)
			}
		}
	}
}
