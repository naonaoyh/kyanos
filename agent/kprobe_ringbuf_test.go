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

// TestKprobeRingbuf - Use ring buffer instead of bpf_trace_printk
func TestKprobeRingbuf(t *testing.T) {
	// Create a ring buffer map
	rbSpec := &ebpf.MapSpec{
		Name:       "test_rb",
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	}
	rb, err := ebpf.NewMap(rbSpec)
	if err != nil {
		t.Fatalf("Ringbuf create failed: %v", err)
	}
	defer rb.Close()

	// BPF program: submit a uint32 value (0xDEADBEEF) to the ring buffer
	// bpf_ringbuf_output(ringbuf_map, data, size, flags)
	// Helper ID: 130 (BPF_FUNC_ringbuf_output)
	insns := asm.Instructions{
		// Store 0x42424242 on stack
		asm.Mov.Imm(asm.R1, 0x42424242),
		asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
		// r1 = ringbuf map fd (will be rewritten by loader)
		asm.LoadMapPtr(asm.R1, rb.FD()),
		// r2 = pointer to data on stack
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		// r3 = size
		asm.Mov.Imm(asm.R3, 4),
		// r4 = flags
		asm.Mov.Imm(asm.R4, 0),
		// call bpf_ringbuf_output
		asm.FnRingbufOutput.Call(),
		// return 0
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	progSpec := &ebpf.ProgramSpec{
		Name:         "kp_ringbuf",
		Type:         ebpf.Kprobe,
		AttachType:   ebpf.AttachNone,
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
	fmt.Printf("prog ID: %d\n", id)

	// Attach kprobe
	kp, err := link.Kprobe("__sys_connect", prog, nil)
	if err != nil {
		t.Fatalf("Kprobe attach failed: %v", err)
	}
	defer kp.Close()
	fmt.Println("kprobe attached")

	// Check link
	out, _ := exec.Command("bash", "-c", "bpftool link show 2>&1 | tail -5").CombinedOutput()
	fmt.Printf("link: %s\n", strings.TrimSpace(string(out)))

	// Create ring buffer reader
	rd, err := ringbuf.NewReader(rb)
	if err != nil {
		t.Fatalf("Ringbuf reader failed: %v", err)
	}
	defer rd.Close()

	// Trigger connect
	fmt.Println("triggering connect...")
	exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()

	// Read from ring buffer with timeout
	rd.SetDeadline(time.Now().Add(2 * time.Second))
	record, err := rd.Read()
	if err != nil {
		fmt.Printf("Ringbuf read: %v\n", err)
		if err == ringbuf.ErrClosed {
			fmt.Println("  >>> FAILURE: ringbuf closed (program didn't fire) <<<")
		} else {
			fmt.Println("  >>> FAILURE: no data from ringbuf (program didn't fire) <<<")
		}
	} else {
		fmt.Printf("Ringbuf record: %d bytes: %v\n", len(record.RawSample), record.RawSample)
		if len(record.RawSample) >= 4 {
			val := uint32(record.RawSample[0]) | uint32(record.RawSample[1])<<8 |
				uint32(record.RawSample[2])<<16 | uint32(record.RawSample[3])<<24
			if val == 0x42424242 {
				fmt.Println("  >>> SUCCESS! Kprobe fired and wrote to ringbuf! <<<")
			} else {
				fmt.Printf("  >>> Got value 0x%X (expected 0x42424242) <<<\n", val)
			}
		}
	}

	// Also check run_cnt
	out, _ = exec.Command("bash", "-c", fmt.Sprintf("bpftool prog show id %d 2>&1", id)).CombinedOutput()
	fmt.Printf("prog info: %s\n", strings.TrimSpace(string(out)))
}
