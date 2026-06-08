package agent_test

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// TestSubprocessConnect - Check if kprobe fires for a SUBPROCESS doing net.Dial
func TestSubprocessConnect(t *testing.T) {
	// Build the dial_only program
	fmt.Println("Building dial_only program...")
	buildCmd := exec.Command("go", "build", "-o", "/tmp/dial_only", "./agent/testdata/dial_only.go")
	buildCmd.Dir = "/mnt/e/Work/kyanos"
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Build failed: %v\n%s", err, out)
	}
	fmt.Println("Built /tmp/dial_only")

	// Create ringbuf
	rbMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "subproc_rb",
		Type:       ebpf.RingBuf,
		MaxEntries: 65536,
	})
	if err != nil {
		t.Fatalf("NewMap: %v", err)
	}
	defer rbMap.Close()

	// Create kprobe program
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "subproc_kp",
		Type:    ebpf.Kprobe,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.FnGetCurrentPidTgid.Call(),
			asm.RSh.Imm(asm.R0, 32),
			asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
			asm.StoreImm(asm.RFP, -8, 0xFACE, asm.Word),
			asm.LoadMapPtr(asm.R1, rbMap.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -8),
			asm.Mov.Imm(asm.R3, 8),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnRingbufOutput.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatalf("NewProgram: %v", err)
	}
	defer prog.Close()

	// Attach kprobe
	kp, err := link.Kprobe("__sys_connect", prog, nil)
	if err != nil {
		t.Fatalf("Kprobe: %v", err)
	}
	defer kp.Close()
	fmt.Println("kprobe __sys_connect attached")

	rd, err := ringbuf.NewReader(rbMap)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rd.Close()

	// Run dial_only subprocess
	fmt.Println("\nRunning /tmp/dial_only...")
	cmd := exec.Command("/tmp/dial_only")
	out, err := cmd.CombinedOutput()
	fmt.Printf("Output: %s\n", strings.TrimSpace(string(out)))

	// Extract PID from output
	var dialPid uint32
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "DIAL_PID=") {
			pidStr := strings.TrimPrefix(line, "DIAL_PID=")
			p, _ := strconv.Atoi(pidStr)
			dialPid = uint32(p)
		}
	}
	fmt.Printf("Subprocess PID: %d\n", dialPid)
	time.Sleep(500 * time.Millisecond)

	// Read events
	rd.SetDeadline(time.Now().Add(2 * time.Second))
	foundOurPid := false
	totalEvents := 0
	for {
		record, err := rd.Read()
		if err != nil {
			break
		}
		totalEvents++
		if len(record.RawSample) >= 8 {
			marker := binary.LittleEndian.Uint32(record.RawSample[0:4])
			pid := binary.LittleEndian.Uint32(record.RawSample[4:8])
			ownMark := ""
			if pid == dialPid {
				ownMark = " <<< SUBPROCESS PID"
				foundOurPid = true
			}
			fmt.Printf("  marker=0x%X pid=%d%s\n", marker, pid, ownMark)
		}
	}
	fmt.Printf("\nTotal events: %d\n", totalEvents)
	fmt.Printf("Found subprocess PID %d: %v\n", dialPid, foundOurPid)

	if !foundOurPid {
		fmt.Println(">>> KPROBE DID NOT FIRE FOR SUBPROCESS <<<")
		// Try with the C program as control
		fmt.Println("\nRunning /tmp/c_connect as control...")
		cCmd := exec.Command("/tmp/c_connect")
		cOut, _ := cCmd.CombinedOutput()
		fmt.Printf("C output: %s\n", strings.TrimSpace(string(cOut)))
		time.Sleep(500 * time.Millisecond)

		rd.SetDeadline(time.Now().Add(1 * time.Second))
		for {
			record, err := rd.Read()
			if err != nil {
				break
			}
			if len(record.RawSample) >= 8 {
				marker := binary.LittleEndian.Uint32(record.RawSample[0:4])
				pid := binary.LittleEndian.Uint32(record.RawSample[4:8])
				fmt.Printf("  C control: marker=0x%X pid=%d\n", marker, pid)
			}
		}
	}
}
