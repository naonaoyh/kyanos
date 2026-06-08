package agent_test

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// PerfEventAttrV8 - full-size attr struct matching PERF_ATTR_SIZE_VER8 (136 bytes)
type PerfEventAttrV8 struct {
	Type               uint32
	Size               uint32
	Config             uint64
	Sample             uint64
	SampleType         uint64
	ReadFormat         uint64
	Bits               uint64
	Wakeup             uint32
	BpType             uint32
	Ext1               uint64
	Ext2               uint64
	BranchSampleType   uint64
	SampleRegsUser     uint64
	SampleStackUser    uint32
	ClockID            int32
	SampleRegsIntr     uint64
	AuxWatermark       uint32
	SampleMaxStack     uint16
	Pad1               uint16
	AuxSampleSize      uint32
	Pad2               uint32
	SigData            uint64
}

const perfAttrSizeVer8 = uint32(136) // 0x88
const perfEvtIOCSetBPF = 0x40042408  // _IOW('$', 8, u32)
const perfEvtIOCEnable = 0x2400      // _IO('$', 0)
const perfEvtIOCDisable = 0x2401     // _IO('$', 1)
const sysPerfEvtOpen = 298

func perfEvtOpen(attr *PerfEventAttrV8, pid, cpu, groupFd, flags int) (int, error) {
	r0, _, errno := syscall.Syscall6(
		sysPerfEvtOpen,
		uintptr(unsafe.Pointer(attr)),
		uintptr(pid), uintptr(cpu), uintptr(groupFd), uintptr(flags), 0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("perf_event_open: %v", errno)
	}
	return int(r0), nil
}

// TestAttrSize - Test if PERF_ATTR_SIZE_VER8 fixes the kprobe
func TestAttrSize(t *testing.T) {
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
			"kp_ver8": {
				Name:         "kp_ver8",
				Type:         ebpf.Kprobe,
				AttachType:   ebpf.AttachNone,
				License:      "GPL",
				Instructions: insns,
			},
		},
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["kp_ver8"]

	out, _ := exec.Command("bash", "-c", "cat /sys/bus/event_source/devices/kprobe/type").CombinedOutput()
	pmuType := uint64(0)
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &pmuType)

	symbol := "__sys_connect\x00"
	symbolPtr := unsafe.Pointer(&[]byte(symbol)[0])

	// Test with VER8 size (like bpftrace)
	fmt.Println("=== kprobe with PERF_ATTR_SIZE_VER8 (136 bytes) ===")
	attr := &PerfEventAttrV8{
		Type: uint32(pmuType),
		Size: perfAttrSizeVer8,
		Ext1: uint64(uintptr(symbolPtr)),
	}

	fd, err := perfEvtOpen(attr, -1, 0, -1, 0x08)
	if err != nil {
		t.Fatalf("perf_event_open failed: %v", err)
	}
	defer syscall.Close(fd)
	fmt.Printf("  fd: %d\n", fd)

	// Follow bpftrace's exact ioctl order: ENABLE → SET_BPF (no DISABLE)
	fmt.Println("  ioctl ENABLE...")
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(perfEvtIOCEnable), 0)
	if errno != 0 {
		fmt.Printf("  ENABLE failed: %v\n", errno)
	}

	fmt.Println("  ioctl SET_BPF...")
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(perfEvtIOCSetBPF), uintptr(prog.FD()))
	if errno != 0 {
		fmt.Printf("  SET_BPF failed: %v\n", errno)
	}

	exec.Command("bash", "-c", "echo > /sys/kernel/tracing/trace").Run()
	exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(500 * time.Millisecond)

	out, _ = exec.Command("bash", "-c", "cat /sys/kernel/tracing/trace 2>&1").CombinedOutput()
	hits := strings.Count(string(out), "bpf_trace_printk: HIT")
	fmt.Printf("  VER8 hits: %d\n", hits)

	if hits > 0 {
		fmt.Println("  >>> SUCCESS! PERF_ATTR_SIZE_VER8 fixes the issue! <<<")
		// Show trace
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "HIT") {
				fmt.Printf("  %s\n", line)
			}
		}
	} else {
		fmt.Println("  >>> FAILURE: VER8 didn't help either <<<")
	}

	// Also test: VER1 size with bpftrace ioctl order
	syscall.Close(fd)

	fmt.Println("\n=== kprobe with PERF_ATTR_SIZE_VER1 (72 bytes) + bpftrace ioctl order ===")
	attr2 := &PerfEventAttrV8{
		Type: uint32(pmuType),
		Size: 72, // VER1
		Ext1: uint64(uintptr(symbolPtr)),
	}

	fd2, err := perfEvtOpen(attr2, -1, 0, -1, 0x08)
	if err != nil {
		fmt.Printf("  perf_event_open VER1 failed: %v\n", err)
		return
	}
	defer syscall.Close(fd2)

	// bpftrace order: ENABLE then SET_BPF
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd2), uintptr(perfEvtIOCEnable), 0)
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd2), uintptr(perfEvtIOCSetBPF), uintptr(prog.FD()))

	exec.Command("bash", "-c", "echo > /sys/kernel/tracing/trace").Run()
	exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(500 * time.Millisecond)

	out, _ = exec.Command("bash", "-c", "cat /sys/kernel/tracing/trace 2>&1").CombinedOutput()
	hits2 := strings.Count(string(out), "bpf_trace_printk: HIT")
	fmt.Printf("  VER1 hits: %d\n", hits2)
}
