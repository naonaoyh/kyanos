package agent_test

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// PerfEventAttr mirrors the kernel perf_event_attr structure (simplified)
type PerfEventAttr struct {
	Type               uint32
	Size               uint32
	Config             uint64
	Sample             uint64 // union: sample_period or sample_freq
	SampleType         uint64
	ReadFormat         uint64
	Bits               uint64 // bitfield
	Wakeup             uint32 // union: wakeup_events or wakeup_watermark
	BpType             uint32
	Ext1               uint64 // union: bp_addr or config1
	Ext2               uint64 // union: bp_len or config2
	BranchSampleType   uint64
	SampleRegsUser     uint64
	SampleStackUser    uint32
	ClockID            int32
	SampleRegsIntr     uint64
	AuxWatermark       uint32
	SampleMaxStack     uint16
	_                  uint16 // padding
}

const perfAttrSizeVer1 = uint32(72) // PERF_ATTR_SIZE_VER1

// PERF_EVENT_IOC_SET_BPF = _IOW('$', 8, u32) = 0x40042408
// PERF_EVENT_IOC_ENABLE = _IO('$', 0) = 0x00002400
const perfEventIOCSetBPF = 0x40042408
const perfEventIOCEnable = 0x00002400
const perfFlagFdCloexec = 0x08
const sysPerfEventOpen = 298 // x86_64

// perfEventOpenRaw calls perf_event_open syscall directly
func perfEventOpenRaw(attr *PerfEventAttr, pid int, cpu int, groupFd int, flags int) (int, error) {
	r0, _, errno := syscall.Syscall6(
		sysPerfEventOpen,
		uintptr(unsafe.Pointer(attr)),
		uintptr(pid),
		uintptr(cpu),
		uintptr(groupFd),
		uintptr(flags),
		0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("perf_event_open failed: errno=%v", errno)
	}
	return int(r0), nil
}

// TestKprobeAllCPUs - Create kprobe on ALL CPUs
func TestKprobeAllCPUs(t *testing.T) {
	numCPU := runtime.NumCPU()
	fmt.Printf("Number of CPUs: %d\n", numCPU)

	// Create a simple kprobe BPF program
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
			"kp_allcpu": {
				Name:       "kp_allcpu",
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

	prog := coll.Programs["kp_allcpu"]

	// Read kprobe PMU type
	out, _ := exec.Command("bash", "-c", "cat /sys/bus/event_source/devices/kprobe/type").CombinedOutput()
	pmuType := uint64(0)
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &pmuType)
	fmt.Printf("kprobe PMU type: %d\n", pmuType)

	// Create symbol string pointer
	symbol := "__sys_connect\x00"
	symbolPtr := unsafe.Pointer(&[]byte(symbol)[0])

	// Test 1: cpu=0 only (like cilium/ebpf does)
	fmt.Println("\n=== Test 1: kprobe on cpu=0 only ===")
	attr := &PerfEventAttr{
		Type:   uint32(pmuType),
		Size:   perfAttrSizeVer1,
		Ext1:   uint64(uintptr(symbolPtr)),
		Ext2:   0,
		Config: 0,
	}

	fd0, err := perfEventOpenRaw(attr, -1, 0, -1, perfFlagFdCloexec)
	if err != nil {
		t.Fatalf("perf_event_open cpu=0 failed: %v", err)
	}
	defer syscall.Close(fd0)
	fmt.Printf("  fd for cpu=0: %d\n", fd0)

	// Attach BPF program via ioctl
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd0),
		uintptr(perfEventIOCSetBPF),
		uintptr(prog.FD()),
	)
	if errno != 0 {
		fmt.Printf("  SET_BPF ioctl failed: %v\n", errno)
	}

	_, _, errno = syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd0),
		uintptr(perfEventIOCEnable),
		0,
	)
	if errno != 0 {
		fmt.Printf("  ENABLE ioctl failed: %v\n", errno)
	}
	fmt.Println("  BPF attached on cpu=0")

	exec.Command("bash", "-c", "echo > /sys/kernel/tracing/trace").Run()
	exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(500 * time.Millisecond)

	out, _ = exec.Command("bash", "-c", "cat /sys/kernel/tracing/trace 2>&1").CombinedOutput()
	hits := strings.Count(string(out), "bpf_trace_printk: HIT")
	fmt.Printf("  cpu=0 only: %d hits\n", hits)
	syscall.Close(fd0)

	// Test 2: kprobe on ALL CPUs
	fmt.Println("\n=== Test 2: kprobe on ALL CPUs ===")
	var fds []int
	for cpu := 0; cpu < numCPU; cpu++ {
		attr2 := &PerfEventAttr{
			Type:   uint32(pmuType),
			Size:   perfAttrSizeVer1,
			Ext1:   uint64(uintptr(symbolPtr)),
			Ext2:   0,
			Config: 0,
		}

		fd, err := perfEventOpenRaw(attr2, -1, cpu, -1, perfFlagFdCloexec)
		if err != nil {
			fmt.Printf("  cpu=%d: perf_event_open failed: %v\n", cpu, err)
			continue
		}

		// Attach BPF program
		_, _, errno := syscall.Syscall(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(perfEventIOCSetBPF),
			uintptr(prog.FD()),
		)
		if errno != 0 {
			fmt.Printf("  cpu=%d: SET_BPF failed: %v\n", cpu, errno)
			syscall.Close(fd)
			continue
		}

		_, _, errno = syscall.Syscall(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(perfEventIOCEnable),
			0,
		)
		if errno != 0 {
			fmt.Printf("  cpu=%d: ENABLE failed: %v\n", cpu, errno)
			syscall.Close(fd)
			continue
		}

		fds = append(fds, fd)
	}
	fmt.Printf("  Attached on %d CPUs\n", len(fds))

	exec.Command("bash", "-c", "echo > /sys/kernel/tracing/trace").Run()
	exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(500 * time.Millisecond)

	out, _ = exec.Command("bash", "-c", "cat /sys/kernel/tracing/trace 2>&1").CombinedOutput()
	hits = strings.Count(string(out), "bpf_trace_printk: HIT")
	fmt.Printf("  ALL CPUs: %d hits\n", hits)

	trace := string(out)
	for _, line := range strings.Split(trace, "\n") {
		if strings.Contains(line, "HIT") || strings.Contains(line, "entries") {
			fmt.Printf("  %s\n", line)
		}
	}

	// Cleanup
	for _, fd := range fds {
		syscall.Close(fd)
	}

	// Test 3: fentry with bpf_link on ALL CPUs (for completeness)
	fmt.Println("\n=== Test 3: Verify bpftrace works ===")
	exec.Command("bash", "-c", "echo > /sys/kernel/tracing/trace").Run()
	btCmd := exec.Command("bash", "-c",
		`timeout 8 bpftrace -e 'kprobe:__sys_connect { printf("BPFTRACE_%d\n", cpu); }' > /tmp/bt_cpu.txt 2>&1 &`)
	btCmd.Run()
	time.Sleep(2 * time.Second)

	exec.Command("bash", "-c", "curl -s --connect-timeout 3 http://www.baidu.com > /dev/null 2>&1").Run()
	time.Sleep(2 * time.Second)

	out, _ = exec.Command("bash", "-c", "cat /tmp/bt_cpu.txt").CombinedOutput()
	fmt.Printf("  bpftrace output:\n%s\n", string(out))

	// Show which CPUs were used
	out, _ = exec.Command("bash", "-c", "cat /tmp/bt_cpu.txt | grep BPFTRACE_ | sort -u").CombinedOutput()
	fmt.Printf("  CPUs used by connect: %s\n", strings.TrimSpace(string(out)))

	if hits > 0 {
		fmt.Println("\n>>> ALL-CPUs kprobe WORKS! The issue was cpu=0 restriction! <<<")
	}
}
