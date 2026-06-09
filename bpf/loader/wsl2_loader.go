//go:build !windows

package loader

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"kyanos/common"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// pid_check.bpf.o is compiled from bpfsrc/pid_check.bpf.c.
// To rebuild: clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64
//   -I../../vmlinux/x86/ -I../../.output/
//   -c bpfsrc/pid_check.bpf.c -o pid_check.bpf.o
//
//go:embed pid_check.bpf.o
var pidCheckBpfO []byte

// detectedBpfVisiblePid stores the BPF-visible PID detected during setAndValidateParameters.
// This is set when WSL2 PID translation is active.
var detectedBpfVisiblePid uint32

// GetBpfVisiblePid returns the BPF-visible PID detected during BPF loading.
// On WSL2, bpf_get_current_pid_tgid() returns a different PID than userspace sees.
// Returns 0 if no detection was performed (non-WSL2 systems).
func GetBpfVisiblePid() uint32 {
	return detectedBpfVisiblePid
}

// IsWSL2 checks if the current system is running WSL2
func IsWSL2() bool {
	return isWSL2()
}

// isWSL2 checks if the current system is running WSL2
func isWSL2() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	version := strings.ToLower(string(data))
	return strings.Contains(version, "microsoft") || strings.Contains(version, "wsl")
}

type pidDetectEvent struct {
	Tgid uint32
	Tid  uint32
	Comm [16]byte
}

// detectBpfVisiblePid loads a temporary BPF probe to detect the PID that
// bpf_get_current_pid_tgid() returns for the current process.
// On WSL2, this may differ from the userspace PID returned by os.Getpid()
// due to WSL2's PID translation layer.
func detectBpfVisiblePid() (uint32, error) {
	rd := bytes.NewReader(pidCheckBpfO)
	spec, err := ebpf.LoadCollectionSpecFromReader(rd)
	if err != nil {
		return 0, fmt.Errorf("load BPF spec from embedded bytes: %w", err)
	}

	// Try to load with kernel BTF for CO-RE relocations
	kernelBTF, btfErr := btf.LoadKernelSpec()
	collOpts := &ebpf.CollectionOptions{}
	if btfErr == nil {
		collOpts.Programs.KernelTypes = kernelBTF
	}

	var objs struct {
		KprobeAllConnect *ebpf.Program `ebpf:"kprobe_all_connect"`
		DbgRb            *ebpf.Map     `ebpf:"dbg_rb"`
	}
	if err := spec.LoadAndAssign(&objs, collOpts); err != nil {
		return 0, fmt.Errorf("load and assign BPF objects: %w", err)
	}
	defer objs.KprobeAllConnect.Close()
	defer objs.DbgRb.Close()

	// Attach kprobe to __sys_connect
	l, err := link.Kprobe("__sys_connect", objs.KprobeAllConnect, nil)
	if err != nil {
		return 0, fmt.Errorf("attach kprobe to __sys_connect: %w", err)
	}
	defer l.Close()

	// Set up ring buffer reader
	rbReader, err := ringbuf.NewReader(objs.DbgRb)
	if err != nil {
		return 0, fmt.Errorf("create ring buffer reader: %w", err)
	}
	defer rbReader.Close()

	// Get current process info
	currentPid := uint32(os.Getpid())
	exePath, _ := os.Executable()
	procName := filepath.Base(exePath)
	// BPF comm field is max 15 chars + null terminator
	if len(procName) > 15 {
		procName = procName[:15]
	}

	common.AgentLog.Debugf("WSL2 PID detection: userspace PID=%d, exe=%s", currentPid, procName)

	// Make a connect() call to trigger the kprobe.
	// This will fail (ECONNREFUSED), but the BPF kprobe fires regardless.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err == nil {
		// Set non-blocking so connect returns immediately
		syscall.SetNonblock(fd, true)
		syscall.Connect(fd, &syscall.SockaddrInet4{
			Port: 1,
			Addr: [4]byte{127, 0, 0, 1},
		})
		syscall.Close(fd)
	}

	// Read ring buffer events to find our process's BPF-visible TGID
	deadline := time.After(3 * time.Second)
	type result struct {
		tgid uint32
		comm string
	}
	results := []result{}

	for {
		select {
		case <-deadline:
			// Timeout - check results
			for _, r := range results {
				common.AgentLog.Debugf("WSL2 PID detection result: tgid=%d, comm=%s", r.tgid, r.comm)
			}
			if len(results) > 0 {
				return results[0].tgid, nil
			}
			return 0, fmt.Errorf("timeout: no matching BPF event found for PID %d", currentPid)
		default:
		}

		rbReader.SetDeadline(time.Now().Add(500 * time.Millisecond))
		record, err := rbReader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				break
			}
			if os.IsTimeout(err) {
				// No more events, check results
				for _, r := range results {
					common.AgentLog.Debugf("WSL2 PID detection result: tgid=%d, comm=%s", r.tgid, r.comm)
				}
				if len(results) > 0 {
					return results[0].tgid, nil
				}
				continue
			}
			continue
		}

		if len(record.RawSample) < 24 {
			continue
		}

		var evt pidDetectEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			continue
		}

		commStr := nullTermString(evt.Comm[:])
		common.AgentLog.Debugf("WSL2 PID detection event: tgid=%d, tid=%d, comm=%s (our comm: %s)",
			evt.Tgid, evt.Tid, commStr, procName)

		// Match by comm name to find our process's BPF-visible TGID.
		// BPF comm is max 15 chars. Use prefix match: compare the
		// shorter name against the prefix of the longer one to avoid
		// false positives (e.g. "kyanos" vs "kyanos-debug").
		var match bool
		if len(procName) <= len(commStr) {
			match = commStr[:len(procName)] == procName
		} else {
			match = procName[:len(commStr)] == commStr
		}
		if match {
			results = append(results, result{tgid: evt.Tgid, comm: commStr})
		}

		// If we found a match, return immediately
		if len(results) > 0 {
			detectedTgid := results[0].tgid
			detectedBpfVisiblePid = detectedTgid // Store for later retrieval
			common.AgentLog.Infof("WSL2 PID detection: userspace PID=%d -> BPF tgid=%d (comm=%s)",
				currentPid, detectedTgid, results[0].comm)
			return detectedTgid, nil
		}
	}

	return 0, fmt.Errorf("could not detect BPF-visible PID for process %d", currentPid)
}

func nullTermString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		return string(b)
	}
	return string(b[:n])
}
