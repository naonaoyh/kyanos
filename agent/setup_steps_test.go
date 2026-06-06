package agent_test

import (
	"fmt"
	ac "kyanos/agent/common"
	"kyanos/agent/compatible"
	"kyanos/agent/conn"
	"kyanos/bpf/loader"
	"kyanos/common"
	"kyanos/version"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

func TestSetupAgentSteps(t *testing.T) {
	totalStart := time.Now()
	stepStart := time.Now()
	elapsed := func(step string) {
		d := time.Since(stepStart)
		total := time.Since(totalStart)
		if d > 1*time.Second {
			fmt.Printf("[!!] %s took %v (SLOW!) total=%v\n", step, d, total)
		} else {
			fmt.Printf("[OK] %s took %v total=%v\n", step, d, total)
		}
		stepStart = time.Now()
	}

	// Step 1: UpgradeDetect (calls GitHub API)
	fmt.Println("[Step 1] version.UpgradeDetect()...")
	_ = version.UpgradeDetect()
	elapsed("UpgradeDetect")

	// Step 2: IsEnableBPF
	fmt.Println("[Step 2] common.IsEnableBPF()...")
	enabled, err := common.IsEnableBPF()
	fmt.Printf("       enabled=%v err=%v\n", enabled, err)
	elapsed("IsEnableBPF")

	// Step 3: HasPermission
	fmt.Println("[Step 3] ac.HasPermission()...")
	ok, _ := ac.HasPermission()
	fmt.Printf("       ok=%v\n", ok)
	elapsed("HasPermission")

	// Step 4: ValidateAndRepairOptions
	fmt.Println("[Step 4] ac.ValidateAndRepairOptions()...")
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	opts := ac.AgentOptions{Stopper: stopper}
	validated, err := ac.ValidateAndRepairOptions(opts)
	if err != nil {
		t.Fatalf("ValidateAndRepairOptions: %v", err)
	}
	elapsed("ValidateAndRepairOptions")

	// Step 5: InitConnManager
	fmt.Println("[Step 5] conn.InitConnManager()...")
	cm := conn.InitConnManager()
	_ = cm
	elapsed("InitConnManager")

	// Step 6: InitProcessorManager
	fmt.Println("[Step 6] conn.InitProcessorManager()...")
	pm := conn.InitProcessorManager(
		validated.ProcessorsNum, cm,
		validated.MessageFilter, validated.LatencyFilter,
		validated.SizeFilter, validated.TraceSide,
		validated.ConntrackCloseWaitTimeMills)
	_ = pm
	elapsed("InitProcessorManager")

	// Step 7: GetCurrentKernelVersion
	fmt.Println("[Step 7] compatible.GetCurrentKernelVersion()...")
	kv := compatible.GetCurrentKernelVersion()
	fmt.Printf("       Version=%s\n", kv.Version)
	elapsed("GetCurrentKernelVersion")

	// Step 8: RemoveMemlock
	fmt.Println("[Step 8] rlimit.RemoveMemlock()...")
	_ = rlimit.RemoveMemlock()
	elapsed("RemoveMemlock")

	// Step 9: LoadBPF (the real BPF loading)
	fmt.Println("[Step 9] loader.LoadBPF()...")
	validated.Kv = &kv
	validated.LoadPorgressChannel = make(chan string, 20)
	go func() {
		for msg := range validated.LoadPorgressChannel {
			fmt.Printf("       [progress] %s\n", msg)
			if msg == "quit" {
				return
			}
		}
	}()
	bf, err := loader.LoadBPF(&validated)
	if err != nil {
		t.Fatalf("LoadBPF: %v", err)
	}
	fmt.Println("       LoadBPF SUCCESS!")
	bf.Close()
	close(validated.LoadPorgressChannel)
	elapsed("LoadBPF")

	fmt.Printf("\n[DIAG] ALL STEPS PASSED in %v\n", time.Since(totalStart))
}
