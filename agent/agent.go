package agent

import (
	"context"
	"errors"
	"fmt"
	"kyanos/agent/analysis"
	anc "kyanos/agent/analysis/common"
	ac "kyanos/agent/common"
	"kyanos/agent/compatible"
	"kyanos/agent/conn"
	"kyanos/agent/protocol"
	loader_render "kyanos/agent/render/loader"
	"kyanos/agent/render/stat"
	"kyanos/agent/render/watch"
	"kyanos/agent/session"
	"kyanos/bpf"
	"kyanos/bpf/loader"
	"kyanos/common"
	"kyanos/version"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/cilium/ebpf/rlimit"
	gops "github.com/google/gops/agent"
)

func SetupAgent(options ac.AgentOptions) {
	startGopsServer(options)

	if err := version.UpgradeDetect(); err != nil {
		if errors.Is(err, version.ErrBehindLatest) {
			common.AgentLog.Warn(err)
		}
	}
	if enabled, err := common.IsEnableBPF(); err == nil && !enabled {
		common.AgentLog.Error("BPF is not enabled in your kernel. This might be because your kernel version is too old. " +
			"Please check the requirements for Kyanos at https://kyanos.io/quickstart.html#installation-requirements.")
		return
	}

	if ok, err := ac.HasPermission(); err != nil {
		common.AgentLog.Error("check capabilities failed: ", err)
		return
	} else if !ok {
		common.AgentLog.Error("Kyanos requires CAP_BPF to run. Please run kyanos with sudo or run container in privilege mode.")
		return
	}

	if common.Is256ColorSupported() {
		common.AgentLog.Debugln("Terminal supports 256 colors")
	} else {
		common.AgentLog.Warnf("Your terminal does not support 256 colors, ui may display incorrectly")
	}

	options = ac.ValidateAndRepairOptions(options)
	common.LaunchEpochTime = GetMachineStartTimeNano()
	stopper := options.Stopper
	connManager := conn.InitConnManager()

	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, stopFunc := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	options.Ctx = ctx

	defer stopFunc()

	if options.ConnManagerInitHook != nil {
		options.ConnManagerInitHook(connManager)
	}
	statRecorder := analysis.InitStatRecorder(&options)

	var recordsChannel chan *anc.AnnotatedRecord = nil
	recordsChannel = make(chan *anc.AnnotatedRecord, 1000)

	pm := conn.InitProcessorManager(options.ProcessorsNum, connManager, options.MessageFilter, options.LatencyFilter, options.SizeFilter, options.TraceSide, options.ConntrackCloseWaitTimeMills)

	// Optional NTRIP/RTCM session diagnostic engine. Disabled by default;
	// when off, behaviour is identical to upstream kyanos.
	var sessionTracker *session.SessionTracker
	var podLoadAnalyzer *session.PodLoadAnalyzer
	if options.SessionDiagnosisEnable {
		sessionTracker = session.NewSessionTracker(options.SessionTrackerConfig)
		correlator := session.NewSessionCorrelator(options.SessionTrackerConfig.Correlator)
		// SessionCorrelator implements SessionListener, so registering it wires
		// cross-session reconnection / IP-change detection automatically via the
		// tracker's create/close notifications.
		sessionTracker.AddListener(correlator)
		if options.SessionPodLoadEnable {
			// PodLoadAnalyzer is also a SessionListener; registering it enables
			// S6 multi-Pod load aggregation (per-Pod connections/frame-rate,
			// stickiness, load-imbalance).
			podLoadAnalyzer = session.NewPodLoadAnalyzer()
			sessionTracker.AddListener(podLoadAnalyzer)
		}
		if options.SessionReportEnable {
			// DiagnosticReporter prints a per-session diagnostic report (login/
			// GGA/RTCM/network/score) to the agent log when each session closes.
			reportCfg := session.ReportConfig{
				GGAWarnInterval:  options.SessionTrackerConfig.GGAWarnInterval,
				RTCMWarnInterval: options.SessionTrackerConfig.RTCMWarnInterval,
				ShowPassword:     options.SessionTrackerConfig.Visibility.ShowPassword,
			}
			reporter := session.NewDiagnosticReporter(reportCfg, func(report string) {
				common.AgentLog.Infof("\n%s", report)
			})
			sessionTracker.AddListener(reporter)
		}
		common.AgentLog.Info("NTRIP/RTCM session diagnosis enabled")
	}

	conn.RecordFunc = func(r protocol.Record, c *conn.Connection4) error {
		if sessionTracker != nil {
			sessionTracker.OnRecord(r, connInfoFromConnection4(c))
		}
		return statRecorder.ReceiveRecord(r, c, recordsChannel)
	}
	conn.OnCloseRecordFunc = func(c *conn.Connection4) error {
		if sessionTracker != nil {
			sessionTracker.OnConnectionClose(connInfoFromConnection4(c), time.Now(), inferCloseDirection(c))
		}
		statRecorder.RemoveRecord(c.TgidFd)
		return nil
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		common.AgentLog.Warn("Remove memlock:", err)
	}

	wg := new(sync.WaitGroup)
	wg.Add(1)

	var _bf loader.BPF
	go func(_bf *loader.BPF) {
		defer wg.Done()
		options.LoadPorgressChannel <- "🍩 Kyanos starting..."
		kernelVersion := compatible.GetCurrentKernelVersion()
		options.Kv = &kernelVersion
		var err error
		defer func() {
			if err != nil {
				common.AgentLog.Errorf("Failed to load BPF programs: %+v", errors.Unwrap(errors.Unwrap(err)))
				_bf.Err = err
				options.LoadPorgressChannel <- "❌ Kyanos start failed"
				options.LoadPorgressChannel <- "quit"
			}
		}()
		bf, err := loader.LoadBPF(&options)
		if err != nil {
			if bf != nil {
				bf.Close()
			}
			return
		}
		_bf.Links = bf.Links
		_bf.Objs = bf.Objs

		err = bpf.PullSyscallDataEvents(ctx, pm.GetSyscallEventsChannels(), options.SyscallPerfEventMapPageNum, options.CustomSyscallEventHook)
		if err != nil {
			return
		}
		err = bpf.PullSslDataEvents(ctx, pm.GetSslEventsChannels(), options.SslPerfEventMapPageNum, options.CustomSslEventHook)
		if err != nil {
			return
		}
		err = bpf.PullConnDataEvents(ctx, pm.GetConnEventsChannels(), options.ConnPerfEventMapPageNum, options.CustomConnEventHook)
		if err != nil {
			return
		}
		err = bpf.PullKernEvents(ctx, pm.GetKernEventsChannels(), options.KernPerfEventMapPageNum, options.CustomKernEventHook)
		if err != nil {
			return
		}
		firstPacketChannel := make(chan *bpf.AgentFirstPacketEvt, 10)
		firstPacketProcessor := conn.NewFirstPacketProcessor(firstPacketChannel, pm.GetFirstPacketEventsChannels())
		go firstPacketProcessor.Start()
		err = bpf.PullFirstPacketEvents(ctx, firstPacketChannel, options.FirstPacketEventMapPageNum)

		err = _bf.AttachProgs(&options)
		if err != nil {
			return
		}
		if options.WatchOptions.UseTui() {
			options.LoadPorgressChannel <- "🍹 All programs attached"
			options.LoadPorgressChannel <- "🍭 Waiting for events.."
			time.Sleep(500 * time.Millisecond)
			options.LoadPorgressChannel <- "quit"
		}
	}(&_bf)
	defer func() {
		_bf.Close()
	}()
	if options.WatchOptions.UseTui() {
		loader_render.Start(ctx, options)
		common.SetLogToStdout()
	} else {
		wg.Wait()
		common.AgentLog.Info("Waiting for events..")
	}
	if _bf.Err != nil {
		logSystemInfo(_bf.Err)
		return
	}

	stop := false
	go func() {
		<-stopper
		// ac.SendStopSignal()
		common.AgentLog.Debugln("stop!")
		pm.StopAll()
		stop = true
	}()

	if options.InitCompletedHook != nil {
		options.InitCompletedHook()
	}

	if options.AnalysisEnable {
		resultChannel := make(chan []*analysis.ConnStat, 1000)
		renderStopper := make(chan int)
		analyzer := analysis.CreateAnalyzer(recordsChannel, &options.AnalysisOptions, resultChannel, renderStopper, options.Ctx)
		go analyzer.Run()
		stat.StartStatRender(ctx, resultChannel, options.AnalysisOptions)
	} else {
		watch.RunWatchRender(ctx, recordsChannel, options.WatchOptions)
	}

	// Emit a multi-Pod load summary at shutdown (S6), if enabled.
	if podLoadAnalyzer != nil {
		common.SetLogToStdout()
		common.AgentLog.Infof("\n%s", session.FormatPodLoadSummary(podLoadAnalyzer))
	}

	common.AgentLog.Infoln("Kyanos Stopped: ", stop)

	return
}

func logSystemInfo(loadError error) {
	common.SetLogToStdout()
	info := []string{
		"OS: " + runtime.GOOS,
		"Arch: " + runtime.GOARCH,
		"NumCPU: " + fmt.Sprintf("%d", runtime.NumCPU()),
		"GoVersion: " + runtime.Version(),
	}

	kernelVersion, err := exec.Command("uname", "-r").Output()
	if err == nil {
		info = append(info, "Kernel Version: "+strings.TrimSpace(string(kernelVersion)))
	} else {
		info = append(info, "Failed to get kernel version: "+err.Error())
	}

	osRelease, err := exec.Command("cat", "/etc/os-release").Output()
	if err == nil {
		info = append(info, strings.TrimSpace(string(osRelease)))
	} else {
		info = append(info, "Failed to get Linux distribution: "+err.Error())
	}

	const crashReportFormat = `
===================================
	  Kyanos Crash Report
=========Error Message=============
%s
============OS Info================
%s
===================================
FAQ         : https://kyanos.io/faq.html
Submit issue: https://github.com/hengyoush/kyanos/issues

`

	var errorInfo string
	if loadError != nil {
		errorInfo = "Error: " + loadError.Error()
	} else {
		errorInfo = "No load errors detected."
	}

	fmt.Printf(crashReportFormat, errorInfo, strings.Join(info, "\n"))
}

func startGopsServer(opts ac.AgentOptions) {
	if opts.StartGopsServer {
		if err := gops.Listen(gops.Options{}); err != nil {
			common.AgentLog.Fatalf("agent.Listen err: %v", err)
		} else {
			common.AgentLog.Info("gops server started")
		}
	}
}
