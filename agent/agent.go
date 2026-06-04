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
	"kyanos/agent/controlplane"
	"kyanos/agent/export"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/ntrip"
	"kyanos/agent/protocol/rtcm"
	loader_render "kyanos/agent/render/loader"
	"kyanos/agent/render/stat"
	"kyanos/agent/render/watch"
	"kyanos/agent/session"
	"kyanos/bpf"
	"kyanos/bpf/loader"
	"kyanos/common"
	"kyanos/console"
	"kyanos/proto/agentpb"
	"kyanos/version"
	"net"
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

	if validatedOptions, err := ac.ValidateAndRepairOptions(options); err != nil {
		common.AgentLog.Errorf("invalid options: %v", err)
		return
	} else {
		options = validatedOptions
	}
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
	var jsonlExporter *session.JSONLExporter
	var taskMgr *controlplane.TaskManager

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
		reportCfg := session.ReportConfig{
			GGAWarnInterval:  options.SessionTrackerConfig.GGAWarnInterval,
			RTCMWarnInterval: options.SessionTrackerConfig.RTCMWarnInterval,
			ShowPassword:     options.SessionTrackerConfig.Visibility.ShowPassword,
		}
		if options.SessionReportEnable {
			// DiagnosticReporter prints a per-session diagnostic report (login/
			// GGA/RTCM/network/score) to the agent log when each session closes.
			reporter := session.NewDiagnosticReporter(reportCfg, func(report string) {
				common.AgentLog.Infof("\n%s", report)
			})
			sessionTracker.AddListener(reporter)
		}
		if options.SessionJSONLPath != "" {
			// JSONLReporter writes one structured session-summary JSON object per
			// line as sessions close, for downstream tooling / offline analysis.
			exp, err := session.NewJSONLExporter(options.SessionJSONLPath)
			if err != nil {
				common.AgentLog.Errorf("failed to create JSONL export %q: %v", options.SessionJSONLPath, err)
			} else {
				jsonlExporter = exp
				sessionTracker.AddListener(session.NewJSONLReporter(exp, reportCfg))
				common.AgentLog.Infof("session JSONL export enabled: %s", options.SessionJSONLPath)
			}
		}
		common.AgentLog.Info("NTRIP/RTCM session diagnosis enabled")

		// Wire the session tracker into the TUI so operators can view
		// diagnostic sessions in real time via the 'd' hotkey.
		if options.WatchOptions.UseTui() {
			options.WatchOptions.DiagTracker = &sessionTrackerDiagAdapter{tracker: sessionTracker}
		}
	}

	// Embedded Web Console (--webui). Starts Console in-process so the Agent
	// is self-contained: gRPC + HTTP + frontend in a single binary.
	if options.WebUIEnable {
		httpAddr := options.WebUIHTTPAddr
		if httpAddr == "" {
			httpAddr = ":8080"
		}
		// Derive gRPC addr: offset HTTP port by 1
		grpcAddr := ":50051"
		if httpAddr != "" {
			// Parse port from addr like ":8080"
			if host, port, err := net.SplitHostPort(httpAddr); err == nil {
				var p int
				fmt.Sscanf(port, "%d", &p)
				if p > 0 {
					grpcAddr = fmt.Sprintf("%s:%d", host, p+1)
				}
			}
		}

		consCfg := console.Config{
			GRPCListenAddr: grpcAddr,
			HTTPListenAddr: httpAddr,
		}
		embeddedConsole := console.New(consCfg)

		// Enable static file serving for the Vue frontend.
		distDir := "console/frontend/dist"
		if _, err := os.Stat(distDir); err == nil {
			embeddedConsole.API().EnableStaticFiles(distDir)
			common.AgentLog.Infof("Serving frontend from %s", distDir)
		} else {
			common.AgentLog.Warnf("Frontend dist not found at %s (run 'npm run build' in console/frontend)", distDir)
		}

		// Register TUI mode callback so the Console can toggle TUI remotely.
		console.TUIModeChanger = func(enabled bool) {
			options.WatchOptions.NoTUI = !enabled
			if enabled {
				common.AgentLog.Info("TUI mode enabled (remote toggle)")
			} else {
				common.AgentLog.Info("TUI mode disabled (remote toggle)")
			}
		}

		go func() {
			if err := embeddedConsole.Start(options.Ctx); err != nil {
				common.AgentLog.Warnf("embedded Console exited: %v", err)
			}
		}()

		// Auto-configure Agent to connect to the embedded Console.
		options.GRPCServer = grpcAddr
		common.AgentLog.Infof("Embedded Web Console started: HTTP=%s gRPC=%s", httpAddr, grpcAddr)

		// Auto-open browser if requested.
		if options.WebUIOpenBrowser {
			go func() {
				// Wait a moment for servers to start
				time.Sleep(1 * time.Second)
				url := fmt.Sprintf("http://localhost%s", httpAddr)
				openBrowser(url)
			}()
		}
	}

	// Standalone PCAP-NG export (--pcap-output). Independent of --diag and gRPC.
	var standalonePcapWriter *export.PcapNgWriter
	var cosUploader *export.COSUploader
	if options.COSBucket != "" {
		uploader, err := export.NewCOSUploader(export.COSUploaderConfig{
			Bucket:    options.COSBucket,
			Region:    options.COSRegion,
			Prefix:    options.COSPrefix,
			DeleteRaw: options.COSDeleteRaw,
		})
		if err != nil {
			common.AgentLog.Errorf("failed to create COS uploader: %v", err)
		} else {
			cosUploader = uploader
			common.AgentLog.Infof("COS upload enabled: bucket=%s region=%s", options.COSBucket, options.COSRegion)
		}
	}
	if options.PcapOutputPath != "" {
		rotator, err := export.NewRotateWriter(export.RotateWriterConfig{
			BasePath:    options.PcapOutputPath,
			MaxSize:     options.PcapMaxSize,
			MaxDuration: options.PcapMaxDuration,
			HeaderGenerator: func() []byte {
				return export.GetGlobalHeaderBytes(nil)
			},
			OnRotate: func(closedPath string) {
				if cosUploader != nil {
					go func() {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
						defer cancel()
						if _, err := cosUploader.Upload(ctx, closedPath); err != nil {
							common.AgentLog.Errorf("COS upload failed for %q: %v", closedPath, err)
						}
					}()
				}
			},
		})
		if err != nil {
			common.AgentLog.Errorf("failed to create pcap rotator: %v", err)
		} else {
			writer, err := export.NewPcapNgWriter(rotator, nil)
			if err != nil {
				common.AgentLog.Errorf("failed to create pcap writer: %v", err)
				rotator.Close()
			} else {
				standalonePcapWriter = writer
				common.AgentLog.Infof("PCAP-NG export enabled: %s", options.PcapOutputPath)
			}
		}
	}

	conn.RecordFunc = func(r protocol.Record, c *conn.Connection4) error {
		var activeSession *session.NTRIPSession
		if sessionTracker != nil {
			clientIP := c.RemoteIp.String()
			clientPort := uint16(c.RemotePort)
			if !c.IsServerSide() {
				clientIP = c.LocalIp.String()
				clientPort = uint16(c.LocalPort)
			}
			activeSession, _ = sessionTracker.FindActiveSession(clientIP, clientPort)
			sessionTracker.OnRecord(r, connInfoFromConnection4(c))
		}

		// PCAP export: try taskMgr first, fall back to standalone writer.
		if activeSession != nil {
			var pcapExp *export.PcapNgWriter
			var taskID string
			if taskMgr != nil {
				pcapExp, taskID, _ = taskMgr.GetPcapNgExpForConn(activeSession)
			}
			if pcapExp == nil && standalonePcapWriter != nil {
				pcapExp = standalonePcapWriter
				taskID = "standalone"
			}
			if pcapExp != nil {
				payload, isReq, tsNs := extractRawPayloadFromRecord(r)
				if len(payload) > 0 {
					comment := generatePacketComment(activeSession, r, taskID)
					clientIPNet := net.ParseIP(activeSession.ClientIP)
					serverIPNet := net.ParseIP(activeSession.ServerIP)
					var serverPort uint16
					if c.IsServerSide() {
						serverPort = uint16(c.LocalPort)
					} else {
						serverPort = uint16(c.RemotePort)
					}

					var src, dst net.IP
					var sPort, dPort uint16
					if isReq {
						src, dst = clientIPNet, serverIPNet
						sPort, dPort = activeSession.ClientPort, serverPort
					} else {
						src, dst = serverIPNet, clientIPNet
						sPort, dPort = serverPort, activeSession.ClientPort
					}

					ts := time.Unix(0, int64(tsNs))
					_ = pcapExp.WritePacket(ts, src, dst, sPort, dPort, payload, isReq, comment)
				}
			}
		}

		return statRecorder.ReceiveRecord(r, c, recordsChannel)
	}
	conn.OnCloseRecordFunc = func(c *conn.Connection4) error {
		var activeSession *session.NTRIPSession
		if sessionTracker != nil {
			clientIP := c.RemoteIp.String()
			clientPort := uint16(c.RemotePort)
			if !c.IsServerSide() {
				clientIP = c.LocalIp.String()
				clientPort = uint16(c.LocalPort)
			}
			activeSession, _ = sessionTracker.FindActiveSession(clientIP, clientPort)
		}

		// PCAP FIN injection: try taskMgr first, fall back to standalone writer.
		if activeSession != nil {
			var pcapExp *export.PcapNgWriter
			if taskMgr != nil {
				pcapExp, _, _ = taskMgr.GetPcapNgExpForConn(activeSession)
			}
			if pcapExp == nil && standalonePcapWriter != nil {
				pcapExp = standalonePcapWriter
			}
			if pcapExp != nil {
				clientIPNet := net.ParseIP(activeSession.ClientIP)
				serverIPNet := net.ParseIP(activeSession.ServerIP)
				var serverPort uint16
				if c.IsServerSide() {
					serverPort = uint16(c.LocalPort)
				} else {
					serverPort = uint16(c.RemotePort)
				}
				direction := inferCloseDirection(c)
				isClientInitiated := direction == session.CloseClient
				_ = pcapExp.WriteFIN(time.Now(), clientIPNet, serverIPNet, activeSession.ClientPort, serverPort, isClientInitiated)
			}
		}

		if sessionTracker != nil {
			sessionTracker.OnConnectionClose(connInfoFromConnection4(c), time.Now(), inferCloseDirection(c))
		}
		statRecorder.RemoveRecord(c.TgidFd)
		return nil
	}

	// -------------------------------------------------------------------------
	// gRPC control-plane subsystem (Phase 7). Constructed ONLY when
	// --grpc-server is provided; otherwise nil/inactive and the Agent operates
	// in Standalone_CLI_Mode with behaviour identical to Phases 1–6.
	// Requirements: 1.1, 1.2, 1.3, 1.6, 2.2, 6.9
	// -------------------------------------------------------------------------
	if options.GRPCModeEnabled() {
		common.AgentLog.Info("gRPC control-plane mode enabled; connecting to Console at ", options.GRPCServer)

		// -- PodResolver (if Pod resolution is enabled) --
		// Constructed before BPF attach so the initial Cgroup_Whitelist is pushed
		// to the BPF map and the kernel filters from the very first event (Req 6.9).
		var podResolver *controlplane.PodResolver
		if options.PodResolutionEnabled() {
			// NOTE: In the full integration the PodLister/ContainerLister/CgroupMapper
			// and CgroupWhitelist will be concrete implementations backed by the K8s
			// API, container runtime, /proc, and BPF map respectively. For now, we
			// construct the resolver with no-op stubs so the wiring compiles and the
			// live path is a deferred-verification item.
			podResolver = controlplane.NewPodResolver(controlplane.PodResolverConfig{
				K8s:       noopPodLister{},
				Runtime:   noopContainerLister{},
				Cgroups:   noopCgroupMapper{},
				Whitelist: noopCgroupWhitelist{},
				Namespace: options.GRPCOptions.Namespace,
				Selector:  options.GRPCOptions.Selector,
			})
			if err := podResolver.ResolveTargets(ctx); err != nil {
				// ResolveTargets logs and may enter fallback mode (Req 6.8).
				// The Agent continues regardless.
				common.AgentLog.Warnf("PodResolver: initial resolution failed (continuing): %v", err)
			}
		}

		// -- Build the core control-plane components --
		bufferCap := options.GRPCOptions.BufferCapacity
		if bufferCap <= 0 {
			bufferCap = 1000 // reasonable default
		}
		eventBuffer := controlplane.NewEventBuffer[*agentpb.SessionEvent](bufferCap)

		taskMgr = controlplane.NewTaskManager(controlplane.NewRealClock())
		if podResolver != nil {
			taskMgr.SetIPToNameFunc(podResolver.IPToPodNameMap)
		}
		filterCtl := controlplane.NewFilterController(controlplane.FilterControllerConfig{
			Apply: func(f protocol.ProtocolFilter) {
				// In the full integration this would hot-swap the active
				// MessageFilter on the ProcessorManager. The concrete swap
				// mechanism is a deferred-verification item (requires the
				// ProcessorManager to expose a SetFilter method).
				common.AgentLog.Debugf("controlplane: FilterController applied new MessageFilter (type %T)", f)
			},
			Whitelist:     noopCgroupWhitelist{},
			Resolver:      podResolver,
			Tasks:         taskMgr,
			InitialFilter: options.MessageFilter,
		})
		dispatcher := controlplane.NewDispatcher(taskMgr, filterCtl)

		// -- Transport credentials --
		creds, err := controlplane.BuildTransport(options.GRPCOptions.TLS)
		if err != nil {
			common.AgentLog.Errorf("gRPC transport configuration failed: %v", err)
			return
		}

		// -- Backoff --
		backoffMax := options.GRPCOptions.BackoffMax
		if backoffMax <= 0 {
			backoffMax = 60 * time.Second
		}
		bo := controlplane.Backoff{
			Base:   1 * time.Second,
			Max:    backoffMax,
			Factor: 2.0,
		}

		// -- Determine node name (Kubernetes NODE_NAME env var or hostname) --
		nodeName := os.Getenv("NODE_NAME")
		if nodeName == "" {
			nodeName, _ = os.Hostname()
		}

		// -- Construct the Client --
		cpClient := controlplane.NewClient(controlplane.ClientConfig{
			Addr:              options.GRPCServer,
			NodeName:          nodeName,
			Version:           version.GetVersion(),
			Creds:             creds,
			Buffer:            eventBuffer,
			Backoff:           bo,
			Dispatcher:        dispatcher,
			Clock:             nil, // uses real clock
			Resolver:          podResolver,
			HeartbeatInterval: options.GRPCOptions.HeartbeatInterval,
			HeartbeatTimeout:  options.GRPCOptions.HeartbeatTimeout,
		})

		// -- EventReporter: register on the SessionTracker if it exists --
		reporter := controlplane.NewEventReporter(controlplane.EventReporterConfig{
			Tasks:    taskMgr,
			Resolver: podResolver,
			Redactor: &controlplane.Redactor{},
			Out:      eventBuffer.Push,
			Silent:   false,
		})
		if sessionTracker != nil {
			sessionTracker.AddEventListener(reporter)
			common.AgentLog.Info("gRPC EventReporter registered on SessionTracker")
		}

		// -- Launch Client.Run on a goroutine bound to ctx --
		go func() {
			if err := cpClient.Run(ctx); err != nil && ctx.Err() == nil {
				common.AgentLog.Warnf("controlplane.Client.Run exited: %v", err)
			}
		}()
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

	if sessionTracker != nil {
		sessionTracker.CloseAll(time.Now())
		// Ensure that the log output triggered by CloseAll (diagnostic reports) is flushed
		time.Sleep(200 * time.Millisecond)
	}

	// Emit a multi-Pod load summary at shutdown (S6), if enabled.
	if podLoadAnalyzer != nil {
		common.SetLogToStdout()
		common.AgentLog.Infof("\n%s", session.FormatPodLoadSummary(podLoadAnalyzer))
	}

	// Flush and close the JSONL export, if enabled.
	if jsonlExporter != nil {
		if err := jsonlExporter.Close(); err != nil {
			common.AgentLog.Warnf("failed to close JSONL export: %v", err)
		}
	}

	// Close the standalone PCAP-NG writer, if enabled.
	if standalonePcapWriter != nil {
		if err := standalonePcapWriter.Close(); err != nil {
			common.AgentLog.Warnf("failed to close PCAP export: %v", err)
		} else {
			common.AgentLog.Infof("PCAP-NG export closed: %s", options.PcapOutputPath)
		}
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

func extractRawPayloadFromRecord(r protocol.Record) ([]byte, bool, uint64) {
	req := r.Request()
	resp := r.Response()

	if resp != nil {
		if nr, ok := resp.(*ntrip.NTRIPResponse); ok {
			raw := []byte(nr.StatusLine + "\r\n")
			if nr.ContentType != "" {
				raw = append(raw, []byte("Content-Type: "+nr.ContentType+"\r\n")...)
			}
			raw = append(raw, []byte("\r\n")...)
			return raw, false, nr.TimestampNs()
		}
	}

	switch msg := req.(type) {
	case *ntrip.NTRIPRequest:
		raw := []byte(fmt.Sprintf("%s %s HTTP/1.1\r\n", msg.Method, msg.Path))
		if msg.UserAgent != "" {
			raw = append(raw, []byte("User-Agent: "+msg.UserAgent+"\r\n")...)
		}
		if msg.ContentType != "" {
			raw = append(raw, []byte("Content-Type: "+msg.ContentType+"\r\n")...)
		}
		raw = append(raw, []byte("\r\n")...)
		return raw, true, msg.TimestampNs()

	case *ntrip.NTRIPNMEASentence:
		return []byte(msg.Raw), true, msg.TimestampNs()

	case *ntrip.NTRIPRTCMFrame:
		if msg.Inner != nil {
			return msg.Inner.RawBytes, false, msg.TimestampNs() // RTCM is downstream (Server -> Client)
		}

	case *rtcm.RTCMFrame:
		return msg.RawBytes, false, msg.TimestampNs() // RTCM is downstream (Server -> Client)
	}

	return nil, false, 0
}

func generatePacketComment(s *session.NTRIPSession, r protocol.Record, taskID string) string {
	var category string
	req := r.Request()

	switch msg := req.(type) {
	case *ntrip.NTRIPRequest:
		category = fmt.Sprintf("Login Request (User: %s)", msg.Username)
	case *ntrip.NTRIPNMEASentence:
		category = fmt.Sprintf("GGA Position Upload (Fix: %d, Sats: %d)", msg.FixQuality, msg.NumSatellites)
	case *ntrip.NTRIPRTCMFrame:
		if msg.Inner != nil {
			category = fmt.Sprintf("RTCM Frame MSG %d (Size: %d)", msg.Inner.MessageType, len(msg.Inner.RawBytes))
		}
	case *rtcm.RTCMFrame:
		category = fmt.Sprintf("RTCM Frame MSG %d (Size: %d)", msg.MessageType, len(msg.RawBytes))
	}

	return fmt.Sprintf("Task: %s | Session: %s | %s", taskID, s.SessionID, category)
}
