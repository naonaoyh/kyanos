package cmd

import (
	"fmt"
	"kyanos/agent"
	ac "kyanos/agent/common"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/rtcm"
	"kyanos/agent/session"
	"kyanos/common"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/jefurry/logrus"
	"github.com/sevlyar/go-daemon"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/klog/v2"
)

type ModeEnum int

var Mode ModeEnum
var SidePar string

const (
	WatchMode ModeEnum = iota
	AnalysisMode
)

func ParseSide(side string) (common.SideEnum, error) {
	switch side {
	case "all":
		return common.AllSide, nil
	case "server":
		return common.ServerSide, nil
	case "client":
		return common.ClientSide, nil
	default:
		logger.Errorf("invalid side: %s", side)
		return common.AllSide, fmt.Errorf("invalid side: %s", side)
	}
}

var options ac.AgentOptions

func startAgent(cmd *cobra.Command) {
	side, err := ParseSide(SidePar)
	if err != nil {
		return
	}
	options.TraceSide = side
	if Mode == AnalysisMode {
		options.AnalysisEnable = true
		analysisOptions, err := createAnalysisOptions()
		if err != nil {
			return
		}
		options.AnalysisOptions = analysisOptions
		options.Side = side
	} else {
		options.WatchOptions.MaxRecords = maxRecords
	}
	options.IfName = IfName
	options.BTFFilePath = BTFFilePath
	options.PerfEventBufferSizeForEvent = KernEvtPerfEventBufferSize
	options.PerfEventBufferSizeForData = DataEvtPerfEventBufferSize

	options.ContainerdEndpoint = ContainerdEndpoint
	options.DockerEndpoint = DockerEndpoint
	options.CriRuntimeEndpoint = CriRuntimeEndpoint
	options.ContainerId = ContainerId
	options.ContainerName = ContainerName
	options.PodName = PodName

	// Populate GRPCOptions from persistent flags (no-op if --grpc-server is empty).
	initGRPCOptions(cmd)

	ac.Options = &options

	InitLog()
	common.AgentLog.Infoln("Kyanos starting...")
	if viper.GetBool(common.DaemonVarName) {
		cntxt := &daemon.Context{
			PidFileName: "./kyanos.pid",
			PidFilePerm: 0644,
			LogFileName: "./kyanos.log",
			LogFilePerm: 0640,
			WorkDir:     "./",
			// Umask:       027,
			Args: nil, // use current os args
		}
		d, err := cntxt.Reborn()
		if err != nil {
			logger.Fatal("Unable to run: ", err)
		}
		if d != nil {
			logger.Println("Kyanos started!")
			return
		}
		defer cntxt.Release()
		logger.Println("----------------------")
		logger.Println("Kyanos started!")
		agent.SetupAgent(options)
	} else {
		agent.SetupAgent(options)
	}
}

func initLatencyFilter(cmd *cobra.Command) protocol.LatencyFilter {
	latency, err := cmd.Flags().GetFloat64("latency")
	if err != nil {
		logger.Fatalf("invalid latency: %v\n", err)
	}
	latencyFilter := protocol.LatencyFilter{
		MinLatency: latency,
	}
	return latencyFilter
}

func initSizeFilter(cmd *cobra.Command) protocol.SizeFilter {
	reqSizeLimit, err := cmd.Flags().GetInt64("req-size")
	if err != nil {
		logger.Fatalf("invalid req-size: %v\n", err)
	}
	respSizeLimit, err := cmd.Flags().GetInt64("resp-size")
	if err != nil {
		logger.Fatalf("invalid resp-size: %v\n", err)
	}
	sizeFilter := protocol.SizeFilter{
		MinReqSize:  reqSizeLimit,
		MinRespSize: respSizeLimit,
	}
	return sizeFilter
}

// initSessionDiagnosis reads the shared session-diagnosis flags (registered by
// addSessionDiagnosisFlags) and, when --diag is set, enables the NTRIP/RTCM
// session diagnostic engine on the global options with a tuned TrackerConfig.
//
// When --diag is not set, options.SessionDiagnosisEnable stays false and the
// agent behaves exactly like upstream kyanos.
func initSessionDiagnosis(cmd *cobra.Command) {
	diag, _ := cmd.Flags().GetBool("diag")
	if !diag {
		return
	}

	cfg := session.DefaultTrackerConfig()

	if v, err := cmd.Flags().GetDuration("gga-interval-warn"); err == nil && v > 0 {
		cfg.GGAWarnInterval = v
	}
	if v, err := cmd.Flags().GetDuration("rtcm-interruption-warn"); err == nil && v > 0 {
		cfg.RTCMWarnInterval = v
	}
	if v, err := cmd.Flags().GetDuration("reconnect-window"); err == nil && v > 0 {
		cfg.Correlator.ReconnectWindow = v
	}
	if tcp, err := cmd.Flags().GetBool("tcp-health"); err == nil && tcp {
		cfg.EnableTCPHealth = true
	}

	options.SessionDiagnosisEnable = true
	options.SessionTrackerConfig = cfg

	if pl, err := cmd.Flags().GetBool("pod-load"); err == nil && pl {
		options.SessionPodLoadEnable = true
	}
	if rep, err := cmd.Flags().GetBool("diag-report"); err == nil && rep {
		options.SessionReportEnable = true
	}
	if path, err := cmd.Flags().GetString("diag-jsonl"); err == nil && path != "" {
		options.SessionJSONLPath = path
	}
}

// applyLeapSeconds reads the --leap-seconds flag (if registered) and overrides
// the RTCM GPS-UTC leap second offset used for epoch->UTC latency conversion.
// A value <= 0 leaves the built-in default in place. Applied independently of
// --diag because it affects RTCM epoch latency whenever diagnostics run.
func applyLeapSeconds(cmd *cobra.Command) {
	if cmd.Flags().Lookup("leap-seconds") == nil {
		return
	}
	if ls, err := cmd.Flags().GetInt("leap-seconds"); err == nil && ls > 0 {
		rtcm.SetLeapSeconds(ls)
	}
}

// applyPcapOptions reads the --pcap-output flags (if registered) and populates
// the corresponding AgentOptions fields. Independent of --diag.
func applyPcapOptions(cmd *cobra.Command) {
	if cmd.Flags().Lookup("pcap-output") == nil {
		return
	}
	if path, err := cmd.Flags().GetString("pcap-output"); err == nil && path != "" {
		options.PcapOutputPath = path
	}
	if sz, err := cmd.Flags().GetInt64("pcap-max-size"); err == nil {
		options.PcapMaxSize = sz
	}
	if dur, err := cmd.Flags().GetDuration("pcap-max-duration"); err == nil {
		options.PcapMaxDuration = dur
	}
	if bucket, err := cmd.Flags().GetString("cos-bucket"); err == nil && bucket != "" {
		options.COSBucket = bucket
	}
	if region, err := cmd.Flags().GetString("cos-region"); err == nil && region != "" {
		options.COSRegion = region
	}
	if prefix, err := cmd.Flags().GetString("cos-prefix"); err == nil {
		options.COSPrefix = prefix
	}
	if del, err := cmd.Flags().GetBool("cos-delete-raw"); err == nil {
		options.COSDeleteRaw = del
	}
}

// applyWebUIOptions reads the --no-tui, --webui, --webui-addr, --open-browser
// flags and populates the corresponding AgentOptions fields.
func applyWebUIOptions(cmd *cobra.Command) {
	if cmd.Flags().Lookup("no-tui") == nil {
		return
	}
	if v, err := cmd.Flags().GetBool("no-tui"); err == nil && v {
		options.WatchOptions.NoTUI = true
	}
	if v, err := cmd.Flags().GetBool("webui"); err == nil && v {
		options.WebUIEnable = true
	}
	if v, err := cmd.Flags().GetString("webui-addr"); err == nil && v != "" {
		options.WebUIHTTPAddr = v
	}
	if v, err := cmd.Flags().GetBool("open-browser"); err == nil && v {
		options.WebUIOpenBrowser = true
	}
}

// initGRPCOptions reads the shared gRPC control-plane persistent flags
// (registered by root.go init) and populates options.GRPCOptions. When
// --grpc-server is empty (the default), GRPCOptions stays at its zero value and
// the Agent remains in Standalone_CLI_Mode (additive, not replacing).
//
// This mirrors the addSessionDiagnosisFlags/initSessionDiagnosis pattern: flags
// are registered centrally (root persistent flags) and the helper reads them
// into the typed options struct before agent startup.
func initGRPCOptions(cmd *cobra.Command) {
	if options.GRPCServer == "" {
		return
	}

	var grpcOpts ac.GRPCOptions

	// TLS configuration
	if v, err := cmd.Flags().GetBool("grpc-tls"); err == nil && v {
		grpcOpts.TLS.Enable = true
	}
	if v, err := cmd.Flags().GetBool("grpc-tls-insecure"); err == nil && v {
		grpcOpts.TLS.Insecure = true
	}
	if v, err := cmd.Flags().GetString("grpc-ca"); err == nil && v != "" {
		grpcOpts.TLS.CAPath = v
	}
	if v, err := cmd.Flags().GetString("grpc-cert"); err == nil && v != "" {
		grpcOpts.TLS.CertPath = v
	}
	if v, err := cmd.Flags().GetString("grpc-key"); err == nil && v != "" {
		grpcOpts.TLS.KeyPath = v
	}

	// Pod resolution
	if v, err := cmd.Flags().GetBool("grpc-pod-resolve"); err == nil && v {
		grpcOpts.PodResolve = true
	}
	if v, err := cmd.Flags().GetString("grpc-namespace"); err == nil && v != "" {
		grpcOpts.Namespace = v
	}
	if v, err := cmd.Flags().GetString("grpc-selector"); err == nil && v != "" {
		grpcOpts.Selector = v
	}

	// Resilience tuning
	if v, err := cmd.Flags().GetInt("grpc-buffer-capacity"); err == nil && v > 0 {
		grpcOpts.BufferCapacity = v
	}
	if v, err := cmd.Flags().GetDuration("grpc-backoff-max"); err == nil && v > 0 {
		grpcOpts.BackoffMax = v
	}
	if v, err := cmd.Flags().GetDuration("grpc-heartbeat"); err == nil && v > 0 {
		grpcOpts.HeartbeatInterval = v
	}
	if v, err := cmd.Flags().GetDuration("grpc-heartbeat-timeout"); err == nil && v > 0 {
		grpcOpts.HeartbeatTimeout = v
	}

	options.GRPCOptions = grpcOpts
}

// addSessionDiagnosisFlags registers the shared session-diagnosis flags on a
// command. Shared by the ntrip and rtcm subcommands so both can drive the
// diagnostic engine with identical flag names.
func addSessionDiagnosisFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("diag", false,
		"Enable the NTRIP/RTCM session diagnostic engine (login/GGA/RTCM/network analysis)")
	cmd.Flags().Duration("gga-interval-warn", 5*time.Second,
		"GGA upload interval threshold for anomaly detection (requires --diag)")
	cmd.Flags().Duration("rtcm-interruption-warn", 2*time.Second,
		"RTCM frame gap threshold for interruption detection (requires --diag)")
	cmd.Flags().Bool("reconnect-detect", false,
		"Detect client reconnections / IP changes across sessions (requires --diag)")
	cmd.Flags().Duration("reconnect-window", 60*time.Second,
		"Max gap between disconnect and reconnect to correlate as a reconnection (requires --diag)")
	cmd.Flags().Bool("tcp-health", false,
		"Attach a per-session TCP health analyzer (retransmissions/RTT/window) (requires --diag)")
	cmd.Flags().Bool("pod-load", false,
		"Enable multi-Pod load analysis (per-Pod connections/frame-rate, stickiness, imbalance) (requires --diag)")
	cmd.Flags().Bool("diag-report", false,
		"Print a per-session diagnostic report (login/GGA/RTCM/network/score) when each session closes (requires --diag)")
	cmd.Flags().String("diag-jsonl", "",
		"Export one structured session-summary JSON object per line to this file as sessions close (requires --diag)")
	cmd.Flags().Int("leap-seconds", 0,
		"Override the GPS-UTC leap second offset for RTCM epoch latency (0 = use built-in default 18)")
	cmd.Flags().String("pcap-output", "",
		"Write captured NTRIP/RTCM traffic to a PCAP-NG file (supports Wireshark)")
	cmd.Flags().Int64("pcap-max-size", 100*1024*1024,
		"Max pcap file size in bytes before rotation (default 100MB, 0=unlimited)")
	cmd.Flags().Duration("pcap-max-duration", 1*time.Hour,
		"Max pcap file duration before rotation (default 1h, 0=unlimited)")
	cmd.Flags().String("cos-bucket", "",
		"Tencent Cloud COS bucket name for auto-uploading rotated pcap files")
	cmd.Flags().String("cos-region", "ap-guangzhou",
		"COS region (default ap-guangzhou)")
	cmd.Flags().String("cos-prefix", "",
		"COS object key prefix (e.g. 'captures/agent-01')")
	cmd.Flags().Bool("cos-delete-raw", false,
		"Delete local pcap file after successful COS upload")
	cmd.Flags().Bool("no-tui", false,
		"Disable TUI, run as background agent (logger output only)")
	cmd.Flags().Bool("webui", false,
		"Start embedded Web Console (Agent + Console + frontend in one process)")
	cmd.Flags().String("webui-addr", ":8080",
		"HTTP address for embedded Web Console (default :8080)")
	cmd.Flags().Bool("open-browser", false,
		"Auto-open browser when --webui is enabled")
}

func InitLog() {
	logrus.SetOutput(os.Stdout)
	if viper.GetBool("debug") {
		DefaultLogLevel = int32(logrus.DebugLevel)
	}
	if isValidLogLevel(DefaultLogLevel) {
		common.DefaultLog.SetLevel(logrus.Level(DefaultLogLevel))
	} else {
		common.DefaultLog.SetLevel(logrus.WarnLevel)
	}
	common.AgentLog.SetLevel(common.DefaultLog.Level)
	common.BPFEventLog.SetLevel(common.DefaultLog.Level)
	common.ConntrackLog.SetLevel(common.DefaultLog.Level)
	common.ProtocolParserLog.SetLevel(common.DefaultLog.Level)
	common.UprobeLog.SetLevel(common.DefaultLog.Level)

	// override log level individually
	if isValidLogLevel(AgentLogLevel) {
		common.AgentLog.SetLevel(logrus.Level(AgentLogLevel))
	}
	if isValidLogLevel(BPFEventLogLevel) {
		common.BPFEventLog.SetLevel(logrus.Level(BPFEventLogLevel))
	}
	if isValidLogLevel(ConntrackLogLevel) {
		common.ConntrackLog.SetLevel(logrus.Level(ConntrackLogLevel))
	}
	if isValidLogLevel(ProtocolLogLevel) {
		common.ProtocolParserLog.SetLevel(logrus.Level(ProtocolLogLevel))
	}
	if isValidLogLevel(UprobeLogLevel) {
		common.UprobeLog.SetLevel(logrus.Level(UprobeLogLevel))
	}

	switch common.AgentLog.Level {
	case logrus.InfoLevel:
		fallthrough
	case logrus.DebugLevel:
		break
	default:
		klog.SetLogger(logr.Discard())
	}
}

func isValidLogLevel(level int32) bool {
	if level < int32(logrus.FatalLevel) || level > int32(logrus.DebugLevel) {
		return false
	}
	return true
}
