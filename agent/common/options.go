package common

import (
	"container/list"
	"context"
	"fmt"
	anc "kyanos/agent/analysis/common"
	"kyanos/agent/compatible"
	"kyanos/agent/metadata"
	"kyanos/agent/protocol"
	"kyanos/agent/render/watch"
	"kyanos/agent/session"
	"kyanos/bpf"
	"kyanos/common"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type LoadBpfProgramFunction func() *list.List
type InitCompletedHook func()
type ConnManagerInitHook func(any)

var Options *AgentOptions

const perfEventDataBufferSize = 30 * 1024 * 1024
const perfEventControlBufferSize = 1 * 1024 * 1024

type AgentOptions struct {
	Stopper                chan os.Signal
	CustomSyscallEventHook bpf.SyscallEventHook
	CustomConnEventHook    bpf.ConnEventHook
	CustomKernEventHook    bpf.KernEventHook
	CustomSslEventHook     bpf.SslEventHook
	InitCompletedHook      InitCompletedHook
	ConnManagerInitHook    ConnManagerInitHook
	LoadBpfProgramFunction LoadBpfProgramFunction
	ProcessorsNum          int
	MessageFilter          protocol.ProtocolFilter
	LatencyFilter          protocol.LatencyFilter
	TraceSide              common.SideEnum
	IfName                 string
	BTFFilePath            string
	protocol.SizeFilter
	AnalysisEnable bool
	anc.AnalysisOptions
	PerfEventBufferSizeForData  int
	PerfEventBufferSizeForEvent int
	WatchOptions                watch.WatchOptions
	PerformanceMode             bool
	ConntrackCloseWaitTimeMills int
	MaxAllowStuckTimeMills      int
	StartGopsServer             bool

	// RecordExportFunc is called for every parsed record before filtering.
	// Used for RTCM data export: writes raw frames to .rtcm files.
	RecordExportFunc func(record protocol.Record)

	// SessionDiagnosisEnable turns on the NTRIP/RTCM session-level diagnostic
	// engine (agent/session). When false, the tracker is never constructed and
	// behaviour is identical to upstream kyanos.
	SessionDiagnosisEnable bool
	// SessionTrackerConfig tunes the diagnostic engine. Only consulted when
	// SessionDiagnosisEnable is true.
	SessionTrackerConfig session.TrackerConfig
	// SessionPodLoadEnable attaches a PodLoadAnalyzer (S6 multi-Pod load
	// analysis) to the tracker. Only consulted when SessionDiagnosisEnable is
	// true.
	SessionPodLoadEnable bool
	// SessionReportEnable attaches a DiagnosticReporter that prints a per-session
	// diagnostic report when each session closes. Only consulted when
	// SessionDiagnosisEnable is true.
	SessionReportEnable bool
	// SessionJSONLPath, when non-empty, enables structured JSONL export: one
	// session-summary JSON object per line is written to this file as sessions
	// close. Only consulted when SessionDiagnosisEnable is true.
	SessionJSONLPath string

	// PcapOutputPath, when non-empty, writes captured NTRIP/RTCM traffic to a
	// PCAP-NG file at this path. Supports file rotation via PcapMaxSize and
	// PcapMaxDuration. Does not require --diag or gRPC.
	PcapOutputPath string
	// PcapMaxSize is the max pcap file size in bytes before rotation (0 = unlimited).
	PcapMaxSize int64
	// PcapMaxDuration is the max pcap file duration before rotation (0 = unlimited).
	PcapMaxDuration time.Duration

	// GRPCServer is the Control Plane / Console address (host:port) supplied via
	// the --grpc-server flag. An empty value (the default zero value) keeps the
	// Agent in Standalone_CLI_Mode: no gRPC_Client is constructed and behaviour
	// is identical to the existing standalone CLI tool. A non-empty value
	// activates gRPC_Mode. (Requirement 1.2)
	GRPCServer string
	// GRPCOptions tunes the gRPC control-plane subsystem. It is only consulted
	// when GRPCServer is non-empty (gRPC_Mode); its zero value corresponds to
	// the disabled/default configuration.
	GRPCOptions GRPCOptions

	FilterComm              string
	ProcessExecEventChannel chan *bpf.AgentProcessExecEvent
	DockerEndpoint          string
	ContainerdEndpoint      string
	CriRuntimeEndpoint      string
	ContainerId             string
	ContainerName           string
	PodName                 string
	PodNameSpace            string

	Cc                  *metadata.ContainerCache
	Objs                any
	Ctx                 context.Context
	Kv                  *compatible.KernelVersion
	LoadPorgressChannel chan string

	SyscallPerfEventMapPageNum int
	SslPerfEventMapPageNum     int
	ConnPerfEventMapPageNum    int
	KernPerfEventMapPageNum    int
	FirstPacketEventMapPageNum int
}

// GRPCTLSConfig holds the transport-credential material for the Console
// connection. Credentials are referenced by configuration key name in logs and
// never logged by value (Requirement 8.6). The zero value (Enable=false)
// selects a plaintext transport.
type GRPCTLSConfig struct {
	// Enable turns on an encrypted transport to the Console (Requirement 8.2).
	Enable bool
	// Insecure requests an encrypted connection that skips transport
	// authentication (server-certificate verification). Only consulted when
	// Enable is true (Requirement 8.3).
	Insecure bool
	// CAPath is the path to the CA certificate bundle used to verify the
	// Console's certificate. Referenced by key name in logs only (Req 8.6).
	CAPath string
	// CertPath is the path to the client certificate for mutual TLS.
	// Referenced by key name in logs only (Req 8.6).
	CertPath string
	// KeyPath is the path to the client private key for mutual TLS.
	// Referenced by key name in logs only (Req 8.6).
	KeyPath string
}

// GRPCOptions tunes the Phase 7 gRPC control-plane subsystem. It is only
// consulted when AgentOptions.GRPCServer is non-empty (gRPC_Mode). Its zero
// value corresponds to the disabled/default configuration, preserving
// Standalone_CLI_Mode behaviour (additive, not replacing).
type GRPCOptions struct {
	// TLS configures the transport credentials for the Console connection
	// (Requirements 8.2, 8.3, 8.6).
	TLS GRPCTLSConfig
	// PodResolve enables the PodResolver, mapping kernel events to K8s Pod
	// identities. When false, the Agent uses the existing container-id based
	// filtering (Requirement 6.9).
	PodResolve bool
	// Namespace is the target Kubernetes namespace for Pod resolution.
	// Only consulted when PodResolve is true (Requirement 6.1).
	Namespace string
	// Selector is the target Kubernetes label selector for Pod resolution.
	// Only consulted when PodResolve is true (Requirement 6.1).
	Selector string
	// BufferCapacity is the maximum number of SessionEvents retained in the
	// Local_Event_Buffer while the gRPC_Stream is disconnected (Requirement 7.3).
	BufferCapacity int
	// BackoffMax caps the exponential reconnection Backoff delay so reconnection
	// attempts continue at a bounded interval (Requirement 7.2).
	BackoffMax time.Duration
	// HeartbeatInterval is the period between Heartbeat keep-alives sent over the
	// established gRPC_Stream (Requirement 7.6).
	HeartbeatInterval time.Duration
	// HeartbeatTimeout is the maximum time to wait for a Heartbeat acknowledgment
	// before treating the gRPC_Stream as lost (Requirement 7.7).
	HeartbeatTimeout time.Duration
}

func (o AgentOptions) FilterByContainer() bool {
	return o.ContainerId != "" || o.ContainerName != "" || o.PodName != ""
}

func (o AgentOptions) FilterByK8s() bool {
	return o.PodName != ""
}

// GRPCModeEnabled reports whether the Agent operates in gRPC_Mode. It is a pure
// function of the options: gRPC_Mode is active if and only if GRPCServer is
// non-empty. An empty GRPCServer keeps the Agent in Standalone_CLI_Mode, in
// which no gRPC_Client is constructed and no outbound connection to a Console
// is opened (Requirements 1.1, 1.2, 1.3, 1.6).
func (o AgentOptions) GRPCModeEnabled() bool {
	return o.GRPCServer != ""
}

// PodResolutionEnabled reports whether the PodResolver should be activated. It
// is a pure function of the options: Pod resolution is active if and only if
// gRPC_Mode is active AND the PodResolve toggle is set. When inactive, the
// Agent continues to use the existing container-id based filtering, preserving
// Standalone_CLI_Mode behaviour (Requirement 6.9).
func (o AgentOptions) PodResolutionEnabled() bool {
	return o.GRPCModeEnabled() && o.GRPCOptions.PodResolve
}

func getPodNameFilter(raw string) (name, ns string) {
	if !strings.Contains(raw, ".") {
		return raw, "default"
	}
	index := strings.LastIndex(raw, ".")
	return raw[:index], raw[index+1:]
}

func getEndpoint(raw string) string {
	if strings.HasPrefix(raw, "http") {
		return raw
	}
	if strings.HasPrefix(raw, "unix://") {
		return raw
	}
	return fmt.Sprintf("unix://%s", raw)
}

// validateGRPCServer validates a Console address supplied via --grpc-server.
// It returns nil if and only if addr is a non-empty, syntactically valid
// host:port address; otherwise it returns a descriptive error whose text
// includes the offending value (Requirement 1.5).
//
// Validation is purely syntactic (no DNS resolution or dialing) so it is a pure
// function suitable for startup gating. The address must be host:port with a
// non-empty host, no surrounding/embedded whitespace, and a numeric port in the
// range 1-65535.
func validateGRPCServer(addr string) error {
	if addr == "" {
		return fmt.Errorf("invalid --grpc-server value %q: address must not be empty", addr)
	}
	if strings.TrimSpace(addr) != addr || strings.ContainsAny(addr, " \t\r\n") {
		return fmt.Errorf("invalid --grpc-server value %q: address must not contain whitespace", addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --grpc-server value %q: expected host:port (%v)", addr, err)
	}
	if host == "" {
		return fmt.Errorf("invalid --grpc-server value %q: host must not be empty", addr)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid --grpc-server value %q: port %q is not a number", addr, port)
	}
	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid --grpc-server value %q: port %d is out of range 1-65535", addr, portNum)
	}
	return nil
}

func ValidateAndRepairOptions(options AgentOptions) (AgentOptions, error) {
	var newOptions = options
	if newOptions.Stopper == nil {
		newOptions.Stopper = make(chan os.Signal)
	}
	if newOptions.ProcessorsNum == 0 {
		newOptions.ProcessorsNum = runtime.NumCPU()
	}
	if newOptions.MessageFilter == nil {
		newOptions.MessageFilter = protocol.BaseFilter{}
	}
	if newOptions.PerfEventBufferSizeForData <= 0 {
		newOptions.PerfEventBufferSizeForData = perfEventDataBufferSize
	}
	if newOptions.PerfEventBufferSizeForEvent <= 0 {
		newOptions.PerfEventBufferSizeForEvent = perfEventControlBufferSize
	}
	// gRPC control-plane mode is opt-in (additive, not replacing). An empty
	// GRPCServer keeps the Agent in Standalone_CLI_Mode and must NOT be
	// rejected. Only validate the address when it is non-empty; an invalid
	// non-empty address rejects startup (Requirements 1.1, 1.5).
	if newOptions.GRPCServer != "" {
		if err := validateGRPCServer(newOptions.GRPCServer); err != nil {
			return newOptions, err
		}
	}
	if newOptions.PodName != "" {
		newOptions.PodName, newOptions.PodNameSpace = getPodNameFilter(newOptions.PodName)
	}
	if newOptions.DockerEndpoint != "" {
		newOptions.DockerEndpoint = getEndpoint(newOptions.DockerEndpoint)
	}
	if newOptions.CriRuntimeEndpoint != "" {
		newOptions.CriRuntimeEndpoint = getEndpoint(newOptions.CriRuntimeEndpoint)
	}
	newOptions.WatchOptions.Init()
	newOptions.LoadPorgressChannel = make(chan string, 10)
	return newOptions, nil
}
