// Package console implements the Phase 8 Web Console backend.
//
// This file defines the domain types used across the Console subsystem.
// These types bridge the gRPC protobuf events (proto/agentpb) and the
// Console's internal storage, REST API, and WebSocket layers.
//
// Credential-safety invariant: no type in this package carries a password
// or credential field. The Agent-side redactor ensures credentials never
// reach the Console; these types mirror that invariant.
package console

import (
	"time"

	"kyanos/proto/agentpb"
)

// Agent represents a connected Kyanos Agent instance on a specific node.
type Agent struct {
	NodeName      string    `json:"node_name"`
	AgentVersion  string    `json:"agent_version"`
	ManagedPods   []PodInfo `json:"managed_pods"`
	DiscardedEvts uint64    `json:"discarded_events"`
	ConnectedAt   time.Time `json:"connected_at"`
	LastStatusAt  time.Time `json:"last_status_at"`
}

// PodInfo is the resolved Kubernetes Pod identity.
type PodInfo struct {
	PodName      string   `json:"pod_name"`
	PodIP        string   `json:"pod_ip"`
	Namespace    string   `json:"namespace"`
	NodeName     string   `json:"node_name"`
	ContainerIDs []string `json:"container_ids"`
	CgroupIDs    []uint64 `json:"cgroup_ids"`
}

// TaskStatus tracks the lifecycle of a capture task.
type TaskStatus int

const (
	TaskStatusPending TaskStatus = iota
	TaskStatusRunning
	TaskStatusStopped
	TaskStatusCompleted
	TaskStatusFailed
)

func (s TaskStatus) String() string {
	switch s {
	case TaskStatusPending:
		return "pending"
	case TaskStatusRunning:
		return "running"
	case TaskStatusStopped:
		return "stopped"
	case TaskStatusCompleted:
		return "completed"
	case TaskStatusFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// NtripFilterView is the serializable view of NTRIP filter config.
type NtripFilterView struct {
	Mountpoints []string `json:"mountpoints,omitempty"`
	Usernames   []string `json:"usernames,omitempty"`
}

// RtcmFilterView is the serializable view of RTCM filter config.
type RtcmFilterView struct {
	MessageTypes []int32 `json:"message_types,omitempty"`
}

// Task represents a capture task dispatched from the Console to an Agent.
type Task struct {
	ID              string            `json:"id"`
	TargetPod       string            `json:"target_pod"`
	TargetNamespace string            `json:"target_namespace"`
	PodLabels       map[string]string `json:"pod_labels,omitempty"`
	DurationSeconds int64             `json:"duration_seconds"`
	Status          TaskStatus        `json:"status"`
	CreatedAt       time.Time         `json:"created_at"`
	StartedAt       time.Time         `json:"started_at,omitempty"`
	StoppedAt       time.Time         `json:"stopped_at,omitempty"`
	NodeName        string            `json:"node_name"`
	SessionCount    int               `json:"session_count"`
	ExportPCAP      bool              `json:"export_pcap"`
	ExportParsed    bool              `json:"export_parsed"`
	COSBucket       string            `json:"cos_bucket,omitempty"`
	NtripFilter     *NtripFilterView  `json:"ntrip_filter,omitempty"`
	RtcmFilter      *RtcmFilterView   `json:"rtcm_filter,omitempty"`
}

// SessionRecord is the Console's persisted view of a NTRIP session.
// It is populated from SessionEvent streams and SessionCloseEvent summaries.
type SessionRecord struct {
	SessionID  string    `json:"session_id"`
	TaskID     string    `json:"task_id"`
	Mountpoint string    `json:"mountpoint"`
	Username   string    `json:"username"`
	NTRIPVer   string    `json:"ntrip_version"`
	ClientIP   string    `json:"client_ip"`
	ClientPort uint32    `json:"client_port"`
	ServerPod  string    `json:"server_pod"`
	ServerIP   string    `json:"server_ip"`
	NodeName   string    `json:"node_name"`
	StartTime  time.Time `json:"start_time"`
	CloseTime  time.Time `json:"close_time,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	Closed     bool      `json:"closed"`

	// Login (S1)
	AuthMethod     string `json:"auth_method"`
	AuthChecked    bool   `json:"auth_checked"`
	AuthSuccess    bool   `json:"auth_success"`
	HTTPStatusCode int32  `json:"http_status_code"`
	LoginLatencyMs int64  `json:"login_latency_ms"`

	// GGA (S2)
	GGAEvents      int32   `json:"gga_events"`
	GGAFixRate     float64 `json:"gga_fix_rate"`
	GGAAvgSats     float64 `json:"gga_avg_satellites"`
	GGAFrequencyHz float64 `json:"gga_frequency_hz"`

	// RTCM (S3)
	RTCMFrames        int32            `json:"rtcm_frames"`
	RTCMBytes         int64            `json:"rtcm_bytes"`
	RTCMCRCErrors     int32            `json:"rtcm_crc_errors"`
	RTCMCRCErrorRate  float64          `json:"rtcm_crc_error_rate"`
	RTCMAvgIntervalMs int64            `json:"rtcm_avg_interval_ms"`
	RTCMP95IntervalMs int64            `json:"rtcm_p95_interval_ms"`
	RTCMThroughputBps float64          `json:"rtcm_throughput_bps"`
	RTCMInterruptions int32            `json:"rtcm_interruptions"`
	RTCMMessageTypes  map[string]int32 `json:"rtcm_message_types"`

	// Network (S5)
	Retransmissions int32   `json:"retransmissions"`
	RetransmitRate  float64 `json:"retransmission_rate"`
	AvgRTTMs        float64 `json:"avg_rtt_ms"`
	P95RTTMs        float64 `json:"p95_rtt_ms"`
	RTTJitterMs     float64 `json:"rtt_jitter_ms"`
	TCPResets       int32   `json:"tcp_resets"`

	// Disconnect (S4)
	DisconnectReason string `json:"disconnect_reason"`
	DisconnectDetail string `json:"disconnect_detail"`

	// Diagnostic score
	Score          int32 `json:"score"`
	LoginScore     int32 `json:"login_score"`
	GGAScore       int32 `json:"gga_score"`
	RTCMScore      int32 `json:"rtcm_score"`
	NetworkScore   int32 `json:"network_score"`
	StabilityScore int32 `json:"stability_score"`

	Issues []SessionIssue `json:"issues,omitempty"`
}

// SessionIssue is a diagnostic issue attached to a session.
type SessionIssue struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// SessionEventRecord is a single diagnostic event within a session's timeline.
type SessionEventRecord struct {
	TaskID      string    `json:"task_id"`
	SessionID   string    `json:"session_id"`
	TimestampNs int64     `json:"timestamp_ns"`
	Timestamp   time.Time `json:"timestamp"`
	PodName     string    `json:"pod_name,omitempty"`
	PodNS       string    `json:"pod_namespace,omitempty"`
	ClientIP    string    `json:"client_ip,omitempty"`
	ClientPort  uint32    `json:"client_port,omitempty"`
	EventType   string    `json:"event_type"` // auth, gga, rtcm, network, close
	EventData   any       `json:"event_data"`
}

// AuthEventData is the parsed payload of an auth event.
type AuthEventData struct {
	Method         string `json:"method"`
	Success        bool   `json:"success"`
	HTTPStatus     int32  `json:"http_status"`
	Mountpoint     string `json:"mountpoint"`
	Username       string `json:"username"`
	LoginLatencyMs int64  `json:"login_latency_ms"`
}

// GGAEventData is the parsed payload of a GGA event.
type GGAEventData struct {
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	FixQuality  int32   `json:"fix_quality"`
	NumSats     int32   `json:"num_satellites"`
	HDOP        float64 `json:"hdop"`
	DiffAge     float64 `json:"diff_age"`
	DiffStation string  `json:"diff_station_id"`
}

// RTCMEventData is the parsed payload of an RTCM event.
type RTCMEventData struct {
	MessageType int32 `json:"message_type"`
	Size        int32 `json:"size"`
	CRCValid    bool  `json:"crc_valid"`
	IntervalMs  int64 `json:"interval_ms"`
}

// NetworkEventData is the parsed payload of a network event.
type NetworkEventData struct {
	Retransmissions int32   `json:"retransmissions"`
	RetransmitRate  float64 `json:"retransmission_rate"`
	AvgRTTUs        int64   `json:"avg_rtt_us"`
	P95RTTUs        int64   `json:"p95_rtt_us"`
	RTTJitterUs     int64   `json:"rtt_jitter_us"`
	TCPResets       int32   `json:"tcp_resets"`
}

// CloseEventData is the parsed payload of a session close event.
type CloseEventData struct {
	Reason     string `json:"reason"`
	Detail     string `json:"detail"`
	HasSummary bool   `json:"has_summary"`
}

// SessionFilter specifies query filters for session listing.
type SessionFilter struct {
	TaskID     string
	Mountpoint string
	Username   string
	ServerPod  string
	NodeName   string
	Closed     *bool // nil = all, true = closed only, false = active only
	MinScore   *int32
	MaxScore   *int32
	Since      *time.Time
	Until      *time.Time
	Limit      int
	Offset     int
}

// TopologyView is the cluster topology for the REST API.
type TopologyView struct {
	Nodes []NodeView `json:"nodes"`
}

// NodeView is a single node in the cluster topology.
type NodeView struct {
	Name          string   `json:"name"`
	AgentVersion  string   `json:"agent_version"`
	PodCount      int      `json:"pod_count"`
	ActiveSession int      `json:"active_sessions"`
	Connected     bool     `json:"connected"`
	Pods          []string `json:"pods"`
}

// --- Protobuf conversion helpers ---

// PodInfoFromProto converts a protobuf PodInfo to the console domain type.
func PodInfoFromProto(p *agentpb.PodInfo) PodInfo {
	if p == nil {
		return PodInfo{}
	}
	return PodInfo{
		PodName:      p.PodName,
		PodIP:        p.PodIp,
		Namespace:    p.Namespace,
		NodeName:     p.NodeName,
		ContainerIDs: p.ContainerIds,
		CgroupIDs:    p.CgroupIds,
	}
}

// PodInfosFromProto converts a slice of protobuf PodInfo.
func PodInfosFromProto(ps []*agentpb.PodInfo) []PodInfo {
	if len(ps) == 0 {
		return nil
	}
	out := make([]PodInfo, len(ps))
	for i, p := range ps {
		out[i] = PodInfoFromProto(p)
	}
	return out
}

// SessionRecordFromSummary builds a SessionRecord from a protobuf SessionSummary
// delivered inside a SessionCloseEvent.
func SessionRecordFromSummary(s *agentpb.SessionSummary, taskID, nodeName string) *SessionRecord {
	if s == nil {
		return nil
	}
	rec := &SessionRecord{
		SessionID:  s.SessionId,
		TaskID:     taskID,
		Mountpoint: s.Mountpoint,
		Username:   s.Username,
		NTRIPVer:   s.NtripVersion,
		ClientIP:   s.ClientIp,
		ClientPort: s.ClientPort,
		ServerPod:  s.ServerPod,
		ServerIP:   s.ServerIp,
		NodeName:   nodeName,
		StartTime:  time.Unix(0, s.StartTimeNs),
		CloseTime:  time.Unix(0, s.CloseTimeNs),
		DurationMs: s.DurationMs,
		Closed:     true,

		AuthMethod:     s.AuthMethod,
		AuthChecked:    s.AuthChecked,
		AuthSuccess:    s.AuthSuccess,
		HTTPStatusCode: s.HttpStatusCode,
		LoginLatencyMs: s.LoginLatencyMs,

		GGAEvents:      s.GgaEvents,
		GGAFixRate:     s.GgaFixRate,
		GGAAvgSats:     s.GgaAvgSatellites,
		GGAFrequencyHz: s.GgaFrequencyHz,

		RTCMFrames:        s.RtcmFrames,
		RTCMBytes:         s.RtcmBytes,
		RTCMCRCErrors:     s.RtcmCrcErrors,
		RTCMCRCErrorRate:  s.RtcmCrcErrorRate,
		RTCMAvgIntervalMs: s.RtcmAvgIntervalMs,
		RTCMP95IntervalMs: s.RtcmP95IntervalMs,
		RTCMThroughputBps: s.RtcmThroughputBps,
		RTCMInterruptions: s.RtcmInterruptions,
		RTCMMessageTypes:  s.RtcmMessageTypes,

		Retransmissions: s.Retransmissions,
		RetransmitRate:  s.RetransmissionRate,
		AvgRTTMs:        s.AvgRttMs,
		P95RTTMs:        s.P95RttMs,
		RTTJitterMs:     s.RttJitterMs,
		TCPResets:       s.TcpResets,

		DisconnectReason: s.DisconnectReason,
		DisconnectDetail: s.DisconnectDetail,

		Score:          s.Score,
		LoginScore:     s.LoginScore,
		GGAScore:       s.GgaScore,
		RTCMScore:      s.RtcmScore,
		NetworkScore:   s.NetworkScore,
		StabilityScore: s.StabilityScore,
	}

	if len(s.Issues) > 0 {
		rec.Issues = make([]SessionIssue, len(s.Issues))
		for i, iss := range s.Issues {
			rec.Issues[i] = SessionIssue{
				Category:    iss.Category,
				Severity:    iss.Severity,
				Description: iss.Description,
			}
		}
	}
	return rec
}

// EventRecordFromProto converts a protobuf SessionEvent into a
// SessionEventRecord for storage.
func EventRecordFromProto(e *agentpb.SessionEvent) *SessionEventRecord {
	if e == nil {
		return nil
	}
	rec := &SessionEventRecord{
		TaskID:      e.TaskId,
		SessionID:   e.SessionId,
		TimestampNs: e.TimestampNs,
		Timestamp:   time.Unix(0, e.TimestampNs),
		ClientIP:    e.GetObservedClient().GetIp(),
		ClientPort:  e.GetObservedClient().GetPort(),
	}
	if e.Pod != nil {
		rec.PodName = e.Pod.PodName
		rec.PodNS = e.Pod.Namespace
	}

	switch ev := e.Event.(type) {
	case *agentpb.SessionEvent_Auth:
		rec.EventType = "auth"
		rec.EventData = AuthEventData{
			Method:         ev.Auth.Method,
			Success:        ev.Auth.Success,
			HTTPStatus:     ev.Auth.HttpStatus,
			Mountpoint:     ev.Auth.Mountpoint,
			Username:       ev.Auth.Username,
			LoginLatencyMs: ev.Auth.LoginLatencyMs,
		}
	case *agentpb.SessionEvent_Gga:
		rec.EventType = "gga"
		rec.EventData = GGAEventData{
			Latitude:    ev.Gga.Latitude,
			Longitude:   ev.Gga.Longitude,
			FixQuality:  ev.Gga.FixQuality,
			NumSats:     ev.Gga.NumSatellites,
			HDOP:        ev.Gga.Hdop,
			DiffAge:     ev.Gga.DiffAge,
			DiffStation: ev.Gga.DiffStationId,
		}
	case *agentpb.SessionEvent_Rtcm:
		rec.EventType = "rtcm"
		rec.EventData = RTCMEventData{
			MessageType: ev.Rtcm.MessageType,
			Size:        ev.Rtcm.Size,
			CRCValid:    ev.Rtcm.CrcValid,
			IntervalMs:  ev.Rtcm.IntervalMs,
		}
	case *agentpb.SessionEvent_Network:
		rec.EventType = "network"
		rec.EventData = NetworkEventData{
			Retransmissions: ev.Network.Retransmissions,
			RetransmitRate:  ev.Network.RetransmissionRate,
			AvgRTTUs:        ev.Network.AvgRttUs,
			P95RTTUs:        ev.Network.P95RttUs,
			RTTJitterUs:     ev.Network.RttJitterUs,
			TCPResets:       ev.Network.TcpResets,
		}
	case *agentpb.SessionEvent_Close:
		rec.EventType = "close"
		rec.EventData = CloseEventData{
			Reason:     ev.Close.DisconnectReason,
			Detail:     ev.Close.DisconnectDetail,
			HasSummary: ev.Close.Summary != nil,
		}
	default:
		rec.EventType = "unknown"
	}
	return rec
}

// AnalyticsSummary represents the aggregated cluster statistics.
type AnalyticsSummary struct {
	TotalSessions     int               `json:"total_sessions"`
	ActiveSessions    int               `json:"active_sessions"`
	AverageScore      float64           `json:"average_score"`
	ScoreDistribution map[string]int    `json:"score_distribution"` // "healthy", "degraded", "poor", "critical"
	TopIssues         []IssueCount      `json:"top_issues"`
	WorstSessions     []*SessionRecord  `json:"worst_sessions"`
	AgentStats        []AgentPerfStats  `json:"agent_stats"`
}

// IssueCount represents the occurrence count of a diagnostic issue category.
type IssueCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// AgentPerfStats holds performance and state stats for an agent.
type AgentPerfStats struct {
	NodeName      string `json:"node_name"`
	Connected     bool   `json:"connected"`
	ActiveSession int    `json:"active_sessions"`
	DiscardedEvts uint64 `json:"discarded_events"`
}
