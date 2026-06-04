// Package controlplane implements the Phase 7 gRPC control-plane subsystem.
//
// This file implements the EventReporter: it subscribes to granular session
// diagnostic events (via session.SessionEventListener), projects them into proto
// SessionEvent messages, enforces the credential redaction gate, tags task_id
// and PodInfo, preserves the observed client address verbatim, and forwards
// accepted events to the EventBuffer.
package controlplane

import (
	"strconv"
	"time"

	"kyanos/agent/session"
	"kyanos/common"
	"kyanos/proto/agentpb"
)

// EventReporter implements session.SessionEventListener and projects session
// diagnostic events into proto SessionEvent messages for the control plane.
//
// A single internal projection path (the projectXxx functions) is the only way
// session state reaches a wire event. It structurally omits the password (it
// never reads NTRIPSession.Password into any proto field) and then passes the
// event through the Redactor gate before forwarding.
//
// Requirements: 3.9, 4.1–4.10, 8.1, 9.2
type EventReporter struct {
	tasks    *TaskManager
	resolver *PodResolver
	redactor *Redactor
	out      func(*agentpb.SessionEvent) // typically EventBuffer.Push
	silent   bool                        // Req 4.10: silent-block configuration
}

// EventReporterConfig holds construction parameters for an EventReporter.
type EventReporterConfig struct {
	Tasks    *TaskManager
	Resolver *PodResolver
	Redactor *Redactor
	Out      func(*agentpb.SessionEvent)
	Silent   bool
}

// NewEventReporter constructs an EventReporter. All fields in cfg should be
// non-nil except Resolver (which is nil when Pod resolution is disabled).
func NewEventReporter(cfg EventReporterConfig) *EventReporter {
	return &EventReporter{
		tasks:    cfg.Tasks,
		resolver: cfg.Resolver,
		redactor: cfg.Redactor,
		out:      cfg.Out,
		silent:   cfg.Silent,
	}
}

// ---------------------------------------------------------------------------
// session.SessionEventListener implementation
// ---------------------------------------------------------------------------

// OnAuthEvent fires when an authentication outcome is recorded.
// (Requirement 4.2)
func (r *EventReporter) OnAuthEvent(s *session.NTRIPSession) {
	ev := r.projectAuthEvent(s)
	r.gate(ev, s)
}

// OnGGAEvent fires when a GGA position upload is recorded.
// (Requirement 4.3)
func (r *EventReporter) OnGGAEvent(s *session.NTRIPSession, e session.GGAEvent) {
	ev := r.projectGGAEvent(s, e)
	r.gate(ev, s)
}

// OnRTCMEvent fires when an RTCM frame delivery is recorded.
// (Requirement 4.4)
func (r *EventReporter) OnRTCMEvent(s *session.NTRIPSession, e session.RTCMEvent) {
	ev := r.projectRTCMEvent(s, e)
	r.gate(ev, s)
}

// OnNetworkEvent fires when a TCP/network-quality observation is recorded.
// (Requirement 4.5)
func (r *EventReporter) OnNetworkEvent(s *session.NTRIPSession, kind session.NetworkEventKind) {
	ev := r.projectNetworkEvent(s, kind)
	r.gate(ev, s)
}

// OnSessionClose fires when a session is closed.
// (Requirement 4.6)
func (r *EventReporter) OnSessionClose(s *session.NTRIPSession) {
	ev := r.projectCloseEvent(s)
	r.gate(ev, s)
}

// ---------------------------------------------------------------------------
// Event projection functions
// ---------------------------------------------------------------------------

// projectAuthEvent maps the session's current auth state to a SessionEvent with
// an AuthEvent oneof variant.
//
// NOTE: This function NEVER reads s.Password — structural omission of the
// NTRIP credential (Requirement 4.8, 8.1).
func (r *EventReporter) projectAuthEvent(s *session.NTRIPSession) *agentpb.SessionEvent {
	// The tracker fires this callback after releasing the session lock, so the
	// exported fields we read are stable (write-before-fire discipline).
	auth := &agentpb.AuthEvent{
		Method:         s.AuthMethod,
		Success:        s.AuthSuccess,
		HttpStatus:     int32(s.HTTPStatusCode),
		Mountpoint:     s.MountPoint,
		Username:       s.Username,
		LoginLatencyMs: s.LoginLatency.Milliseconds(),
	}

	ev := r.buildEnvelope(s)
	ev.Event = &agentpb.SessionEvent_Auth{Auth: auth}
	return ev
}

// projectGGAEvent maps a GGA event to a SessionEvent with a GgaEvent variant.
func (r *EventReporter) projectGGAEvent(s *session.NTRIPSession, e session.GGAEvent) *agentpb.SessionEvent {
	gga := &agentpb.GgaEvent{
		Latitude:      e.Latitude,
		Longitude:     e.Longitude,
		FixQuality:    int32(e.FixQuality),
		NumSatellites: int32(e.NumSatellites),
		Hdop:          e.HDOP,
		DiffAge:       e.DiffAge,
		DiffStationId: e.DiffStationID,
	}

	ev := r.buildEnvelope(s)
	ev.Event = &agentpb.SessionEvent_Gga{Gga: gga}
	return ev
}

// projectRTCMEvent maps an RTCM event to a SessionEvent with an RtcmEvent variant.
func (r *EventReporter) projectRTCMEvent(s *session.NTRIPSession, e session.RTCMEvent) *agentpb.SessionEvent {
	rtcm := &agentpb.RtcmEvent{
		MessageType: int32(e.MessageType),
		Size:        int32(e.Size),
		CrcValid:    e.CRCValid,
		IntervalMs:  e.Interval.Milliseconds(),
	}

	ev := r.buildEnvelope(s)
	ev.Event = &agentpb.SessionEvent_Rtcm{Rtcm: rtcm}
	return ev
}

// projectNetworkEvent maps the session's current network-quality state to a
// SessionEvent with a NetworkEvent variant.
func (r *EventReporter) projectNetworkEvent(s *session.NTRIPSession, _ session.NetworkEventKind) *agentpb.SessionEvent {
	nq := s.NetworkQuality

	net := &agentpb.NetworkEvent{
		Retransmissions:    int32(nq.TotalRetransmissions),
		RetransmissionRate: nq.RetransmissionRate,
		AvgRttUs:           nq.AvgRTT.Microseconds(),
		P95RttUs:           nq.P95RTT.Microseconds(),
		RttJitterUs:        nq.RTTJitter.Microseconds(),
		TcpResets:          int32(len(nq.TCPResetEvents)),
	}

	ev := r.buildEnvelope(s)
	ev.Event = &agentpb.SessionEvent_Network{Network: net}
	return ev
}

// projectCloseEvent maps a closed session to a SessionEvent with a
// SessionCloseEvent variant. The summary is always present, even if the session
// recorded no prior events. (Requirement 4.6)
//
// NOTE: buildSessionSummary NEVER reads s.Password — structural omission.
func (r *EventReporter) projectCloseEvent(s *session.NTRIPSession) *agentpb.SessionEvent {
	closeEv := &agentpb.SessionCloseEvent{
		DisconnectReason: s.DisconnectReason.String(),
		DisconnectDetail: s.DisconnectDetail,
		Summary:          buildSessionSummary(s),
	}

	ev := r.buildEnvelope(s)
	ev.Event = &agentpb.SessionEvent_Close{Close: closeEv}
	return ev
}

// ---------------------------------------------------------------------------
// Envelope and helper functions
// ---------------------------------------------------------------------------

// buildEnvelope constructs the common SessionEvent envelope fields: task_id,
// session_id, timestamp, PodInfo, and observed client address (Requirement 9.2).
// The caller fills in the oneof variant after this returns.
func (r *EventReporter) buildEnvelope(s *session.NTRIPSession) *agentpb.SessionEvent {
	ev := &agentpb.SessionEvent{
		SessionId:   s.SessionID,
		TimestampNs: time.Now().UnixNano(),
		ObservedClient: &agentpb.ClientAddr{
			Ip:   s.ClientIP,
			Port: uint32(s.ClientPort),
		},
	}

	// Tag task_id via TaskManager (Requirement 3.9).
	if r.tasks != nil {
		if taskID, ok := r.tasks.TaskIDForSession(s); ok {
			ev.TaskId = taskID
		}
	}

	// Enrich with PodInfo via PodResolver (if available).
	if r.resolver != nil {
		ev.Pod = r.lookupPodForSession(s)
	}

	return ev
}

// lookupPodForSession attempts to find PodInfo for the session's server pod.
// Returns nil if no match is found or if the resolver is in fallback mode.
//
// The PodResolver's Lookup method is keyed by cgroup ID. At the EventReporter
// level, we don't have the kernel-level cgroup ID directly. In a full
// integration the cgroup ID would be carried by the kernel event and passed
// through the pipeline. For now, PodInfo enrichment relies on future wiring —
// the field is documented as "may be empty" in the proto definition.
func (r *EventReporter) lookupPodForSession(_ *session.NTRIPSession) *agentpb.PodInfo {
	if r.resolver == nil || r.resolver.InFallback() {
		return nil
	}

	// The PodResolver exposes Lookup(cgroupID uint64) but the reporter
	// doesn't have the cgroup ID at this level. Full integration will pass
	// the cgroup ID through the event pipeline. Return nil (field is optional).
	return nil
}

// buildSessionSummary constructs a proto SessionSummary from a session.
//
// NOTE: This function NEVER reads s.Password — structural omission of the
// credential. The SessionSummary proto intentionally carries no credential field.
func buildSessionSummary(s *session.NTRIPSession) *agentpb.SessionSummary {
	var closeTimeNs int64
	var durationMs int64
	if s.ConnCloseTime != nil {
		closeTimeNs = s.ConnCloseTime.UnixNano()
		durationMs = s.ConnCloseTime.Sub(s.ConnStartTime).Milliseconds()
	}

	// RTCM message types: convert int keys to string keys for the proto map.
	rtcmMsgTypes := make(map[string]int32, len(s.RTCMStats.MessageTypes))
	for k, v := range s.RTCMStats.MessageTypes {
		rtcmMsgTypes[strconv.Itoa(k)] = int32(v)
	}

	return &agentpb.SessionSummary{
		SessionId:    s.SessionID,
		Mountpoint:   s.MountPoint,
		Username:     s.Username,
		NtripVersion: s.NTRIPVersion,
		ClientIp:     s.ClientIP,
		ClientPort:   uint32(s.ClientPort),
		ServerPod:    s.ServerPod,
		ServerIp:     s.ServerIP,
		StartTimeNs:  s.ConnStartTime.UnixNano(),
		CloseTimeNs:  closeTimeNs,
		DurationMs:   durationMs,
		// Auth (S1)
		AuthMethod:     s.AuthMethod,
		AuthChecked:    s.AuthChecked,
		AuthSuccess:    s.AuthSuccess,
		HttpStatusCode: int32(s.HTTPStatusCode),
		LoginLatencyMs: s.LoginLatency.Milliseconds(),
		// GGA (S2)
		GgaEvents:      int32(len(s.GGAEvents)),
		GgaFrequencyHz: s.GGAFrequency,
		// RTCM (S3)
		RtcmFrames:        int32(s.RTCMStats.TotalFrames),
		RtcmBytes:         s.RTCMStats.TotalBytes,
		RtcmCrcErrors:     int32(s.RTCMStats.CRCErrors),
		RtcmCrcErrorRate:  s.RTCMStats.CRCErrorRate,
		RtcmAvgIntervalMs: s.RTCMStats.AvgInterval.Milliseconds(),
		RtcmP95IntervalMs: s.RTCMStats.P95Interval.Milliseconds(),
		RtcmThroughputBps: s.RTCMStats.ThroughputBps,
		RtcmInterruptions: int32(len(s.RTCMStats.Interruptions)),
		RtcmMessageTypes:  rtcmMsgTypes,
		// Network (S5)
		Retransmissions:    int32(s.NetworkQuality.TotalRetransmissions),
		RetransmissionRate: s.NetworkQuality.RetransmissionRate,
	}
}

// ---------------------------------------------------------------------------
// Redaction gate
// ---------------------------------------------------------------------------

// gate passes the projected event through the Redactor credential gate. If the
// gate confirms the event is clean, it is forwarded to the EventBuffer. If it
// cannot confirm, the event is blocked.
//
// On a block, a descriptive error is emitted unless silent mode is configured
// (Requirement 4.10).
func (r *EventReporter) gate(ev *agentpb.SessionEvent, s *session.NTRIPSession) {
	if ev == nil {
		return
	}

	// Collect the session's secret(s) for the redaction gate.
	// We read Password directly — it's an exported field and the tracker has
	// already released the session lock before calling us.
	password := s.Password

	secrets := []string{password}

	// Run the redaction gate (Requirement 4.8, 4.9).
	if r.redactor != nil && !r.redactor.Confirm(ev, secrets) {
		// Cannot confirm the event excludes the credential — block it.
		if !r.silent {
			common.AgentLog.Errorf(
				"EventReporter: blocked SessionEvent for session %q — "+
					"cannot confirm NTRIP password exclusion",
				ev.GetSessionId(),
			)
		}
		return
	}

	// Event confirmed clean; forward to the buffer.
	if r.out != nil {
		r.out(ev)
	}
}

// ---------------------------------------------------------------------------
// Compile-time interface assertion
// ---------------------------------------------------------------------------

var _ session.SessionEventListener = (*EventReporter)(nil)
