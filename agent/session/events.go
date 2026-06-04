package session

// ---------------------------------------------------------------------------
// Granular session event listener (Phase 7)
// ---------------------------------------------------------------------------
//
// SessionEventListener is an *additive* richer counterpart to SessionListener.
// The existing SessionListener (OnSessionCreated/OnSessionClosed) is left
// unchanged; the SessionTracker fires both, so existing consumers keep working
// while real-time consumers (e.g. the gRPC control-plane EventReporter) can
// observe per-event authentication, GGA, RTCM, network, and close activity as
// it happens.
//
// Design constraint: the session package keeps ZERO dependency on gRPC or the
// controlplane package. This interface and its value types are expressed purely
// in terms of session-local types (NTRIPSession, GGAEvent, RTCMEvent,
// NetworkEventKind), preserving the existing decoupling discipline where
// `session` depends only on `protocol/*`. The controlplane.EventReporter
// implements this interface from the other side.
//
// Note: GGAEvent and RTCMEvent are defined in types.go and are reused here
// verbatim; they are intentionally not redefined in this file.
type SessionEventListener interface {
	// OnAuthEvent fires when an authentication outcome is recorded for the
	// session (request seen, or response observed updating auth state).
	OnAuthEvent(s *NTRIPSession)

	// OnGGAEvent fires when a GGA position upload is recorded for the session.
	// e is the GGA event that was just appended to the session.
	OnGGAEvent(s *NTRIPSession, e GGAEvent)

	// OnRTCMEvent fires when an RTCM frame delivery is recorded for the session.
	// e is the RTCM event that was just appended to the session.
	OnRTCMEvent(s *NTRIPSession, e RTCMEvent)

	// OnNetworkEvent fires when a TCP/network-quality observation is recorded
	// for the session. kind discriminates which kind of network event occurred.
	OnNetworkEvent(s *NTRIPSession, kind NetworkEventKind)

	// OnSessionClose fires when the session is closed, regardless of whether it
	// recorded any prior authentication, GGA, RTCM, or network events.
	OnSessionClose(s *NTRIPSession)
}

// ---------------------------------------------------------------------------
// Network event kind
// ---------------------------------------------------------------------------

// NetworkEventKind discriminates the kind of TCP/network-quality observation
// reported through SessionEventListener.OnNetworkEvent. The kinds mirror the
// TCP-health observations the SessionTracker already records
// (retransmissions, RTT samples, window changes, and TCP resets).
type NetworkEventKind int

const (
	// NetworkEventUnknown is the zero value, used when no specific kind applies.
	NetworkEventUnknown NetworkEventKind = iota

	// NetworkEventRetransmission indicates a TCP retransmission was observed.
	NetworkEventRetransmission

	// NetworkEventRTTSample indicates a round-trip-time sample was recorded.
	NetworkEventRTTSample

	// NetworkEventWindowChange indicates a TCP window-size change was observed.
	NetworkEventWindowChange

	// NetworkEventTCPReset indicates a TCP RST was observed for the session.
	NetworkEventTCPReset
)

var networkEventKindNames = map[NetworkEventKind]string{
	NetworkEventUnknown:        "unknown",
	NetworkEventRetransmission: "retransmission",
	NetworkEventRTTSample:      "rtt_sample",
	NetworkEventWindowChange:   "window_change",
	NetworkEventTCPReset:       "tcp_reset",
}

// String returns a stable, human-readable name for the network event kind.
func (k NetworkEventKind) String() string {
	if name, ok := networkEventKindNames[k]; ok {
		return name
	}
	return "unknown"
}
