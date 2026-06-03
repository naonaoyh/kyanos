package rtcm

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"slices"
)

// Compile-time interface check
var _ protocol.ProtocolFilter = RTCMFilter{}

// RTCMFilter provides filtering capabilities for RTCM frames.
// It supports filtering by message type, constellation, MSM class, and CRC validity.
type RTCMFilter struct {
	TargetMessageTypes   []int           // Filter by specific RTCM message types (empty = all)
	TargetConstellations []Constellation // Filter by GNSS constellation (empty = all)
	CRCErrorsOnly        bool            // Only show frames with CRC validation errors
}

// Filter determines whether a request/response pair should be included.
// For RTCM, only the request (frame) is relevant since it's unidirectional.
func (f RTCMFilter) Filter(req protocol.ParsedMessage, resp protocol.ParsedMessage) bool {
	frame, ok := req.(*RTCMFrame)
	if !ok {
		return false
	}

	// Filter by CRC validity
	if f.CRCErrorsOnly && frame.CRCValid {
		return false
	}

	// Filter by message type
	if len(f.TargetMessageTypes) > 0 {
		if !slices.Contains(f.TargetMessageTypes, frame.MessageType) {
			return false
		}
	}

	// Filter by constellation
	if len(f.TargetConstellations) > 0 {
		if !slices.Contains(f.TargetConstellations, frame.Constellation) {
			return false
		}
	}

	return true
}

// FilterByProtocol returns true if the protocol is RTCM.
func (f RTCMFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolRTCM
}

// FilterByRequest returns true if there are request-side filter conditions.
func (f RTCMFilter) FilterByRequest() bool {
	return len(f.TargetMessageTypes) > 0 ||
		len(f.TargetConstellations) > 0 ||
		f.CRCErrorsOnly
}

// FilterByResponse returns false since RTCM is unidirectional.
func (f RTCMFilter) FilterByResponse() bool {
	return false
}

// Protocol returns the RTCM protocol type.
func (f RTCMFilter) Protocol() bpf.AgentTrafficProtocolT {
	return bpf.AgentTrafficProtocolTKProtocolRTCM
}
