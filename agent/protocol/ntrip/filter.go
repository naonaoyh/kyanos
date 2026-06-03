// Package ntrip provides NTRIP v1/v2 protocol filtering for Kyanos.
package ntrip

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"slices"
)

// Compile-time interface check
var _ protocol.ProtocolFilter = &NTRIPFilter{}

// NTRIPFilter filters NTRIP protocol messages based on various criteria.
// All non-empty filter fields are ANDed together: a message must match
// ALL specified criteria to pass the filter.
type NTRIPFilter struct {
	// TargetVersions filters by NTRIP protocol version (NTRIPv1, NTRIPv2).
	TargetVersions []NTRIPVersion

	// TargetSessionTypes filters by session type (DataStream, SourcePush, Sourcetable).
	TargetSessionTypes []NTRIPSessionType

	// TargetMountPoints filters by mountpoint name (exact match).
	TargetMountPoints []string

	// TargetMethods filters by HTTP method (GET, POST, SOURCE).
	TargetMethods []string

	// TargetUsernames filters by username in auth credentials (exact match).
	TargetUsernames []string

	// StatusCodes filters responses by HTTP status code.
	// Use 0 to match ICY responses (which have no standard status code).
	StatusCodes []int

	// ErrorsOnly shows only error responses (status >= 400 or ERROR prefix).
	ErrorsOnly bool

	// CRC errors in the embedded RTCM stream.
	// When true, only RTCM frames with CRC validation failures are shown.
	CRCErrorsOnly bool

	// GGAOnly when true, only NMEA GGA sentences are shown (client position uploads).
	GGAOnly bool
}

// Filter evaluates whether a request/response pair passes the filter.
// It handles all NTRIP message types: NTRIPRequest, NTRIPResponse,
// NTRIPRTCMFrame, and NTRIPNMEASentence.
func (f NTRIPFilter) Filter(req protocol.ParsedMessage, resp protocol.ParsedMessage) bool {
	// Try request-side messages
	if ntripReq, ok := req.(*NTRIPRequest); ok {
		return f.filterRequest(ntripReq)
	}

	// Try NTRIP RTCM frame (post-handshake data)
	if rtcmFrame, ok := req.(*NTRIPRTCMFrame); ok {
		return f.filterRTCMFrame(rtcmFrame)
	}

	// Try NMEA sentence (post-handshake backchannel)
	if nmea, ok := req.(*NTRIPNMEASentence); ok {
		// GGAOnly: only pass GGA sentences
		if f.GGAOnly && nmea.SentenceType != "GGA" {
			return false
		}
		// NMEA sentences pass through unless ErrorsOnly is set
		return !f.ErrorsOnly
	}

	// Try response-side messages
	if ntripResp, ok := resp.(*NTRIPResponse); ok {
		return f.filterResponse(ntripResp)
	}

	if rtcmFrame, ok := resp.(*NTRIPRTCMFrame); ok {
		return f.filterRTCMFrame(rtcmFrame)
	}

	return false
}

// filterRequest applies filter criteria to an NTRIP request.
func (f NTRIPFilter) filterRequest(req *NTRIPRequest) bool {
	// Version filter
	if len(f.TargetVersions) > 0 && !slices.Contains(f.TargetVersions, req.Version) {
		return false
	}

	// Session type filter
	if len(f.TargetSessionTypes) > 0 && !slices.Contains(f.TargetSessionTypes, req.SessionType) {
		return false
	}

	// Mountpoint filter
	if len(f.TargetMountPoints) > 0 && !slices.Contains(f.TargetMountPoints, req.MountPoint) {
		return false
	}

	// Method filter
	if len(f.TargetMethods) > 0 {
		methodUpper := req.Method
		matched := false
		for _, m := range f.TargetMethods {
			if slices.Contains([]string{m}, methodUpper) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Username filter
	if len(f.TargetUsernames) > 0 && !slices.Contains(f.TargetUsernames, req.Username) {
		return false
	}

	// ErrorsOnly: requests are never errors
	if f.ErrorsOnly {
		return false
	}

	return true
}

// filterResponse applies filter criteria to an NTRIP response.
func (f NTRIPFilter) filterResponse(resp *NTRIPResponse) bool {
	// Version filter
	if len(f.TargetVersions) > 0 && !slices.Contains(f.TargetVersions, resp.Version) {
		return false
	}

	// Session type filter
	if len(f.TargetSessionTypes) > 0 && !slices.Contains(f.TargetSessionTypes, resp.SessionType) {
		return false
	}

	// Status code filter
	if len(f.StatusCodes) > 0 && !slices.Contains(f.StatusCodes, resp.StatusCode) {
		return false
	}

	// ErrorsOnly: show only error responses
	if f.ErrorsOnly {
		isError := resp.StatusCode >= 400 || resp.StatusLine == "" ||
			(len(resp.StatusLine) >= 5 && resp.StatusLine[:5] == "ERROR")
		if !isError {
			return false
		}
	}

	return true
}

// filterRTCMFrame applies filter criteria to an NTRIP-wrapped RTCM frame.
func (f NTRIPFilter) filterRTCMFrame(frame *NTRIPRTCMFrame) bool {
	if f.CRCErrorsOnly && frame.Inner.CRCValid {
		return false
	}

	// CRC error filter: show only frames with CRC failures
	if f.ErrorsOnly && frame.Inner.CRCValid {
		return false
	}

	return true
}

// FilterByProtocol returns true if the given protocol is NTRIP.
func (f NTRIPFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolNTRIP
}

// FilterByRequest returns true if any request-side filter criteria are set.
func (f NTRIPFilter) FilterByRequest() bool {
	return len(f.TargetVersions) > 0 ||
		len(f.TargetSessionTypes) > 0 ||
		len(f.TargetMountPoints) > 0 ||
		len(f.TargetMethods) > 0 ||
		len(f.TargetUsernames) > 0 ||
		f.CRCErrorsOnly ||
		f.GGAOnly
}

// FilterByResponse returns true if any response-side filter criteria are set.
func (f NTRIPFilter) FilterByResponse() bool {
	return len(f.StatusCodes) > 0 || f.ErrorsOnly
}

// Protocol returns the NTRIP protocol identifier.
func (f NTRIPFilter) Protocol() bpf.AgentTrafficProtocolT {
	return bpf.AgentTrafficProtocolTKProtocolNTRIP
}
