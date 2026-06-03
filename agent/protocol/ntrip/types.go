// Package ntrip provides NTRIP v1/v2 protocol parsing for Kyanos.
// NTRIP (Networked Transport of RTCM via Internet Protocol) is used for
// streaming GNSS correction data over HTTP.
package ntrip

// NTRIP protocol constants
const (
	// NTRIPVersionHeaderKey is the HTTP header key for NTRIP version negotiation
	NTRIPVersionHeaderKey = "Ntrip-Version"
	// NTRIPVersionHeaderValueV2 is the expected value for NTRIP v2
	NTRIPVersionHeaderValueV2 = "Ntrip/2.0"
	// NTRIPContentType is the MIME type used in NTRIP v2 responses
	NTRIPContentType = "gnss/data"
)

// NTRIPVersion represents the NTRIP protocol version.
type NTRIPVersion int

const (
	NTRIPVersionUnknown NTRIPVersion = iota
	NTRIPv1                          // NTRIP v1: uses ICY/SOURCETABLE non-standard responses
	NTRIPv2                          // NTRIP v2: standard HTTP/1.1 with Ntrip-Version header
)

func (v NTRIPVersion) String() string {
	switch v {
	case NTRIPv1:
		return "NTRIPv1"
	case NTRIPv2:
		return "NTRIPv2"
	default:
		return "Unknown"
	}
}

// NTRIPSessionType represents the type of NTRIP session.
type NTRIPSessionType int

const (
	SessionTypeUnknown     NTRIPSessionType = iota
	SessionTypeDataStream                   // Client requesting correction data from a mountpoint
	SessionTypeSourcePush                   // Source pushing data to caster (SOURCE method)
	SessionTypeSourcetable                  // Client requesting the sourcetable (GET /)
)

func (t NTRIPSessionType) String() string {
	switch t {
	case SessionTypeDataStream:
		return "DataStream"
	case SessionTypeSourcePush:
		return "SourcePush"
	case SessionTypeSourcetable:
		return "Sourcetable"
	default:
		return "Unknown"
	}
}

// NTRIP v1 response status line prefixes
const (
	NTRIPv1ICYPrefix         = "ICY "
	NTRIPv1SourcetablePrefix = "SOURCETABLE "
	NTRIPv1ErrorPrefix       = "ERROR "
)

// NTRIP request methods
const (
	MethodSource = "SOURCE" // NTRIP v1 source push method
	MethodGet    = "GET"
	MethodPost   = "POST"
)
