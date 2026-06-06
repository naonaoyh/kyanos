// Package ntrip provides NTRIP v1/v2 protocol filtering for Kyanos.
package ntrip

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"kyanos/agent/protocol"
	"kyanos/bpf"
)

// matchWildcard implements simple wildcard matching.
// - "*" matches everything.
// - "foo*" matches any string starting with "foo".
// - "*bar" matches any string ending with "bar".
// - Otherwise, does an exact string equality check.
func matchWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(value, prefix)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(value, suffix)
	}
	return pattern == value
}

// InitExtensions parses mountpoint filters to extract and initialize the Geo-fence
// and all advanced capturing extensions.
// Expected formats in TargetMountPoints:
// - "geo:lat,lon,radius" (e.g. "geo:39.9,116.4,5000")
// - "ext:reconnect:subnet" (e.g. "ext:reconnect:24")
// - "ext:kick:subnet" (e.g. "ext:kick:24")
// - "ext:scan:distance" (e.g. "ext:scan:1000" or "ext:scan:1km")
// - "ext:brute:interval,passwords,fails" (e.g. "ext:brute:60,4,10")
// - "ext:nearby:distance" (e.g. "ext:nearby:1km" or "ext:nearby:1000")
func (f *NTRIPFilter) InitExtensions() {
	var remainingMounts []string
	for _, m := range f.TargetMountPoints {
		if strings.HasPrefix(m, "geo:") {
			parts := strings.Split(m[4:], ",")
			if len(parts) == 3 {
				lat, err1 := strconv.ParseFloat(parts[0], 64)
				lon, err2 := strconv.ParseFloat(parts[1], 64)
				radius, err3 := strconv.ParseFloat(parts[2], 64)
				if err1 == nil && err2 == nil && err3 == nil {
					f.HasGeoFence = true
					f.CenterLat = lat
					f.CenterLon = lon
					f.Radius = radius
					f.RadiusSq = radius * radius

					// Precompute parameters
					const R = 6371000.0 // Earth radius in meters
					f.Ky = (math.Pi * R) / 180.0
					f.Kx = ((math.Pi * R) / 180.0) * math.Cos(lat*math.Pi/180.0)

					deltaLat := radius / f.Ky
					deltaLon := 180.0 // Default if Kx is zero (at poles)
					if f.Kx > 0.000001 {
						deltaLon = radius / f.Kx
					}

					f.LatMin = lat - deltaLat
					f.LatMax = lat + deltaLat
					f.LonMin = lon - deltaLon
					f.LonMax = lon + deltaLon
				}
			}
		} else if strings.HasPrefix(m, "ext:") {
			parts := strings.Split(m[4:], ":")
			if len(parts) >= 1 {
				cmdType := parts[0]
				switch cmdType {
				case "reconnect":
					f.ReconnectEnable = true
					f.ReconnectSubnet = 24 // default mask /24
					if len(parts) >= 2 {
						if sub, err := strconv.Atoi(parts[1]); err == nil {
							f.ReconnectSubnet = sub
						}
					}
				case "kick":
					f.KickEnable = true
					f.KickSubnet = 24 // default mask /24
					if len(parts) >= 2 {
						if sub, err := strconv.Atoi(parts[1]); err == nil {
							f.KickSubnet = sub
						}
					}
				case "scan":
					f.ScanEnable = true
					f.ScanThreshold = 1000.0 // default 1000 meters
					if len(parts) >= 2 {
						val := parts[1]
						isKm := false
						if strings.HasSuffix(val, "km") {
							isKm = true
							val = val[:len(val)-2]
						} else if strings.HasSuffix(val, "m") {
							val = val[:len(val)-1]
						}
						if dist, err := strconv.ParseFloat(val, 64); err == nil {
							if isKm {
								f.ScanThreshold = dist * 1000.0
							} else {
								f.ScanThreshold = dist
							}
						}
					}
				case "brute":
					f.BruteEnable = true
					f.BruteInterval = 1 * time.Minute
					f.BrutePassThreshold = 4
					f.BruteFailThreshold = 10
					if len(parts) >= 2 {
						subParts := strings.Split(parts[1], ",")
						if len(subParts) == 3 {
							sec, err1 := strconv.Atoi(subParts[0])
							pwd, err2 := strconv.Atoi(subParts[1])
							fail, err3 := strconv.Atoi(subParts[2])
							if err1 == nil && err2 == nil && err3 == nil {
								f.BruteInterval = time.Duration(sec) * time.Second
								f.BrutePassThreshold = pwd
								f.BruteFailThreshold = fail
							}
						}
					}
				case "nearby":
					f.NearbyEnable = true
					f.NearbyThreshold = 1000.0 // default 1000 meters
					if len(parts) >= 2 {
						val := parts[1]
						isKm := false
						if strings.HasSuffix(val, "km") {
							isKm = true
							val = val[:len(val)-2]
						} else if strings.HasSuffix(val, "m") {
							val = val[:len(val)-1]
						}
						if dist, err := strconv.ParseFloat(val, 64); err == nil {
							if isKm {
								f.NearbyThreshold = dist * 1000.0
							} else {
								f.NearbyThreshold = dist
							}
						}
					}
				}
			}
		} else {
			remainingMounts = append(remainingMounts, m)
		}
	}
	f.TargetMountPoints = remainingMounts
}

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

	// Geo-fencing cache
	HasGeoFence bool
	CenterLat   float64
	CenterLon   float64
	Radius      float64
	LatMin      float64
	LatMax      float64
	LonMin      float64
	LonMax      float64
	Ky          float64
	Kx          float64
	RadiusSq    float64

	// Capturing extensions
	ReconnectEnable    bool
	ReconnectSubnet    int
	KickEnable         bool
	KickSubnet         int
	ScanEnable         bool
	ScanThreshold      float64
	BruteEnable        bool
	BruteInterval      time.Duration
	BrutePassThreshold int
	BruteFailThreshold int
	NearbyEnable       bool
	NearbyThreshold    float64
}

// Filter evaluates whether a request/response pair passes the filter.
// It handles all NTRIP message types: NTRIPRequest, NTRIPResponse,
// NTRIPRTCMFrame, and NTRIPNMEASentence.
func (f NTRIPFilter) Filter(req protocol.ParsedMessage, resp protocol.ParsedMessage) bool {
	var connKey string
	if req != nil {
		switch r := req.(type) {
		case *NTRIPRequest:
			connKey = r.ConnKey
		case *NTRIPNMEASentence:
			connKey = r.ConnKey
		case *NTRIPRTCMFrame:
			connKey = r.ConnKey
		}
	}
	if connKey == "" && resp != nil {
		switch r := resp.(type) {
		case *NTRIPResponse:
			connKey = r.ConnKey
		case *NTRIPRTCMFrame:
			connKey = r.ConnKey
		}
	}

	// 1. Fast Pass: If this connection is already marked as captured, allow it immediately.
	if connKey != "" && globalTracker.IsCaptured(connKey) {
		if nmea, ok := req.(*NTRIPNMEASentence); ok && nmea.SentenceType == "GGA" && nmea.GGAParsed {
			username := globalTracker.GetUsername(connKey)
			globalTracker.UpdateCapturedPoint(connKey, username, nmea.Latitude, nmea.Longitude)
		}
		return true
	}

	// 2. Request Side (Connection handshake / Login attempt)
	if ntripReq, ok := req.(*NTRIPRequest); ok {
		passed := f.filterRequest(ntripReq)

		// Check reconnect or kick-out conditions
		if !passed && (f.ReconnectEnable || f.KickEnable) {
			isReconnect, isKick := globalTracker.CheckReconnectOrKick(
				ntripReq.Username,
				ntripReq.ClientIP,
				f.ReconnectEnable,
				f.ReconnectSubnet,
				f.KickEnable,
				f.KickSubnet,
			)
			if isReconnect || isKick {
				passed = true
			}
		}

		// Check brute-force login attempts
		if !passed && f.BruteEnable && resp != nil {
			if ntripResp, ok := resp.(*NTRIPResponse); ok {
				success := ntripResp.StatusCode == 200
				isBrute := globalTracker.RecordLoginAttempt(
					ntripReq.Username,
					ntripReq.Password,
					success,
					f.BruteInterval,
					f.BrutePassThreshold,
					f.BruteFailThreshold,
				)
				if isBrute {
					passed = true
				}
			}
		}

		if passed {
			if connKey != "" {
				globalTracker.MarkCapturedWithUser(connKey, ntripReq.Username)
				globalTracker.RegisterCapturedUser(ntripReq.Username, ntripReq.ClientIP)
			}
			return true
		}
		return false
	}

	// 3. NMEA GGA positioning reports
	if nmea, ok := req.(*NTRIPNMEASentence); ok {
		if nmea.SentenceType == "GGA" && nmea.GGAParsed {
			username := globalTracker.GetUsername(connKey)

			hasGeoRules := f.HasGeoFence || f.ScanEnable || f.NearbyEnable
			passed := !hasGeoRules

			// Check standard Geo-fencing
			if f.HasGeoFence {
				inFence := true
				if nmea.Latitude < f.LatMin || nmea.Latitude > f.LatMax || nmea.Longitude < f.LonMin || nmea.Longitude > f.LonMax {
					inFence = false
				} else {
					dy := (nmea.Latitude - f.CenterLat) * f.Ky
					dx := (nmea.Longitude - f.CenterLon) * f.Kx
					if dx*dx+dy*dy > f.RadiusSq {
						inFence = false
					}
				}
				if inFence {
					passed = true
				}
			}

			// Check grid scanning behavior
			if f.ScanEnable && connKey != "" {
				if globalTracker.CheckGridScan(connKey, nmea.Latitude, nmea.Longitude, f.ScanThreshold) {
					passed = true
				}
			}

			// Check nearby user correlation
			if f.NearbyEnable && connKey != "" {
				if globalTracker.CheckNearbyCorrelation(connKey, username, nmea.Latitude, nmea.Longitude, f.NearbyThreshold) {
					passed = true
				}
			}

			if passed {
				if connKey != "" {
					globalTracker.MarkCapturedWithUser(connKey, username)
					globalTracker.UpdateCapturedPoint(connKey, username, nmea.Latitude, nmea.Longitude)
				}
				return true
			} else {
				return false
			}
		}

		if f.GGAOnly && nmea.SentenceType != "GGA" {
			return false
		}
		return !f.ErrorsOnly
	}

	// 4. Response Side (Post-handshake HTTP response)
	if ntripResp, ok := resp.(*NTRIPResponse); ok {
		passed := f.filterResponse(ntripResp)
		if passed {
			if connKey != "" {
				globalTracker.MarkCapturedWithUser(connKey, "")
			}
			return true
		}
		return false
	}

	// 5. RTCM frame filtering
	if rtcmFrame, ok := req.(*NTRIPRTCMFrame); ok {
		return f.filterRTCMFrame(rtcmFrame)
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
	if len(f.TargetUsernames) > 0 {
		matched := false
		for _, u := range f.TargetUsernames {
			if matchWildcard(u, req.Username) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// ErrorsOnly: requests are never errors
	if f.ErrorsOnly {
		return false
	}

	// Extension-only mode: if no standard request-side criteria are set but
	// extension features (brute-force, reconnect, kick) are enabled, return
	// false so the extension checks in Filter() make the capture decision.
	if len(f.TargetVersions) == 0 && len(f.TargetSessionTypes) == 0 &&
		len(f.TargetMountPoints) == 0 && len(f.TargetMethods) == 0 &&
		len(f.TargetUsernames) == 0 {
		if f.BruteEnable || f.ReconnectEnable || f.KickEnable {
			return false
		}
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

	// ErrorsOnly: show only error responses (status >= 400 or ERROR prefix)
	if f.ErrorsOnly {
		isError := resp.StatusCode >= 400 || resp.StatusCode == 0 ||
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

// FilterByProtocol returns true if the given protocol is NTRIP, HTTP, or RTCM.
func (f NTRIPFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolNTRIP || p == bpf.AgentTrafficProtocolTKProtocolHTTP || p == bpf.AgentTrafficProtocolTKProtocolRTCM
}

// FilterByRequest returns true if any request-side filter criteria are set.
func (f NTRIPFilter) FilterByRequest() bool {
	return len(f.TargetVersions) > 0 ||
		len(f.TargetSessionTypes) > 0 ||
		len(f.TargetMountPoints) > 0 ||
		len(f.TargetMethods) > 0 ||
		len(f.TargetUsernames) > 0 ||
		f.ErrorsOnly ||
		f.CRCErrorsOnly ||
		f.GGAOnly ||
		f.HasGeoFence ||
		f.ReconnectEnable ||
		f.KickEnable ||
		f.ScanEnable ||
		f.BruteEnable ||
		f.NearbyEnable
}

// FilterByResponse returns true if any response-side filter criteria are set.
func (f NTRIPFilter) FilterByResponse() bool {
	return len(f.StatusCodes) > 0 || f.ErrorsOnly || f.BruteEnable
}

// Protocol returns the NTRIP protocol identifier.
func (f NTRIPFilter) Protocol() bpf.AgentTrafficProtocolT {
	return bpf.AgentTrafficProtocolTKProtocolNTRIP
}
