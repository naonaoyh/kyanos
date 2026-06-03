package rtcm

import (
	"time"
)

// ---------------------------------------------------------------------------
// RTCM epoch time extraction from raw frame bytes
// ---------------------------------------------------------------------------
//
// RTCM 3.x observation messages embed an epoch timestamp that indicates when
// the GNSS measurements were taken at the reference station.  By comparing
// this epoch with the eBPF capture timestamp we can measure the end-to-end
// latency introduced by the network and processing pipeline.
//
// Epoch encoding differs by message family:
//
//   - MSM (1071-1137):  DF004 is a 30-bit field (bits 24-53 of payload),
//     representing milliseconds within the current GPS week (mod 604 800 000).
//
//   - GPS legacy (1001-1004): DF004 is a 24-bit field (bits 24-47 of payload),
//     representing milliseconds within the current GPS hour (mod 3 600 000).
//
//   - GLONASS legacy (1009-1012): uses GLONASS epoch time (DF004, 27 bits),
//     representing milliseconds within the current GLONASS day (mod 86 400 000).
//     GLONASS time = UTC + 3 hours (Moscow time offset is not applied here).

// GPS epoch: January 6, 1980 00:00:00 UTC.
var gpsEpoch = time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)

// GPSWeekMs is the number of milliseconds in one GPS week.
const GPSWeekMs int64 = 604_800_000

// GPSHourMs is the number of milliseconds in one GPS hour (legacy messages).
const GPSHourMs int64 = 3_600_000

// GLONASSDayMs is the number of milliseconds in one GLONASS day.
const GLONASSDayMs int64 = 86_400_000

// LeapSecondsGPSUTC is the default GPS-UTC leap second offset.
// As of 2024, GPS time = UTC time + 18 seconds.
// This is the compile-time default; use SetLeapSeconds to override at runtime
// when a new leap second is announced (avoids needing a rebuild).
const LeapSecondsGPSUTC = 18

// leapSeconds holds the active GPS-UTC leap second offset. It defaults to
// LeapSecondsGPSUTC and can be changed via SetLeapSeconds. All epoch->UTC
// conversions read this value, so updating it takes effect immediately.
var leapSeconds = LeapSecondsGPSUTC

// SetLeapSeconds overrides the active GPS-UTC leap second offset (in seconds).
// Negative values are ignored. Intended to be called once at startup from a
// CLI/config option when the built-in default is stale.
func SetLeapSeconds(seconds int) {
	if seconds < 0 {
		return
	}
	leapSeconds = seconds
}

// LeapSeconds returns the active GPS-UTC leap second offset (in seconds).
func LeapSeconds() int {
	return leapSeconds
}

// leapSecondsDuration returns the active leap-second offset as a time.Duration.
func leapSecondsDuration() time.Duration {
	return time.Duration(leapSeconds) * time.Second
}

// ExtractEpochMs extracts the epoch time from an RTCM frame's raw bytes.
//
// Returns:
//   - epochMs: the epoch value in milliseconds (modular, see constants above)
//   - ok: true if the epoch was successfully extracted
//
// The returned value is modular (wraps around GPS week / hour / day boundaries).
// Use EpochToUTC to convert to an absolute time with the help of the capture
// timestamp.
func ExtractEpochMs(frame *RTCMFrame) (epochMs int64, ok bool) {
	raw := frame.RawBytes
	if len(raw) < RTCMHeaderLen+6 { // need at least 6 bytes of payload
		return 0, false
	}

	payload := raw[RTCMHeaderLen:] // skip 3-byte header

	msgType := frame.MessageType

	switch {
	case IsMSMMessage(msgType):
		// MSM: DF004 at bits 24-53 (30 bits)
		if len(payload) < 7 { // need 54 bits = 7 bytes
			return 0, false
		}
		ms := extractBits30(payload, 24)
		return int64(ms), true

	case msgType >= Msg1001 && msgType <= Msg1004:
		// GPS legacy: DF004 at bits 24-47 (24 bits)
		if len(payload) < 6 { // need 48 bits = 6 bytes
			return 0, false
		}
		ms := extractBits24(payload, 24)
		return int64(ms), true

	case msgType >= Msg1009 && msgType <= Msg1012:
		// GLONASS legacy: DF004 at bits 24-50 (27 bits)
		if len(payload) < 7 { // need 51 bits ≈ 7 bytes
			return 0, false
		}
		ms := extractBits27(payload, 24)
		return int64(ms), true

	default:
		return 0, false
	}
}

// GPSWeek computes the GPS week number for the given UTC time.
func GPSWeek(t time.Time) int {
	utc := t.UTC()
	d := utc.Sub(gpsEpoch)
	return int(d / (time.Duration(GPSWeekMs) * time.Millisecond))
}

// EpochToUTC converts a modular RTCM epoch (milliseconds) to an absolute
// UTC time, using the capture timestamp to determine the correct GPS week
// (or hour / day) boundary.
//
// For MSM messages, the epoch is milliseconds within the GPS week.
// For GPS legacy messages, the epoch is milliseconds within the GPS hour.
// For GLONASS legacy messages, the epoch is milliseconds within the GLONASS day.
//
// The conversion applies: GPS time = UTC + LeapSecondsGPSUTC.
func EpochToUTC(epochMs int64, msgType int, captureTime time.Time) time.Time {
	captureUTC := captureTime.UTC()

	switch {
	case IsMSMMessage(msgType):
		return msmEpochToUTC(epochMs, captureUTC)
	case msgType >= Msg1001 && msgType <= Msg1004:
		return gpsLegacyEpochToUTC(epochMs, captureUTC)
	case msgType >= Msg1009 && msgType <= Msg1012:
		return glonassLegacyEpochToUTC(epochMs, captureUTC)
	default:
		return time.Time{}
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// msmEpochToUTC converts MSM epoch (ms in GPS week) to UTC.
func msmEpochToUTC(epochMs int64, captureUTC time.Time) time.Time {
	week := GPSWeek(captureUTC)

	// GPS time for this epoch = gpsEpoch + week*604800s + epochMs
	gpsTime := gpsEpoch.Add(time.Duration(week)*time.Duration(GPSWeekMs)*time.Millisecond +
		time.Duration(epochMs)*time.Millisecond)

	// Convert GPS time → UTC by subtracting leap seconds
	return gpsTime.Add(-leapSecondsDuration())
}

// gpsLegacyEpochToUTC converts GPS legacy epoch (ms in GPS hour) to UTC.
func gpsLegacyEpochToUTC(epochMs int64, captureUTC time.Time) time.Time {
	// Determine the GPS hour of the capture time
	captureGPS := captureUTC.Add(leapSecondsDuration())
	d := captureGPS.Sub(gpsEpoch)
	gpsHourStart := (d / (time.Duration(GPSHourMs) * time.Millisecond)) *
		time.Duration(GPSHourMs) * time.Millisecond

	gpsTime := gpsEpoch.Add(gpsHourStart + time.Duration(epochMs)*time.Millisecond)

	// Check if the epoch is "ahead" of the capture (unlikely but handle wrap)
	if gpsTime.After(captureUTC.Add(leapSecondsDuration()).Add(time.Hour)) {
		// Probably in the previous hour
		gpsTime = gpsTime.Add(-time.Duration(GPSHourMs) * time.Millisecond)
	}

	return gpsTime.Add(-leapSecondsDuration())
}

// glonassLegacyEpochToUTC converts GLONASS legacy epoch (ms in GLONASS day) to UTC.
func glonassLegacyEpochToUTC(epochMs int64, captureUTC time.Time) time.Time {
	// GLONASS time = UTC + 3 hours (no leap second correction between GLONASS and UTC)
	glonassNow := captureUTC.Add(3 * time.Hour)

	// Start of GLONASS day
	dayStart := time.Date(glonassNow.Year(), glonassNow.Month(), glonassNow.Day(),
		0, 0, 0, 0, time.UTC)

	// GLONASS time for this epoch
	glonassTime := dayStart.Add(time.Duration(epochMs) * time.Millisecond)

	// Handle day wrap-around
	if glonassTime.After(glonassNow.Add(24 * time.Hour)) {
		glonassTime = glonassTime.Add(-time.Duration(GLONASSDayMs) * time.Millisecond)
	}

	// Convert GLONASS time → UTC by subtracting 3 hours
	return glonassTime.Add(-3 * time.Hour)
}

// extractBits30 extracts a 30-bit unsigned value starting at bit offset from data.
func extractBits30(data []byte, bitOffset int) uint32 {
	byteIdx := bitOffset / 8
	bitIdx := bitOffset % 8

	// Read 5 bytes (40 bits) and shift to get 30 bits
	var val uint64
	for i := 0; i < 5 && byteIdx+i < len(data); i++ {
		val = (val << 8) | uint64(data[byteIdx+i])
	}
	// Total bits read: min(5, len-byteIdx) * 8
	bitsRead := 5 * 8
	if byteIdx+5 > len(data) {
		bitsRead = (len(data) - byteIdx) * 8
	}
	shift := bitsRead - bitIdx - 30
	if shift < 0 {
		return 0
	}
	return uint32((val >> uint(shift)) & 0x3FFFFFFF) // 30-bit mask
}

// extractBits27 extracts a 27-bit unsigned value starting at bit offset from data.
func extractBits27(data []byte, bitOffset int) uint32 {
	byteIdx := bitOffset / 8
	bitIdx := bitOffset % 8

	var val uint64
	for i := 0; i < 5 && byteIdx+i < len(data); i++ {
		val = (val << 8) | uint64(data[byteIdx+i])
	}
	bitsRead := 5 * 8
	if byteIdx+5 > len(data) {
		bitsRead = (len(data) - byteIdx) * 8
	}
	shift := bitsRead - bitIdx - 27
	if shift < 0 {
		return 0
	}
	return uint32((val >> uint(shift)) & 0x7FFFFFF) // 27-bit mask
}

// extractBits24 extracts a 24-bit unsigned value starting at bit offset from data.
func extractBits24(data []byte, bitOffset int) uint32 {
	byteIdx := bitOffset / 8
	bitIdx := bitOffset % 8

	var val uint64
	for i := 0; i < 4 && byteIdx+i < len(data); i++ {
		val = (val << 8) | uint64(data[byteIdx+i])
	}
	bitsRead := 4 * 8
	if byteIdx+4 > len(data) {
		bitsRead = (len(data) - byteIdx) * 8
	}
	shift := bitsRead - bitIdx - 24
	if shift < 0 {
		return 0
	}
	return uint32((val >> uint(shift)) & 0xFFFFFF) // 24-bit mask
}
