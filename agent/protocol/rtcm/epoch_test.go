package rtcm

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Bit extraction helpers
// ---------------------------------------------------------------------------

func TestExtractBits24(t *testing.T) {
	// 3 bytes: 0x01 0x02 0x03 = 0000_0001 0000_0010 0000_0011
	// bits 0-23 should give 0x010203 = 66051
	data := []byte{0x01, 0x02, 0x03, 0x00}
	got := extractBits24(data, 0)
	if got != 0x010203 {
		t.Errorf("extractBits24 at offset 0 = 0x%06X, want 0x010203", got)
	}
}

func TestExtractBits30(t *testing.T) {
	// Manually construct 30 bits: value = 123456789
	// 123456789 in binary = 0000_0111 0101_1011 1100_1101 0001_0101 (30 bits)
	val := uint32(123456789)
	// Pack into 4 bytes at bit offset 0 (top 30 bits of 32 bits)
	b0 := byte(val >> 22)
	b1 := byte(val >> 14)
	b2 := byte(val >> 6)
	b3 := byte((val & 0x3F) << 2) // bottom 6 bits shifted to top of byte

	data := []byte{b0, b1, b2, b3}
	got := extractBits30(data, 0)
	if got != val {
		t.Errorf("extractBits30 = %d, want %d", got, val)
	}
}

// ---------------------------------------------------------------------------
// ExtractEpochMs
// ---------------------------------------------------------------------------

func TestExtractEpochMsMSM(t *testing.T) {
	// Build a fake MSM4 (1074) frame with known epoch
	// Payload structure:
	//   Bits 0-11:  Message type = 1074 = 0x432
	//   Bits 12-23: Station ID = 0
	//   Bits 24-53: Epoch time = 302400000 ms (mid-GPS-week = Wed 12:00:00 GPS)

	epochValue := uint32(302400000) // ms within GPS week

	// Build payload bytes (need at least 7 bytes for 54 bits)
	payload := make([]byte, 8)
	// Message type (12 bits): 1074 = 0x432
	payload[0] = 0x04 // high nibble of 0x432 >> 4
	payload[1] = 0x32 // low byte (0x32 << 4 | station_id_high)
	// Station ID (12 bits) = 0: already zero in payload[1] low nibble + payload[2]
	payload[2] = 0x00

	// Epoch (30 bits starting at bit 24)
	// Bit 24 = byte 3, bit 0
	payload[3] = byte(epochValue >> 22)
	payload[4] = byte(epochValue >> 14)
	payload[5] = byte(epochValue >> 6)
	payload[6] = byte((epochValue & 0x3F) << 2)

	// Build full frame with header
	frame := &RTCMFrame{
		MessageType: 1074,
		RawBytes:    append([]byte{0xD3, 0x00, byte(len(payload))}, payload...),
		PayloadLen:  len(payload),
		TotalLen:    3 + len(payload) + 3,
	}

	epochMs, ok := ExtractEpochMs(frame)
	if !ok {
		t.Fatal("ExtractEpochMs returned ok=false for MSM frame")
	}
	if epochMs != int64(epochValue) {
		t.Errorf("ExtractEpochMs = %d, want %d", epochMs, epochValue)
	}
}

func TestExtractEpochMsGPSLegacy(t *testing.T) {
	// Build a fake GPS legacy (1004) frame with known epoch
	epochValue := uint32(1800000) // 1800 seconds = 30 minutes, within GPS hour

	payload := make([]byte, 7)
	// Message type (12 bits): 1004 = 0x3EC
	// byte 0: high 8 bits = 0x03
	// byte 1 high nibble: low 4 bits of msg type = 0xE, shifted left 4 = 0xE0
	payload[0] = 0x03
	payload[1] = 0xE0 // low nibble = station ID (0)

	// Epoch (24 bits starting at bit 24)
	payload[3] = byte(epochValue >> 16)
	payload[4] = byte(epochValue >> 8)
	payload[5] = byte(epochValue)

	frame := &RTCMFrame{
		MessageType: 1004,
		RawBytes:    append([]byte{0xD3, 0x00, byte(len(payload))}, payload...),
		PayloadLen:  len(payload),
		TotalLen:    3 + len(payload) + 3,
	}

	epochMs, ok := ExtractEpochMs(frame)
	if !ok {
		t.Fatal("ExtractEpochMs returned ok=false for GPS legacy frame")
	}
	if epochMs != int64(epochValue) {
		t.Errorf("ExtractEpochMs = %d, want %d", epochMs, epochValue)
	}
}

func TestExtractEpochMsUnsupported(t *testing.T) {
	// 1005 (Station ARP) has no epoch field
	frame := &RTCMFrame{
		MessageType: 1005,
		RawBytes:    make([]byte, 20),
		PayloadLen:  17,
		TotalLen:    23,
	}
	frame.RawBytes[0] = 0xD3

	_, ok := ExtractEpochMs(frame)
	if ok {
		t.Error("ExtractEpochMs should return ok=false for non-observation message")
	}
}

func TestExtractEpochMsShortFrame(t *testing.T) {
	frame := &RTCMFrame{
		MessageType: 1074,
		RawBytes:    []byte{0xD3, 0x00, 0x02}, // only header, no payload
		PayloadLen:  0,
	}

	_, ok := ExtractEpochMs(frame)
	if ok {
		t.Error("ExtractEpochMs should return ok=false for short frame")
	}
}

// ---------------------------------------------------------------------------
// GPSWeek and EpochToUTC
// ---------------------------------------------------------------------------

func TestGPSWeek(t *testing.T) {
	// GPS epoch itself → week 0
	w := GPSWeek(time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC))
	if w != 0 {
		t.Errorf("GPSWeek(epoch) = %d, want 0", w)
	}

	// 2026-06-03 → approximately week 2420 (verify range)
	w2 := GPSWeek(time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC))
	if w2 < 2400 || w2 > 2500 {
		t.Errorf("GPSWeek(2026-06-03) = %d, expected ~2420", w2)
	}
}

func TestEpochToUTCMSM(t *testing.T) {
	// A capture time and corresponding MSM epoch
	captureTime := time.Date(2026, 6, 3, 14, 0, 0, 0, time.UTC)
	week := GPSWeek(captureTime)

	// Epoch = start of this GPS week (ms = 0) → should be ~ gpsEpoch + week*604800s - 18s
	epochMs := int64(0)
	result := EpochToUTC(epochMs, 1074, captureTime)

	expected := gpsEpoch.Add(time.Duration(week) * time.Duration(GPSWeekMs) * time.Millisecond).
		Add(-LeapSecondsGPSUTC * time.Second)

	diff := result.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("EpochToUTC(0, MSM) = %v, want ~%v (diff=%v)", result, expected, diff)
	}
}

func TestEpochToUTCGPSLegacy(t *testing.T) {
	captureTime := time.Date(2026, 6, 3, 14, 30, 0, 0, time.UTC)

	// Epoch = 1800000 ms (30 minutes into the GPS hour)
	epochMs := int64(1800000)
	result := EpochToUTC(epochMs, 1004, captureTime)

	// The result should be close to the capture time (within the same hour)
	diff := captureTime.Sub(result)
	if diff < -time.Hour || diff > time.Hour {
		t.Errorf("EpochToUTC(GPS legacy) = %v, capture = %v, diff = %v", result, captureTime, diff)
	}
}

func TestEpochToUTCUnsupported(t *testing.T) {
	result := EpochToUTC(1000, 1005, time.Now())
	if !result.IsZero() {
		t.Errorf("EpochToUTC(unsupported) should return zero time, got %v", result)
	}
}
