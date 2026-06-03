package rtcm

import (
	"testing"
	"time"
)

func TestSetLeapSeconds(t *testing.T) {
	orig := LeapSeconds()
	defer SetLeapSeconds(orig) // restore global after test

	if orig != LeapSecondsGPSUTC {
		t.Fatalf("default LeapSeconds() = %d, want %d", orig, LeapSecondsGPSUTC)
	}

	SetLeapSeconds(19)
	if LeapSeconds() != 19 {
		t.Errorf("after SetLeapSeconds(19), LeapSeconds() = %d, want 19", LeapSeconds())
	}

	// Negative values are ignored.
	SetLeapSeconds(-5)
	if LeapSeconds() != 19 {
		t.Errorf("negative override should be ignored, LeapSeconds() = %d, want 19", LeapSeconds())
	}
}

// TestLeapSecondsAffectsEpochConversion verifies the configurable offset is
// actually applied in EpochToUTC: bumping the leap second count by 1 shifts the
// resulting UTC by exactly 1 second.
func TestLeapSecondsAffectsEpochConversion(t *testing.T) {
	orig := LeapSeconds()
	defer SetLeapSeconds(orig)

	capture := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	// An MSM message epoch (ms within GPS week).
	const msgType = 1077
	const epochMs = 100000

	SetLeapSeconds(18)
	at18 := EpochToUTC(epochMs, msgType, capture)

	SetLeapSeconds(19)
	at19 := EpochToUTC(epochMs, msgType, capture)

	diff := at18.Sub(at19)
	if diff != time.Second {
		t.Errorf("increasing leap seconds by 1 should move UTC back by 1s, got %v", diff)
	}
}
