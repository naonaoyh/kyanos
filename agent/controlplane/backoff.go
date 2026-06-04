package controlplane

import (
	"math"
	"time"
)

// Backoff computes exponentially increasing, capped delays between reconnection
// attempts (Requirements 7.1, 7.2). The delay for a 0-based attempt n is
//
//	Delay(n) = min(Base * Factor^n, Max)
//
// which is non-decreasing in n (for Factor >= 1) and never exceeds Max.
type Backoff struct {
	// Base is the delay for attempt 0 (before any exponential growth).
	Base time.Duration
	// Max caps the delay so reconnection attempts continue at a bounded
	// interval (Requirement 7.2).
	Max time.Duration
	// Factor is the geometric growth multiplier per attempt; typically 2.0.
	Factor float64
}

// Delay returns the backoff delay for the given 0-based attempt number,
// computed as min(Base * Factor^attempt, Max).
//
// Negative attempts are treated as attempt 0. The result is always clamped to
// the inclusive range [0, Max] (when Max > 0); overflow from a large attempt or
// factor saturates to Max rather than wrapping.
func (b Backoff) Delay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	// Normalize a non-positive base to zero delay.
	if b.Base <= 0 {
		return 0
	}

	maxDelay := b.effectiveMax()

	// Attempt 0 is just the base (still clamped to the cap).
	if attempt == 0 {
		return clamp(b.Base, maxDelay)
	}

	// A factor <= 0 is meaningless for exponential growth; fall back to a
	// flat base delay rather than producing zero/negative values.
	factor := b.Factor
	if factor <= 0 {
		return clamp(b.Base, maxDelay)
	}

	// Compute Base * Factor^attempt in float64 nanoseconds. Saturate to the
	// cap on overflow or non-finite results.
	growth := math.Pow(factor, float64(attempt))
	delayNs := float64(b.Base.Nanoseconds()) * growth
	if math.IsInf(delayNs, 0) || math.IsNaN(delayNs) || delayNs >= float64(math.MaxInt64) {
		return capOrValue(maxDelay, time.Duration(math.MaxInt64))
	}

	return clamp(time.Duration(delayNs), maxDelay)
}

// effectiveMax returns the effective maximum delay, or 0 when no positive cap
// is set (meaning "uncapped").
func (b Backoff) effectiveMax() time.Duration {
	if b.Max < 0 {
		return 0
	}
	return b.Max
}

// clamp limits d to the inclusive range [0, maxDelay]; a non-positive maxDelay
// means "uncapped" so d is returned unchanged (but never below zero).
func clamp(d, maxDelay time.Duration) time.Duration {
	if d < 0 {
		d = 0
	}
	if maxDelay > 0 && d > maxDelay {
		return maxDelay
	}
	return d
}

// capOrValue returns maxDelay when it is positive, otherwise value. Used so an
// uncapped backoff returns the saturated value on overflow rather than 0.
func capOrValue(maxDelay, value time.Duration) time.Duration {
	if maxDelay > 0 {
		return maxDelay
	}
	return value
}
