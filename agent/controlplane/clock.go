// Package controlplane implements the Phase 7 gRPC control-plane subsystem for
// the Kyanos Agent. Everything in this package is additive and gated on
// gRPC_Mode; when the --grpc-server flag is absent the package is never
// constructed, preserving Standalone_CLI_Mode behavior.
//
// This file provides the Clock abstraction used to make duration timers,
// reconnect backoff, and heartbeat timing deterministic under test. Production
// code uses the real clock; tests inject a fake clock they can advance
// manually.
package controlplane

import (
	"sort"
	"sync"
	"time"
)

// Timer represents a scheduled one-shot callback created via Clock.AfterFunc.
// It mirrors the relevant surface of *time.Timer so the real and fake clocks
// can be used interchangeably.
type Timer interface {
	// Stop prevents the timer from firing. It returns true if the call
	// stops the timer, or false if the timer has already fired or been
	// stopped.
	Stop() bool
}

// Clock abstracts the passage of time so that components depending on timers
// (TaskManager durations, Client backoff/heartbeat) can be tested
// deterministically by injecting a fake.
type Clock interface {
	// Now returns the current time according to the clock.
	Now() time.Time
	// AfterFunc schedules f to run in its own goroutine after at least d has
	// elapsed according to the clock, returning a Timer that can cancel it.
	AfterFunc(d time.Duration, f func()) Timer
}

// realClock is the production Clock backed by the standard library.
type realClock struct{}

// NewRealClock returns a Clock backed by the standard time package.
func NewRealClock() Clock { return realClock{} }

// Now returns the current wall-clock time.
func (realClock) Now() time.Time { return time.Now() }

// AfterFunc schedules f using time.AfterFunc and wraps the returned timer.
func (realClock) AfterFunc(d time.Duration, f func()) Timer {
	return &realTimer{t: time.AfterFunc(d, f)}
}

// realTimer adapts *time.Timer to the Timer interface.
type realTimer struct{ t *time.Timer }

// Stop cancels the underlying time.Timer.
func (r *realTimer) Stop() bool { return r.t.Stop() }

// FakeClock is an injectable, deterministic Clock for tests. Time only advances
// when Advance or SetTime is called; any AfterFunc callbacks whose deadline is
// reached are invoked synchronously (in deadline order) from within Advance.
//
// FakeClock is safe for concurrent use.
type FakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

// NewFakeClock returns a FakeClock whose current time is start.
func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{now: start}
}

// Now returns the fake clock's current time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// AfterFunc registers f to fire once the clock reaches now+d. If d is zero or
// negative the callback fires immediately and the returned Timer is already
// stopped.
func (c *FakeClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	if d <= 0 {
		c.mu.Unlock()
		f()
		return &fakeTimer{fired: true}
	}
	t := &fakeTimer{
		deadline: c.now.Add(d),
		f:        f,
		clock:    c,
	}
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	return t
}

// Advance moves the clock forward by d and fires every timer whose deadline is
// at or before the new time, in deadline order. Callbacks run synchronously so
// tests observe their effects immediately after Advance returns.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.fireDueLocked()
	c.mu.Unlock()
}

// SetTime moves the clock to t (only forward; earlier times are ignored) and
// fires any due timers.
func (c *FakeClock) SetTime(t time.Time) {
	c.mu.Lock()
	if t.After(c.now) {
		c.now = t
	}
	c.fireDueLocked()
	c.mu.Unlock()
}

// fireDueLocked invokes and removes all timers due at the current time. The
// caller must hold c.mu; callbacks run with the lock released so they may
// safely re-enter the clock (e.g. reschedule another timer).
func (c *FakeClock) fireDueLocked() {
	for {
		var due []*fakeTimer
		remaining := c.timers[:0]
		for _, t := range c.timers {
			if !t.fired && !t.deadline.After(c.now) {
				due = append(due, t)
			} else {
				remaining = append(remaining, t)
			}
		}
		c.timers = remaining
		if len(due) == 0 {
			return
		}
		// Fire in deadline order for determinism.
		sort.SliceStable(due, func(i, j int) bool {
			return due[i].deadline.Before(due[j].deadline)
		})
		for _, t := range due {
			t.fired = true
		}
		c.mu.Unlock()
		for _, t := range due {
			if t.f != nil {
				t.f()
			}
		}
		c.mu.Lock()
		// Loop again in case a callback scheduled a timer already due.
	}
}

// fakeTimer is a Timer produced by FakeClock.
type fakeTimer struct {
	deadline time.Time
	f        func()
	clock    *FakeClock
	fired    bool
}

// Stop prevents the timer from firing if it has not already fired.
func (t *fakeTimer) Stop() bool {
	if t.clock == nil {
		return false
	}
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.fired {
		return false
	}
	t.fired = true
	for i, ct := range t.clock.timers {
		if ct == t {
			t.clock.timers = append(t.clock.timers[:i], t.clock.timers[i+1:]...)
			break
		}
	}
	return true
}
