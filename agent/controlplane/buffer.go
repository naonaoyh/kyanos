// Package controlplane implements the Agent-side gRPC control-plane subsystem
// (Phase 7). Every capability in this package is additive and gated on
// gRPC_Mode; nothing here runs in Standalone_CLI_Mode.
//
// This file implements the Local_Event_Buffer: a bounded ring buffer that holds
// SessionEvents produced while the gRPC_Stream is disconnected, so they can be
// replayed in order once the stream is re-established.
package controlplane

import "sync"

// EventBuffer is a bounded, FIFO ring buffer (the Local_Event_Buffer).
//
// It is generic over the stored element type T so that the pure data-structure
// logic compiles and is testable before the generated protobuf bindings exist.
// Once proto/agentpb is generated it is instantiated as
// EventBuffer[*agentpb.SessionEvent].
//
// Behavior (Requirements 7.3, 7.4, 7.5):
//   - Push appends the newest event. When the buffer is at capacity it evicts
//     the oldest event to admit the new one and increments the discard counter.
//   - DrainInOrder returns the retained events in push (FIFO) order and empties
//     the buffer, ready for replay on reconnect.
//   - Discarded reports the cumulative number of events dropped due to overflow.
//   - Len reports the number of events currently buffered.
//
// All methods are safe for concurrent use; the buffer is the single
// synchronized hand-off point between the EventReporter goroutine and the
// Client send loop.
type EventBuffer[T any] struct {
	mu        sync.Mutex
	ring      []T
	head      int // index of the oldest buffered element
	size      int // number of elements currently buffered
	capacity  int
	discarded uint64
}

// NewEventBuffer creates a buffer that retains at most capacity events. A
// capacity less than or equal to zero yields a buffer that retains nothing;
// every pushed event is immediately counted as discarded.
func NewEventBuffer[T any](capacity int) *EventBuffer[T] {
	if capacity < 0 {
		capacity = 0
	}
	return &EventBuffer[T]{
		ring:     make([]T, capacity),
		capacity: capacity,
	}
}

// Push adds ev as the newest event. If the buffer is already at capacity, the
// oldest event is evicted to make room and the discard counter is incremented
// (Requirement 7.5). FIFO order among retained events is preserved.
func (b *EventBuffer[T]) Push(ev T) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.capacity == 0 {
		// Nothing can be retained; the event is dropped.
		b.discarded++
		return
	}

	if b.size == b.capacity {
		// Evict the oldest element to admit the new one.
		b.head = (b.head + 1) % b.capacity
		b.size--
		b.discarded++
	}

	tail := (b.head + b.size) % b.capacity
	b.ring[tail] = ev
	b.size++
}

// DrainInOrder returns all currently buffered events in push (FIFO) order and
// empties the buffer (Requirement 7.4). The cumulative discard counter is left
// unchanged so it can continue to be reported after a replay.
func (b *EventBuffer[T]) DrainInOrder() []T {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]T, b.size)
	for i := 0; i < b.size; i++ {
		out[i] = b.ring[(b.head+i)%b.capacity]
	}

	// Clear retained slots so evicted references can be garbage collected.
	var zero T
	for i := range b.ring {
		b.ring[i] = zero
	}
	b.head = 0
	b.size = 0

	return out
}

// Discarded reports the cumulative count of events dropped due to overflow,
// whether the stream was connected or disconnected (Requirement 7.5).
func (b *EventBuffer[T]) Discarded() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.discarded
}

// Len reports the number of events currently buffered.
func (b *EventBuffer[T]) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.size
}
