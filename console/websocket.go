// Package console — websocket.go
//
// WSHub is a WebSocket pub/sub hub that broadcasts session events and
// task status updates to connected frontend clients. Each subscription
// is scoped to a topic (session ID or task ID) so clients only receive
// events they are interested in.
//
// This file intentionally does not import gorilla/websocket. It defines
// the hub logic and a WebSocket-agnostic Subscriber interface. The actual
// HTTP upgrade handler (using net/http or gorilla) lives in api.go.
package console

import (
	"encoding/json"
	"sync"
	"time"
)

// WSMessage is the envelope for a WebSocket message pushed to clients.
type WSMessage struct {
	Type      string    `json:"type"`  // "session_event", "task_status", "session_update"
	Topic     string    `json:"topic"` // session ID or task ID
	Data      any       `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// Subscriber is a single WebSocket subscriber. Implementations wrap a
// concrete WebSocket connection (e.g., gorilla/websocket.Conn) and
// provide a Send method that writes JSON to the wire.
type Subscriber interface {
	// Send writes a JSON message to the WebSocket client.
	// It must be safe for concurrent use.
	Send(msg *WSMessage) error

	// Topic returns the subscription topic.
	Topic() string

	// Close closes the underlying connection.
	Close()
}

// WSHub manages topic-based subscriptions and broadcasts messages to
// all subscribers of a given topic.
type WSHub struct {
	mu          sync.RWMutex
	subscribers map[string]map[Subscriber]struct{} // topic → set of subscribers
}

// NewWSHub creates an empty WebSocket hub.
func NewWSHub() *WSHub {
	return &WSHub{
		subscribers: make(map[string]map[Subscriber]struct{}),
	}
}

// Subscribe adds a subscriber to a topic. The subscriber will receive
// all future Broadcast calls for that topic until Unsubscribe is called.
func (h *WSHub) Subscribe(topic string, sub Subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subscribers[topic] == nil {
		h.subscribers[topic] = make(map[Subscriber]struct{})
	}
	h.subscribers[topic][sub] = struct{}{}
}

// Unsubscribe removes a subscriber from a topic and closes its connection.
func (h *WSHub) Unsubscribe(topic string, sub Subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	subs, ok := h.subscribers[topic]
	if !ok {
		return
	}
	delete(subs, sub)
	if len(subs) == 0 {
		delete(h.subscribers, topic)
	}
	sub.Close()
}

// UnsubscribeAll removes a subscriber from all topics.
func (h *WSHub) UnsubscribeAll(sub Subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for topic, subs := range h.subscribers {
		delete(subs, sub)
		if len(subs) == 0 {
			delete(h.subscribers, topic)
		}
	}
	sub.Close()
}

// Broadcast sends a message to all subscribers of the given topic.
// Subscribers that fail to send are silently removed (their connection
// is assumed broken).
func (h *WSHub) Broadcast(topic string, msg *WSMessage) {
	h.mu.RLock()
	subs, ok := h.subscribers[topic]
	if !ok || len(subs) == 0 {
		h.mu.RUnlock()
		return
	}
	// Snapshot subscriber set to avoid holding the lock during I/O.
	snapshot := make([]Subscriber, 0, len(subs))
	for s := range subs {
		snapshot = append(snapshot, s)
	}
	h.mu.RUnlock()

	var failed []Subscriber
	for _, s := range snapshot {
		if err := s.Send(msg); err != nil {
			failed = append(failed, s)
		}
	}

	// Clean up failed subscribers.
	if len(failed) > 0 {
		h.mu.Lock()
		for _, s := range failed {
			delete(h.subscribers[topic], s)
			s.Close()
		}
		if len(h.subscribers[topic]) == 0 {
			delete(h.subscribers, topic)
		}
		h.mu.Unlock()
	}
}

// BroadcastSessionEvent pushes a session event to all subscribers of
// that session's topic.
func (h *WSHub) BroadcastSessionEvent(sessionID string, evt *SessionEventRecord) {
	h.Broadcast(sessionID, &WSMessage{
		Type:      "session_event",
		Topic:     sessionID,
		Data:      evt,
		Timestamp: time.Now(),
	})
}

// BroadcastSessionUpdate pushes a session summary update (e.g., on close).
func (h *WSHub) BroadcastSessionUpdate(sessionID string, rec *SessionRecord) {
	h.Broadcast(sessionID, &WSMessage{
		Type:      "session_update",
		Topic:     sessionID,
		Data:      rec,
		Timestamp: time.Now(),
	})
}

// BroadcastTaskStatus pushes a task status change to all subscribers.
func (h *WSHub) BroadcastTaskStatus(taskID string, t *Task) {
	h.Broadcast("task:"+taskID, &WSMessage{
		Type:      "task_status",
		Topic:     taskID,
		Data:      t,
		Timestamp: time.Now(),
	})
}

// SubscriberCount returns the number of subscribers for a topic.
func (h *WSHub) SubscriberCount(topic string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subscribers[topic])
}

// TotalSubscriberCount returns the total number of subscriptions across
// all topics.
func (h *WSHub) TotalSubscriberCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for _, subs := range h.subscribers {
		n += len(subs)
	}
	return n
}

// --- simpleSubscriber: a minimal Subscriber backed by a JSON channel ---

// channelSubscriber is a simple Subscriber that writes JSON to a channel.
// It is used for testing and as a reference implementation; real WebSocket
// connections would wrap a gorilla/websocket.Conn.
type channelSubscriber struct {
	topic string
	ch    chan<- []byte
	mu    sync.Mutex
	done  chan struct{}
	once  sync.Once
}

// NewChannelSubscriber creates a subscriber that writes JSON-encoded
// messages to ch. The caller should read from ch and forward to the
// WebSocket connection.
func NewChannelSubscriber(topic string, ch chan<- []byte) Subscriber {
	return &channelSubscriber{
		topic: topic,
		ch:    ch,
		done:  make(chan struct{}),
	}
}

func (s *channelSubscriber) Topic() string { return s.topic }

func (s *channelSubscriber) Send(msg *WSMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return errSubscriberClosed
	default:
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	select {
	case s.ch <- data:
		return nil
	default:
		// Channel full — drop message to avoid blocking the hub.
		return nil
	}
}

func (s *channelSubscriber) Close() {
	s.once.Do(func() {
		close(s.done)
	})
}

type subscriberClosedError struct{}

func (subscriberClosedError) Error() string { return "subscriber closed" }

var errSubscriberClosed = subscriberClosedError{}
