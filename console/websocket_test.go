// Package console — websocket_test.go
//
// Tests for WSHub: subscribe, unsubscribe, broadcast, and cleanup.
package console

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestWSHubSubscribeAndBroadcast(t *testing.T) {
	hub := NewWSHub()
	ch := make(chan []byte, 10)
	sub := NewChannelSubscriber("sess-001", ch)
	hub.Subscribe("sess-001", sub)

	hub.Broadcast("sess-001", &WSMessage{
		Type:  "session_event",
		Topic: "sess-001",
		Data:  "hello",
	})

	select {
	case data := <-ch:
		var msg WSMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if msg.Type != "session_event" {
			t.Errorf("type = %q, want session_event", msg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for broadcast")
	}
}

func TestWSHubBroadcastNoSubscribers(t *testing.T) {
	hub := NewWSHub()
	// Should not panic when no subscribers exist.
	hub.Broadcast("nonexistent", &WSMessage{Type: "test"})
}

func TestWSHubUnsubscribe(t *testing.T) {
	hub := NewWSHub()
	ch := make(chan []byte, 10)
	sub := NewChannelSubscriber("topic-1", ch)
	hub.Subscribe("topic-1", sub)

	if hub.SubscriberCount("topic-1") != 1 {
		t.Errorf("subscriber count = %d, want 1", hub.SubscriberCount("topic-1"))
	}

	hub.Unsubscribe("topic-1", sub)

	if hub.SubscriberCount("topic-1") != 0 {
		t.Errorf("subscriber count = %d, want 0", hub.SubscriberCount("topic-1"))
	}

	// Broadcast after unsubscribe should not deliver.
	hub.Broadcast("topic-1", &WSMessage{Type: "test"})
	select {
	case <-ch:
		t.Error("received message after unsubscribe")
	case <-time.After(100 * time.Millisecond):
		// expected
	}
}

func TestWSHubMultipleSubscribers(t *testing.T) {
	hub := NewWSHub()
	ch1 := make(chan []byte, 10)
	ch2 := make(chan []byte, 10)
	sub1 := NewChannelSubscriber("topic", ch1)
	sub2 := NewChannelSubscriber("topic", ch2)
	hub.Subscribe("topic", sub1)
	hub.Subscribe("topic", sub2)

	if hub.SubscriberCount("topic") != 2 {
		t.Errorf("subscriber count = %d, want 2", hub.SubscriberCount("topic"))
	}

	hub.Broadcast("topic", &WSMessage{Type: "multi", Topic: "topic"})

	for _, ch := range []chan []byte{ch1, ch2} {
		select {
		case <-ch:
			// ok
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
}

func TestWSHubUnsubscribeAll(t *testing.T) {
	hub := NewWSHub()
	ch := make(chan []byte, 10)
	sub := NewChannelSubscriber("t1", ch)
	hub.Subscribe("t1", sub)
	hub.Subscribe("t2", sub) // same sub on different topic

	hub.UnsubscribeAll(sub)

	if hub.TotalSubscriberCount() != 0 {
		t.Errorf("total subscribers = %d, want 0", hub.TotalSubscriberCount())
	}
}

func TestWSHubBroadcastSessionEvent(t *testing.T) {
	hub := NewWSHub()
	ch := make(chan []byte, 10)
	sub := NewChannelSubscriber("sess-001", ch)
	hub.Subscribe("sess-001", sub)

	evt := &SessionEventRecord{
		SessionID: "sess-001",
		EventType: "auth",
	}
	hub.BroadcastSessionEvent("sess-001", evt)

	select {
	case data := <-ch:
		var msg WSMessage
		json.Unmarshal(data, &msg)
		if msg.Type != "session_event" {
			t.Errorf("type = %q, want session_event", msg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestWSHubBroadcastTaskStatus(t *testing.T) {
	hub := NewWSHub()
	ch := make(chan []byte, 10)
	sub := NewChannelSubscriber("task:task-1", ch)
	hub.Subscribe("task:task-1", sub)

	task := &Task{ID: "task-1", Status: TaskStatusRunning}
	hub.BroadcastTaskStatus("task-1", task)

	select {
	case data := <-ch:
		var msg WSMessage
		json.Unmarshal(data, &msg)
		if msg.Type != "task_status" {
			t.Errorf("type = %q, want task_status", msg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestWSHubConcurrentBroadcast(t *testing.T) {
	hub := NewWSHub()
	ch := make(chan []byte, 1000)
	sub := NewChannelSubscriber("topic", ch)
	hub.Subscribe("topic", sub)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			hub.Broadcast("topic", &WSMessage{Type: "concurrent", Data: n})
		}(i)
	}
	wg.Wait()

	// Give a moment for all messages to arrive.
	time.Sleep(100 * time.Millisecond)
	count := len(ch)
	if count != 100 {
		t.Errorf("received %d messages, want 100", count)
	}
}

func TestWSHubTotalSubscriberCount(t *testing.T) {
	hub := NewWSHub()
	if hub.TotalSubscriberCount() != 0 {
		t.Error("expected 0 total subscribers initially")
	}

	ch1 := make(chan []byte, 1)
	ch2 := make(chan []byte, 1)
	hub.Subscribe("a", NewChannelSubscriber("a", ch1))
	hub.Subscribe("b", NewChannelSubscriber("b", ch2))
	hub.Subscribe("a", NewChannelSubscriber("a", ch2))

	if hub.TotalSubscriberCount() != 3 {
		t.Errorf("total = %d, want 3", hub.TotalSubscriberCount())
	}
}

func TestChannelSubscriberSendAfterClose(t *testing.T) {
	ch := make(chan []byte, 10)
	sub := NewChannelSubscriber("topic", ch)
	sub.Close()

	err := sub.Send(&WSMessage{Type: "test"})
	if err == nil {
		t.Error("expected error after close")
	}
}

func TestChannelSubscriberTopic(t *testing.T) {
	ch := make(chan []byte, 1)
	sub := NewChannelSubscriber("my-topic", ch)
	if sub.Topic() != "my-topic" {
		t.Errorf("topic = %q, want my-topic", sub.Topic())
	}
}
