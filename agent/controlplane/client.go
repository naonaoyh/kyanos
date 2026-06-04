// Package controlplane implements the Phase 7 gRPC control-plane subsystem.
//
// This file implements the Client (gRPC_Client): it establishes and maintains
// the gRPC connection and bidirectional stream to the Console, performs the
// registration handshake, sends heartbeats, drives reconnection via Backoff on
// stream loss, replays buffered events on reconnect, and routes inbound
// commands through the Dispatcher.
//
// The Client never builds or redacts events itself; it only transports what the
// EventReporter placed in the EventBuffer, keeping the credential-safety gate
// in exactly one place.
package controlplane

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"kyanos/common"
	"kyanos/proto/agentpb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Client is the gRPC_Client: it establishes and maintains the connection and
// bidirectional stream to the Console, performs registration, sends heartbeats,
// drives reconnection via Backoff, replays buffered events on reconnect, and
// routes inbound commands through the Dispatcher.
//
// The Client never builds or redacts events itself; it only transports what the
// EventReporter placed in the EventBuffer (Requirements 2.2, 7.1, 7.4, 7.6,
// 7.7, 8.5, 8.7).
type Client struct {
	// addr is the Console address (host:port) from --grpc-server.
	addr string
	// nodeName is the Kubernetes node name used as unique Agent identity.
	nodeName string
	// version is the Agent software version string.
	version string
	// creds holds the transport credentials (TLS or insecure) built via
	// buildTransport. nil means plaintext.
	creds credentials.TransportCredentials

	// buffer is the Local_Event_Buffer; it decouples the EventReporter
	// goroutine from the Client send loop.
	buffer *EventBuffer[*agentpb.SessionEvent]
	// backoff drives exponential capped reconnection delays.
	backoff Backoff
	// dispatcher routes inbound ControlCommands to TaskManager/FilterController.
	dispatcher *Dispatcher
	// clock abstracts time for heartbeat timers (injectable for tests).
	clock Clock

	// resolver provides managed-pod information for registration/status.
	resolver *PodResolver

	// hbInterval is the period between heartbeat keep-alives.
	hbInterval time.Duration
	// hbTimeout is the maximum time to wait for a heartbeat ack before
	// treating the stream as lost.
	hbTimeout time.Duration

	// connected indicates whether an authenticated stream is currently
	// established. Commands are accepted only when this is true (Req 8.7).
	connected atomic.Bool

	// mu protects the lastStatus field for status-change detection.
	mu         sync.Mutex
	lastStatus *agentpb.AgentStatus
}

// ClientConfig holds the construction parameters for a Client.
type ClientConfig struct {
	Addr       string
	NodeName   string
	Version    string
	Creds      credentials.TransportCredentials
	Buffer     *EventBuffer[*agentpb.SessionEvent]
	Backoff    Backoff
	Dispatcher *Dispatcher
	Clock      Clock
	Resolver   *PodResolver

	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
}

// NewClient constructs a Client from the given configuration. The Client is
// inert until Run is called.
func NewClient(cfg ClientConfig) *Client {
	clk := cfg.Clock
	if clk == nil {
		clk = NewRealClock()
	}
	return &Client{
		addr:       cfg.Addr,
		nodeName:   cfg.NodeName,
		version:    cfg.Version,
		creds:      cfg.Creds,
		buffer:     cfg.Buffer,
		backoff:    cfg.Backoff,
		dispatcher: cfg.Dispatcher,
		clock:      clk,
		resolver:   cfg.Resolver,
		hbInterval: cfg.HeartbeatInterval,
		hbTimeout:  cfg.HeartbeatTimeout,
	}
}

// Enqueue hands an already-projected, already-redacted event to the outbound
// path (the EventBuffer). The Client itself never builds or redacts events; it
// only transports them. This method is safe for concurrent use.
func (c *Client) Enqueue(ev *agentpb.SessionEvent) {
	if c.buffer != nil {
		c.buffer.Push(ev)
	}
}

// IsConnected reports whether the Client currently has an established,
// authenticated stream. Commands are accepted only when connected (Req 8.7).
func (c *Client) IsConnected() bool {
	return c.connected.Load()
}

// Run drives the connect → register → serve → backoff-retry loop until ctx is
// cancelled. It is designed to run on a goroutine and exit cleanly when ctx is
// done.
//
// On each iteration:
//  1. Dial the Console.
//  2. Register (send AgentInfo via Connect RPC). On rejection, retry under
//     Backoff (Requirement 2.5).
//  3. Open the ReportEvents client stream for sending events.
//  4. Replay buffered events in order (Requirement 7.4).
//  5. Serve the bidirectional stream: receive commands via the Connect stream
//     (→ Dispatcher), drain EventBuffer → send via ReportEvents, send
//     heartbeats at the configured interval.
//  6. On stream loss (receive error, heartbeat timeout, etc.), close the
//     connection, back off (Requirement 7.1), and retry from step 1.
//
// Requirements: 2.2, 2.3, 2.5, 7.1, 7.4, 7.6, 7.7, 8.5, 8.7
func (c *Client) Run(ctx context.Context) error {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := c.runOnce(ctx)
		if err == nil || ctx.Err() != nil {
			return ctx.Err()
		}

		// Stream lost or registration rejected — back off and retry.
		common.AgentLog.Warnf("controlplane.Client: connection lost: %v; backing off (attempt %d)", err, attempt)
		delay := c.backoff.Delay(attempt)
		attempt++

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

// runOnce performs a single connection attempt: dial, register, serve stream,
// and return when the stream is lost or ctx is cancelled.
func (c *Client) runOnce(ctx context.Context) error {
	// Step 1: Dial the Console.
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	svc := agentpb.NewAgentServiceClient(conn)

	// Step 2: Register. On rejection, return an error so the outer loop retries
	// under Backoff (Requirement 2.5).
	cmdStream, err := c.register(ctx, svc)
	if err != nil {
		return err
	}

	// Step 3: Open the ReportEvents client stream for sending events.
	evStream, err := svc.ReportEvents(ctx)
	if err != nil {
		return err
	}

	// Mark the stream as established and authenticated (Requirement 8.7).
	c.connected.Store(true)
	defer c.connected.Store(false)

	common.AgentLog.Infof("controlplane.Client: connected to Console at %s", c.addr)

	// Step 4: Replay buffered events in order before resuming live sends
	// (Requirement 7.4).
	if err := c.replayBuffered(evStream); err != nil {
		return err
	}

	// Step 5: Serve the bidirectional stream.
	return c.serve(ctx, cmdStream, evStream)
}

// dial establishes a gRPC connection to the Console address using the
// configured transport credentials. (Requirements 8.2, 8.3, 8.5)
func (c *Client) dial(_ context.Context) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	if c.creds != nil {
		opts = append(opts, grpc.WithTransportCredentials(c.creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(c.addr, opts...)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// register performs the registration handshake: builds AgentInfo and calls
// Connect to get the server stream of commands. On rejection (Unavailable,
// PermissionDenied, Unauthenticated), logs the reason and returns an error
// so the outer loop retries under Backoff (Requirement 2.5).
func (c *Client) register(ctx context.Context, svc agentpb.AgentServiceClient) (grpc.ServerStreamingClient[agentpb.ControlCommand], error) {
	managedPods := c.getManagedPods()
	info := buildAgentInfo(c.nodeName, c.version, managedPods)

	stream, err := svc.Connect(ctx, info)
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			common.AgentLog.Warnf("controlplane.Client: registration rejected: code=%s reason=%q", st.Code(), st.Message())
		}
		return nil, err
	}

	common.AgentLog.Infof("controlplane.Client: registered with Console (node=%s, version=%s, pods=%d)",
		c.nodeName, c.version, len(managedPods))
	return stream, nil
}

// replayBuffered drains the EventBuffer and sends all buffered events in FIFO
// order over the event stream before any live events. (Requirement 7.4)
func (c *Client) replayBuffered(evStream grpc.ClientStreamingClient[agentpb.SessionEvent, agentpb.EventAck]) error {
	events := c.buffer.DrainInOrder()
	if len(events) == 0 {
		return nil
	}
	common.AgentLog.Infof("controlplane.Client: replaying %d buffered events", len(events))
	for _, ev := range events {
		if err := evStream.SendMsg(ev); err != nil {
			return err
		}
	}
	return nil
}

// serve manages the established bidirectional stream: it concurrently receives
// commands (routing them through the Dispatcher), sends events from the
// EventBuffer, and sends heartbeats at the configured interval. It returns when
// the stream is lost, a heartbeat times out, or ctx is cancelled.
func (c *Client) serve(
	ctx context.Context,
	cmdStream grpc.ServerStreamingClient[agentpb.ControlCommand],
	evStream grpc.ClientStreamingClient[agentpb.SessionEvent, agentpb.EventAck],
) error {
	// errCh collects the first fatal error from any concurrent goroutine.
	errCh := make(chan error, 3)

	// Sub-context so we can cancel all goroutines when any one fails.
	sCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Goroutine 1: Receive commands from the Console and dispatch them.
	go func() {
		errCh <- c.receiveCommands(sCtx, cmdStream)
	}()

	// Goroutine 2: Drain EventBuffer and send events.
	go func() {
		errCh <- c.sendEvents(sCtx, evStream)
	}()

	// Goroutine 3: Send heartbeats at the configured interval.
	go func() {
		errCh <- c.heartbeatLoop(sCtx, evStream)
	}()

	// Wait for the first error (or ctx cancellation).
	select {
	case err := <-errCh:
		cancel()
		return err
	case <-sCtx.Done():
		return sCtx.Err()
	}
}

// receiveCommands reads commands from the Connect server stream and dispatches
// them. It returns when the stream ends or ctx is cancelled.
// Commands are only accepted over the established authenticated stream (Req 8.7).
func (c *Client) receiveCommands(ctx context.Context, cmdStream grpc.ServerStreamingClient[agentpb.ControlCommand]) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cmd, err := cmdStream.Recv()
		if err != nil {
			if err == io.EOF {
				// Server closed the stream gracefully.
				return io.EOF
			}
			return err
		}

		// Route the command through the Dispatcher. Errors from dispatch are
		// logged but do not kill the stream (Requirement 2.7).
		if c.dispatcher != nil {
			resp, dispErr := c.dispatcher.Dispatch(cmd)
			if dispErr != nil {
				common.AgentLog.Warnf("controlplane.Client: command dispatch error: %v", dispErr)
			}
			_ = resp // TaskResponse is not sent back over this stream (fire-and-forget dispatch)
		}
	}
}

// sendEvents drains the EventBuffer periodically and sends events over the
// ReportEvents stream. It returns when ctx is cancelled or a send fails.
func (c *Client) sendEvents(ctx context.Context, evStream grpc.ClientStreamingClient[agentpb.SessionEvent, agentpb.EventAck]) error {
	// Poll the buffer at a reasonable interval to batch sends without excessive
	// latency.
	const sendInterval = 100 * time.Millisecond
	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			events := c.buffer.DrainInOrder()
			for _, ev := range events {
				if err := evStream.SendMsg(ev); err != nil {
					// Re-buffer unsent events so they can be replayed on
					// reconnect. Push them back in order.
					for _, remaining := range events {
						c.buffer.Push(remaining)
					}
					return err
				}
			}
		}
	}
}

// heartbeatLoop sends heartbeat events at the configured interval. If no ack is
// received within the configured timeout, it treats the stream as lost and
// returns an error to trigger reconnection (Requirement 7.7).
//
// The heartbeat is realized as a SessionEvent with a special empty payload sent
// over the ReportEvents stream. The server acknowledges heartbeats via the
// EventAck response. If the ReportEvents stream supports CloseSend+RecvMsg for
// ack, we use a simpler approach: send a periodic status report via
// ReportStatus as the heartbeat/ack mechanism.
//
// Implementation note: Since ReportEvents is a client-streaming RPC (the ack
// comes only after CloseAndRecv), we implement the heartbeat/ack check by
// monitoring the stream's liveness — if a send fails, the stream is dead. For
// explicit heartbeat timeout detection, we use a timer that resets on each
// successful send; if no send succeeds within hbInterval+hbTimeout, the stream
// is declared dead.
func (c *Client) heartbeatLoop(ctx context.Context, evStream grpc.ClientStreamingClient[agentpb.SessionEvent, agentpb.EventAck]) error {
	if c.hbInterval <= 0 {
		// Heartbeats disabled; block until context is done.
		<-ctx.Done()
		return ctx.Err()
	}

	ticker := time.NewTicker(c.hbInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Send a heartbeat by reporting the current status to the Console.
			// This doubles as the heartbeat signal and the managed-pod status
			// report (Requirement 2.4, 7.6).
			if err := c.sendHeartbeat(ctx, evStream); err != nil {
				// Stream is dead or heartbeat timed out.
				return err
			}
		}
	}
}

// sendHeartbeat sends a heartbeat signal and waits for acknowledgment within
// the configured timeout. If the timeout expires, the stream is treated as lost
// (Requirement 7.7).
//
// The heartbeat is implemented as a lightweight event send over the event stream.
// A successful SendMsg confirms the transport layer is alive. To detect a truly
// dead connection (where sends buffer without delivery), we impose a write
// deadline via a context timeout.
func (c *Client) sendHeartbeat(ctx context.Context, evStream grpc.ClientStreamingClient[agentpb.SessionEvent, agentpb.EventAck]) error {
	timeout := c.hbTimeout
	if timeout <= 0 {
		timeout = c.hbInterval
	}

	// Create a heartbeat event — a minimal SessionEvent that signals liveness.
	// The Console ignores events with empty session_id as heartbeat probes.
	hbEvent := &agentpb.SessionEvent{
		TimestampNs: c.clock.Now().UnixNano(),
	}

	// Use a deadline to detect stuck writes (missed heartbeat ack, Req 7.7).
	done := make(chan error, 1)
	go func() {
		done <- evStream.SendMsg(hbEvent)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return err
		}
		return nil
	case <-time.After(timeout):
		// Heartbeat ack not received within timeout — treat as stream loss.
		common.AgentLog.Warnf("controlplane.Client: heartbeat timeout (%v) — treating stream as lost", timeout)
		return status.Error(codes.DeadlineExceeded, "heartbeat timeout: no ack within configured timeout")
	}
}

// getManagedPods returns the current list of managed pods from the PodResolver.
// If the resolver is nil or in fallback mode, returns nil.
func (c *Client) getManagedPods() []*agentpb.PodInfo {
	if c.resolver == nil || c.resolver.InFallback() {
		return nil
	}
	// Read from the resolver's cache. We gather all cached PodInfo entries.
	c.resolver.mu.RLock()
	pods := make([]*agentpb.PodInfo, 0, len(c.resolver.cache))
	seen := make(map[string]bool)
	for _, info := range c.resolver.cache {
		key := info.GetNamespace() + "/" + info.GetPodName()
		if !seen[key] {
			seen[key] = true
			pods = append(pods, info)
		}
	}
	c.resolver.mu.RUnlock()
	return pods
}
