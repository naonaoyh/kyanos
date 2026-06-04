// Package console — console.go
//
// Console is the main orchestrator that ties together the gRPC server,
// REST API, WebSocket hub, and diagnostic reporter. It provides a
// unified Start/Stop lifecycle for the Web Console backend.
package console

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"kyanos/proto/agentpb"

	"google.golang.org/grpc"
)

// Config holds the Console startup configuration.
type Config struct {
	// GRPCListenAddr is the address for the gRPC server (e.g., ":50051").
	GRPCListenAddr string

	// HTTPListenAddr is the address for the REST API + WebSocket server
	// (e.g., ":8080").
	HTTPListenAddr string

	// Logger is an optional logger; if nil, the standard log package is used.
	Logger *log.Logger
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		GRPCListenAddr: ":50051",
		HTTPListenAddr: ":8080",
	}
}

// Console is the main orchestrator for the Web Console backend.
type Console struct {
	cfg      Config
	store    SessionStore
	hub      *WSHub
	grpcSrv  *grpc.Server
	handler  *AgentServiceHandler
	api      *APIHandler
	reporter *DiagnosticReporter
	httpSrv  *http.Server
	logger   *log.Logger
}

// New creates a Console with the given configuration. It initializes all
// subsystems but does not start listening.
func New(cfg Config) *Console {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	store := NewMemoryStore()
	hub := NewWSHub()
	reporter := NewDiagnosticReporter()
	handler := NewAgentServiceHandler(store, hub)
	api := NewAPIHandler(store, handler, hub, reporter)

	grpcSrv := grpc.NewServer(
		grpc.MaxRecvMsgSize(16*1024*1024), // 16MB
		grpc.MaxSendMsgSize(16*1024*1024),
	)
	agentpb.RegisterAgentServiceServer(grpcSrv, handler)

	return &Console{
		cfg:      cfg,
		store:    store,
		hub:      hub,
		grpcSrv:  grpcSrv,
		handler:  handler,
		api:      api,
		reporter: reporter,
		logger:   cfg.Logger,
	}
}

// Store returns the underlying SessionStore, useful for testing.
func (c *Console) Store() SessionStore { return c.store }

// Hub returns the WebSocket hub.
func (c *Console) Hub() *WSHub { return c.hub }

// GRPCHandler returns the AgentService handler.
func (c *Console) GRPCHandler() *AgentServiceHandler { return c.handler }

// Start launches the gRPC and HTTP servers concurrently. It blocks until
// the context is cancelled, then performs a graceful shutdown.
func (c *Console) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	// Start gRPC server.
	grpcLis, err := net.Listen("tcp", c.cfg.GRPCListenAddr)
	if err != nil {
		return fmt.Errorf("gRPC listen %s: %w", c.cfg.GRPCListenAddr, err)
	}
	c.logger.Printf("console: gRPC server listening on %s", grpcLis.Addr())
	go func() {
		if err := c.grpcSrv.Serve(grpcLis); err != nil {
			errCh <- fmt.Errorf("gRPC serve: %w", err)
		}
	}()

	// Start HTTP server (REST API + WebSocket).
	c.httpSrv = &http.Server{
		Addr:         c.cfg.HTTPListenAddr,
		Handler:      c.api,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // WebSocket connections need unlimited write timeout.
		IdleTimeout:  120 * time.Second,
	}
	c.logger.Printf("console: HTTP server listening on %s", c.cfg.HTTPListenAddr)
	go func() {
		if err := c.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP serve: %w", err)
		}
	}()

	// Wait for context cancellation or server error.
	select {
	case <-ctx.Done():
		c.logger.Printf("console: shutting down...")
	case err := <-errCh:
		return err
	}

	return c.shutdown()
}

// shutdown performs a graceful shutdown of both servers.
func (c *Console) shutdown() error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Stop HTTP server.
	if c.httpSrv != nil {
		if err := c.httpSrv.Shutdown(shutdownCtx); err != nil {
			c.logger.Printf("console: HTTP shutdown error: %v", err)
		}
	}

	// Graceful stop gRPC server.
	c.grpcSrv.GracefulStop()

	c.logger.Printf("console: shutdown complete")
	return nil
}
