// cmd/console.go — CLI command to start the NTRIP Web Console server.
//
// Usage:
//   kyanos console --grpc-addr :50051 --http-addr :8080
package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"kyanos/console"

	"github.com/spf13/cobra"
)

func init() {
	consoleCmd.Flags().String("grpc-addr", ":50051", "gRPC server listen address")
	consoleCmd.Flags().String("http-addr", ":8080", "HTTP/REST server listen address")
	rootCmd.AddCommand(consoleCmd)
}

var consoleCmd = &cobra.Command{
	Use:   "console",
	Short: "Start the NTRIP Web Console backend server",
	Long: `Start the NTRIP Web Console backend, which includes:
  - gRPC server for Agent registration and event streaming
  - REST API for task management, session queries, and diagnostics
  - WebSocket server for real-time session and task updates`,
	RunE: func(cmd *cobra.Command, args []string) error {
		grpcAddr, _ := cmd.Flags().GetString("grpc-addr")
		httpAddr, _ := cmd.Flags().GetString("http-addr")

		cfg := console.Config{
			GRPCListenAddr: grpcAddr,
			HTTPListenAddr: httpAddr,
		}

		c := console.New(cfg)

		ctx, cancel := signal.NotifyContext(context.Background(),
			os.Interrupt, syscall.SIGTERM)
		defer cancel()

		return c.Start(ctx)
	},
}
