package agent_test

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// TestSimpleDialOnly - Just do net.Dial, nothing else (for bpftrace tracing)
func TestSimpleDialOnly(t *testing.T) {
	pid := os.Getpid()
	fmt.Printf("TEST PID: %d\n", pid)
	fmt.Println("Sleeping 3s before dial (wait for bpftrace)...")
	time.Sleep(3 * time.Second)

	fmt.Println("Dialing 127.0.0.1:1 ...")
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1", 2*time.Second)
	if err != nil {
		fmt.Printf("Dial error: %v\n", err)
	} else {
		fmt.Println("Dial OK")
		conn.Close()
	}
	fmt.Println("Done")
}
