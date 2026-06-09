// dial_only is a minimal standalone program that makes a TCP connection.
// It is built by TestSubprocessConnect (agent/subprocess_connect_test.go)
// via: go build -o /tmp/dial_only ./agent/testdata/dial_only.go
//
// The program prints its PID as DIAL_PID=<pid> so the test can identify
// which kprobe events belong to this subprocess, then attempts a TCP
// connection to trigger the __sys_connect kprobe.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	fmt.Printf("DIAL_PID=%d\n", os.Getpid())

	// Attempt a TCP connection to trigger __sys_connect kprobe.
	// Port 1 on localhost will get ECONNREFUSED, but the syscall still fires.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1", 3*time.Second)
	if err == nil {
		conn.Close()
	}
}
