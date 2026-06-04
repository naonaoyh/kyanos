package common

import (
	"os"
	"runtime"
	"strings"
)

// IsWSL returns true when running inside Windows Subsystem for Linux.
func IsWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if data, err := os.ReadFile("/proc/version"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "microsoft") {
			return true
		}
	}
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	return false
}

// IsContainer returns true when running inside a container (Docker, K8s, etc.)
func IsContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := strings.ToLower(string(data))
		if strings.Contains(s, "docker") || strings.Contains(s, "kubepods") {
			return true
		}
	}
	return false
}
