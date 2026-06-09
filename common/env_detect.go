package common

import (
	"os"
	"runtime"
	"strings"
)

// IsWSL returns true when running inside Windows Subsystem for Linux.
// It checks /proc/version for "microsoft" or "wsl" strings (the latter
// catches newer WSL2 kernels that may not contain "microsoft"), and
// falls back to the WSL_DISTRO_NAME environment variable.
func IsWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if data, err := os.ReadFile("/proc/version"); err == nil {
		v := strings.ToLower(string(data))
		if strings.Contains(v, "microsoft") || strings.Contains(v, "wsl") {
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
