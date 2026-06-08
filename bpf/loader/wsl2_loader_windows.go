//go:build windows

package loader

// GetBpfVisiblePid returns 0 on non-WSL2 systems (no PID translation needed).
func GetBpfVisiblePid() uint32 {
	return 0
}

// IsWSL2 returns false on Windows.
func IsWSL2() bool {
	return false
}
