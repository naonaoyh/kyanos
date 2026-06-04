package agent

import (
	"os/exec"
	"runtime"

	"kyanos/common"
)

// openBrowser opens the given URL in the default browser.
func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "linux":
		cmd = "xdg-open"
		args = []string{url}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	default:
		common.AgentLog.Warnf("unsupported platform for browser open: %s", runtime.GOOS)
		return
	}

	if err := exec.Command(cmd, args...).Start(); err != nil {
		common.AgentLog.Warnf("failed to open browser: %v", err)
	}
}
