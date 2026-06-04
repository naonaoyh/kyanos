package agent

import (
	"os/exec"
	"runtime"

	"kyanos/common"
)

// openBrowser opens the given URL in the default browser.
// In WSL, it opens the Windows host browser via cmd.exe.
// In containers, it does nothing (no browser available).
func openBrowser(url string) {
	if common.IsContainer() {
		common.AgentLog.Infof("running in container, skipping browser open: %s", url)
		return
	}

	var cmd string
	var args []string

	switch {
	case common.IsWSL():
		cmd = "cmd.exe"
		args = []string{"/c", "start", url}
	case runtime.GOOS == "darwin":
		cmd = "open"
		args = []string{url}
	case runtime.GOOS == "linux":
		cmd = "xdg-open"
		args = []string{url}
	case runtime.GOOS == "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	default:
		common.AgentLog.Warnf("unsupported platform for browser open: %s", runtime.GOOS)
		return
	}

	if err := exec.Command(cmd, args...).Start(); err != nil {
		common.AgentLog.Warnf("failed to open browser: %v", err)
	} else {
		common.AgentLog.Infof("opened browser: %s", url)
	}
}
