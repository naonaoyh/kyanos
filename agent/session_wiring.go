package agent

import (
	"kyanos/agent/conn"
	"kyanos/agent/session"
)

// connInfoFromConnection4 adapts a conn.Connection4 into the minimal
// session.ConnInfo the diagnostic engine needs. It lives in the agent package
// (not session) so that the session package stays decoupled from conn and no
// import cycle is introduced (agent -> conn, agent -> session).
func connInfoFromConnection4(c *conn.Connection4) *session.ConnInfo {
	return &session.ConnInfo{
		LocalIP:    c.LocalIp,
		RemoteIP:   c.RemoteIp,
		LocalPort:  uint16(c.LocalPort),
		RemotePort: uint16(c.RemotePort),
		IsServer:   c.IsServerSide(),
	}
}

// inferCloseDirection determines which side initiated the TCP close.
//
// The current BPF layer records connection close timing (CloseTs) but does not
// distinguish whether the FIN/RST originated from the client or the server.
// Until that signal is plumbed through from the kernel, we report
// CloseDirectionUnknown. This is a known limitation that downgrades the S4
// disconnect-reason heuristics (client-initiated vs RTCM-abort) to the
// GGA-timeout / unknown branches. See docs/ROADMAP_NEXT.md §3.3.
func inferCloseDirection(c *conn.Connection4) session.CloseDirection {
	return session.CloseDirectionUnknown
}
