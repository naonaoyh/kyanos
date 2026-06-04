package watch

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// DiagProvider: abstraction over SessionTracker for TUI rendering
// ---------------------------------------------------------------------------

// DiagSessionSnapshot is a point-in-time view of a single NTRIP session,
// decoupled from the session package's internal types.
type DiagSessionSnapshot struct {
	SessionID  string
	MountPoint string
	Username   string
	ClientIP   string
	ClientRole string
	Duration   time.Duration
	IsActive   bool
	Score      int // 0-100 total
	GGAEvents  int
	RTCMFrames int
	RTCMBytes  int64
	AuthMethod string
	Disconnect string
}

// DiagProvider abstracts the SessionTracker so the render package does not
// import the session package.
type DiagProvider interface {
	DiagSnapshots() []DiagSessionSnapshot
}

// ---------------------------------------------------------------------------
// Diag summary table
// ---------------------------------------------------------------------------

var diagHeaderStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("99")).
	BorderStyle(lipgloss.NormalBorder()).
	BorderBottom(true).
	BorderForeground(lipgloss.Color("240"))

var diagActiveStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
var diagClosedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
var diagScoreGoodStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
var diagScoreWarnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
var diagScoreBadStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
var diagSummaryStyle = lipgloss.NewStyle().
	Padding(0, 1).
	Foreground(lipgloss.Color("252"))

func scoreColor(score int) lipgloss.Style {
	switch {
	case score >= 90:
		return diagScoreGoodStyle
	case score >= 70:
		return diagScoreWarnStyle
	default:
		return diagScoreBadStyle
	}
}

// NewDiagTable creates a Bubble Tea table for the diagnostic session list.
func NewDiagTable(snapshots []DiagSessionSnapshot) table.Model {
	columns := []table.Column{
		{Title: "ID", Width: 4},
		{Title: "Mount", Width: 14},
		{Title: "User", Width: 12},
		{Title: "Score", Width: 7},
		{Title: "GGA", Width: 5},
		{Title: "RTCM", Width: 6},
		{Title: "Bytes", Width: 8},
		{Title: "Duration", Width: 9},
		{Title: "Status", Width: 8},
	}

	rows := make([]table.Row, 0, len(snapshots))
	for i, s := range snapshots {
		status := "Active"
		if !s.IsActive {
			status = "Closed"
		}
		mount := s.MountPoint
		if len(mount) > 12 {
			mount = mount[:12] + ".."
		}
		user := s.Username
		if user == "" {
			user = "-"
		}
		if len(user) > 10 {
			user = user[:10] + ".."
		}
		rows = append(rows, table.Row{
			fmt.Sprintf("%d", i+1),
			mount,
			user,
			fmt.Sprintf("%d/100", s.Score),
			fmt.Sprintf("%d", s.GGAEvents),
			fmt.Sprintf("%d", s.RTCMFrames),
			fmt.Sprintf("%d", s.RTCMBytes),
			formatDuration(s.Duration),
			status,
		})
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(min(len(rows)+1, 15)),
	)
	styles := table.DefaultStyles()
	styles.Header = diagHeaderStyle
	styles.Selected = styles.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(styles)
	return t
}

// RenderDiagHeader produces the summary line above the sessions table.
func RenderDiagHeader(snapshots []DiagSessionSnapshot) string {
	active := 0
	totalScore := 0
	for _, s := range snapshots {
		if s.IsActive {
			active++
		}
		totalScore += s.Score
	}
	avgScore := 0
	if len(snapshots) > 0 {
		avgScore = totalScore / len(snapshots)
	}
	return diagSummaryStyle.Render(
		fmt.Sprintf("Active: %s | Total: %s | Avg Score: %s",
			diagActiveStyle.Render(fmt.Sprintf("%d", active)),
			fmt.Sprintf("%d", len(snapshots)),
			scoreColor(avgScore).Render(fmt.Sprintf("%d", avgScore)),
		),
	)
}

// RenderDiagFooter produces the help line for the diagnostic view.
func RenderDiagFooter() string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Render("  d: back to records  enter: session detail  esc: back  q: quit")
}

// RenderDiagTitle produces the title bar for the diagnostic view.
func RenderDiagTitle(width int) string {
	title := diagHeaderStyle.Render(" NTRIP Diagnostic Sessions ")
	line := strings.Repeat("─", max(0, width-lipgloss.Width(title)))
	return lipgloss.JoinHorizontal(lipgloss.Center, title, line)
}

// ---------------------------------------------------------------------------
// Per-session detail rendering
// ---------------------------------------------------------------------------

// RenderSessionDetail produces a full diagnostic report for a single session,
// suitable for display in a viewport.
func RenderSessionDetail(snap DiagSessionSnapshot, width int) string {
	var b strings.Builder

	sectionStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))

	writeLine := func(format string, args ...any) {
		b.WriteString(fmt.Sprintf(format, args...))
		b.WriteByte('\n')
	}

	// Identity
	writeLine("%s", sectionStyle.Render("── Identity ──"))
	writeLine("  %s %s", labelStyle.Render("Session:"), snap.SessionID)
	writeLine("  %s %s", labelStyle.Render("Client:"), snap.ClientIP)
	writeLine("  %s %s", labelStyle.Render("Role:"), snap.ClientRole)
	writeLine("  %s %s", labelStyle.Render("Mount:"), snap.MountPoint)
	if snap.Username != "" {
		writeLine("  %s %s", labelStyle.Render("User:"), snap.Username)
	}
	writeLine("  %s %s", labelStyle.Render("Duration:"), formatDuration(snap.Duration))
	writeLine("")

	// Auth
	writeLine("%s", sectionStyle.Render("── Authentication (S1) ──"))
	if snap.AuthMethod != "" {
		writeLine("  %s %s", labelStyle.Render("Method:"), snap.AuthMethod)
	} else {
		writeLine("  Auth: not observed")
	}
	writeLine("")

	// GGA
	writeLine("%s", sectionStyle.Render("── GGA Uploads (S2) ──"))
	writeLine("  %s %d", labelStyle.Render("Events:"), snap.GGAEvents)
	writeLine("")

	// RTCM
	writeLine("%s", sectionStyle.Render("── RTCM Delivery (S3) ──"))
	writeLine("  %s %d", labelStyle.Render("Frames:"), snap.RTCMFrames)
	writeLine("  %s %d bytes", labelStyle.Render("Total:"), snap.RTCMBytes)
	writeLine("")

	// Score
	writeLine("%s", sectionStyle.Render("── Diagnostic Score ──"))
	sc := scoreColor(snap.Score)
	writeLine("  %s", sc.Render(fmt.Sprintf("%d/100", snap.Score)))
	writeLine("")

	// Status
	writeLine("%s", sectionStyle.Render("── Status ──"))
	if snap.IsActive {
		writeLine("  %s", diagActiveStyle.Render("Active"))
	} else {
		writeLine("  %s", diagClosedStyle.Render("Closed"))
		if snap.Disconnect != "" {
			writeLine("  %s %s", labelStyle.Render("Reason:"), snap.Disconnect)
		}
	}

	return b.String()
}

// Detail title for the viewport header.
func RenderSessionDetailTitle(snap DiagSessionSnapshot, width int) string {
	title := fmt.Sprintf(" Session: %s ", snap.MountPoint)
	styled := lipgloss.NewStyle().
		Bold(true).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("99")).
		Padding(0, 1).
		Render(title)
	line := strings.Repeat("─", max(0, width-lipgloss.Width(styled)))
	return lipgloss.JoinHorizontal(lipgloss.Center, styled, line)
}

// Detail footer with scroll percentage.
func RenderSessionDetailFooter(scrollPct float64, width int) string {
	info := fmt.Sprintf(" %.0f%% ", scrollPct*100)
	styled := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		Padding(0, 1).
		Render(info)
	line := strings.Repeat("─", max(0, width-lipgloss.Width(styled)))
	return lipgloss.JoinHorizontal(lipgloss.Center, line, styled) +
		"\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("  esc: back to session list  d: back to records")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%.0fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
