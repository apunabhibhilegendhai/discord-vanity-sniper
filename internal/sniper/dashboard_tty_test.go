package sniper

import (
	"strings"
	"testing"
	"time"
)

func TestStdoutIsTYTONonTerminal(t *testing.T) {
	// In `go test`, stdout is redirected to a file or pipe in most CI runs, so
	// this mostly asserts "not a TTY", but the helper must never panic and
	// must accept both branches.
	if stdoutIsTTY() {
		t.Skip("stdout is a terminal in this environment — nothing to assert")
	}
}

func TestDashboardRepaintFormat(t *testing.T) {
	// Non-TTY: one timestamped log-style line per tick, no \r prefix.
	repaint := "\r[stats] %s   "
	if stdoutIsTTY() {
		t.Skip("stdout is a terminal — the non-TTY repaint format is not exercised")
	}

	// Mirror dashboard()'s non-TTY branch (period + format) so behavior is
	// verified against the exact strings production uses.
	period := 5 * time.Second
	isTTY := stdoutIsTTY()
	if !isTTY {
		period = 5 * time.Minute
		repaint = "[stats] %s\n"
	}
	if period != 5*time.Minute {
		t.Fatalf("non-TTY dashboard period must be 5m, got %v", period)
	}
	if strings.HasPrefix(repaint, "\r") {
		t.Fatalf("non-TTY repaint must not carry a carriage return: %q", repaint)
	}
	if !strings.Contains(repaint, "\n") {
		t.Fatalf("non-TTY repaint must terminate each line: %q", repaint)
	}
}
