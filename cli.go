package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

type CLI struct {
	orch    *Orchestrator
	done    chan struct{}
	reader  *bufio.Reader
	sniperStarted bool
}

func NewCLI(orch *Orchestrator) *CLI {
	return &CLI{
		orch:   orch,
		done:   make(chan struct{}),
		reader: bufio.NewReader(os.Stdin),
	}
}

func (c *CLI) Done() <-chan struct{} {
	return c.done
}

func (c *CLI) Run() {
	defer close(c.done)

	stat, err := os.Stdin.Stat()
	if err != nil || (stat.Mode()&os.ModeCharDevice) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("=== Discord Vanity Sniper ===")
	fmt.Printf("Targets: %d | Burst: %d | Guard: %v\n",
		len(c.orch.cfg.Targets), c.orch.cfg.BurstCount, c.orch.cfg.GuardMode)
	fmt.Println("MFA caching automatically in background...")

	// Wait a moment for initial MFA prime to show in logs
	time.Sleep(500 * time.Millisecond)

	for {
		fmt.Println()
		fmt.Println("── Menu ──────────────────────────────")
		fmt.Println("  [1] Start Sniper")
		fmt.Println("  [2] Toggle Guard" + guardStatus(c.orch.cfg.GuardMode))
		fmt.Println("  [3] Status")
		fmt.Println("  [4] Exit")
		fmt.Println("──────────────────────────────────────")
		fmt.Print("Select (1-4): ")

		line, err := c.reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		switch line {
		case "1":
			c.startSniper()
		case "2":
			c.toggleGuard()
		case "3":
			c.showStatus()
		case "4", "exit", "quit", "q":
			fmt.Println("Shutting down...")
			return
		default:
			fmt.Printf("Unknown option: %q\n", line)
		}
	}
}

func guardStatus(enabled bool) string {
	if enabled {
		return " [ON]"
	}
	return " [OFF]"
}

func (c *CLI) startSniper() {
	if c.sniperStarted {
		fmt.Println("Sniper already running.")
		return
	}

	t := &c.orch.cfg.Targets[0]
	fmt.Printf("Target vanity code (Enter for '%s'): ", t.Vanity)
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return
	}
	vanity := strings.TrimSpace(line)

	if vanity != "" && vanity != t.Vanity {
		t.mu.Lock()
		t.Vanity = vanity
		t.claimed = false
		t.mu.Unlock()
	}

	c.sniperStarted = true
	if err := c.orch.StartTarget(0); err != nil {
		fmt.Printf("Error: %v\n", err)
		c.sniperStarted = false
		return
	}
	fmt.Printf("Sniper started for '%s'. Press ENTER anytime for menu.\n", t.Vanity)
	fmt.Println()

	interrupt := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		for {
			os.Stdin.Read(buf)
			if buf[0] == '\n' {
				close(interrupt)
				return
			}
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-interrupt:
			fmt.Println()
			return
		case <-ticker.C:
			c.printStatusLine()
		}
	}
}

func (c *CLI) printStatusLine() {
	checks, claims, errors := c.orch.stats.Snapshot()
	elapsed := time.Since(c.orch.stats.StartTime)
	cps := float64(checks) / elapsed.Seconds()

	latLine := ""
	if p50, _, ok := c.orch.stats.LatencyPercentiles(); ok {
		latLine = fmt.Sprintf(" | latency %.0fms", p50.total.Seconds()*1000)
	}

	claimed := ""
	if c.orch.cfg.Targets[0].claimed {
		claimed = " [CLAIMED]"
	}

	fmt.Printf("\r[stats] checks: %d | claims: %d | errors: %d | speed: %.1f/s | uptime: %s%s%s   ",
		checks, claims, errors, cps, elapsed.Round(time.Second), latLine, claimed)
}

func (c *CLI) toggleGuard() {
	c.orch.cfg.GuardMode = !c.orch.cfg.GuardMode
	// Update runner guardEnabled flag too
	for _, rn := range c.orch.runners {
		rn.target.mu.Lock()
		if c.orch.cfg.GuardMode {
			rn.target.guardArmed = rn.target.claimed
		} else {
			rn.target.guardArmed = false
		}
		rn.target.mu.Unlock()
	}
	fmt.Printf("Guard is now: %v\n", c.orch.cfg.GuardMode)
}

func (c *CLI) showStatus() {
	checks, claims, errors := c.orch.stats.Snapshot()
	elapsed := time.Since(c.orch.stats.StartTime)
	cps := float64(checks) / elapsed.Seconds()

	fmt.Println()
	fmt.Printf("Uptime: %s\n", elapsed.Round(time.Second))
	fmt.Printf("Checks: %d | Claims: %d | Errors: %d | Speed: %.1f/s\n",
		checks, claims, errors, cps)

	for i, rn := range c.orch.runners {
		t := rn.target
		t.mu.Lock()
		claimed := t.claimed
		guardArmed := t.guardArmed
		lost := t.lost
		t.mu.Unlock()

		fmt.Printf("\nTarget #%d [%s]\n", i, t.Vanity)
		fmt.Printf("  Guild:     %s\n", t.GuildID)
		fmt.Printf("  Gateway:   %s\n", gatewayStatus(rn.gateway))
		fmt.Printf("  Claimed:   %v\n", claimed)
		fmt.Printf("  Guard:     action=%s armed=%v lost=%v\n", c.orch.cfg.GuardAction, guardArmed, lost)
		fmt.Printf("  MFA:       %s\n", mfaStatus(rn.mfa))
	}

	if p50, p99, ok := c.orch.stats.LatencyPercentiles(); ok {
		fmt.Printf("\nLatency (p50/p99):\n")
		fmt.Printf("  Dispatch: %.1f / %.1f ms\n", p50.dispatch.Seconds()*1000, p99.dispatch.Seconds()*1000)
		fmt.Printf("  Local:    %.1f / %.1f ms\n", p50.local.Seconds()*1000, p99.local.Seconds()*1000)
		fmt.Printf("  RTT:      %.1f / %.1f ms\n", p50.rtt.Seconds()*1000, p99.rtt.Seconds()*1000)
		fmt.Printf("  Total:    %.1f / %.1f ms\n", p50.total.Seconds()*1000, p99.total.Seconds()*1000)
	}

	if c.orch.cfg.GuardMode {
		reclaims, losses, quarantines, qFails := c.orch.stats.GuardSnapshot()
		if reclaims > 0 || losses > 0 || quarantines > 0 {
			fmt.Printf("\nGuard: reclaims=%d losses=%d quarantines=%d fails=%d\n",
				reclaims, losses, quarantines, qFails)
		}
	}
	fmt.Println()
}

func gatewayStatus(g *Gateway) string {
	if g == nil {
		return "no gateway"
	}
	if g.IsConnected() {
		return "connected"
	}
	return "disconnected"
}

func mfaStatus(m *MFAHandler) string {
	name, val := m.GetHeader()
	if name == "" || val == "" {
		return "expired"
	}
	remaining := ""
	m.mu.Lock()
	if !m.expiresAt.IsZero() {
		d := time.Until(m.expiresAt)
		if d > 0 {
			remaining = fmt.Sprintf(" (%s left)", d.Round(time.Second))
		}
	}
	m.mu.Unlock()
	return "valid" + remaining
}
