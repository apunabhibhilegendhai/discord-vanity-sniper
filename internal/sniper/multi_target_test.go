package sniper

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeConn is a Conn that records the bytes written by a claim and returns a
// canned HTTP 200 response. It lets the multi-target harness exercise the real
// Run → tryClaim → fire → sentry → runOnce path without opening a socket.
type fakeConn struct {
	mu       sync.Mutex
	written  bytes.Buffer
	response []byte
	served   bool
	// readDelay simulates one network RTT in tests that measure the poller's
	// observation cadence. Zero for every other test.
	readDelay time.Duration
	// pastDeadline is true while a read deadline in the past is set. The pool's
	// isConnAlive probe uses exactly that trick; returning a timeout keeps the
	// conn classified as alive instead of consuming the canned response.
	pastDeadline bool
	closed       bool
}

type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

func newFakeConn(vanity string) *fakeConn {
	body := fmt.Sprintf(`{"code":%q,"uses":0}`, vanity)
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		len(body), body)
	return &fakeConn{response: []byte(resp)}
}

func (c *fakeConn) Handshake() error { return nil }

func (c *fakeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readDelay > 0 {
		time.Sleep(c.readDelay)
	}
	if c.pastDeadline {
		return 0, fakeTimeout{}
	}
	if c.served {
		return 0, io.EOF
	}
	c.served = true
	return copy(p, c.response), nil
}

func (c *fakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Each write starts a new request/response cycle: make the next Read serve
	// a fresh canned response instead of EOF. This lets the latency harness run
	// many claim iterations over one held connection.
	c.served = false
	return c.written.Write(p)
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr  { return fakeAddr("local") }
func (c *fakeConn) RemoteAddr() net.Addr { return fakeAddr("remote") }

func (c *fakeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.pastDeadline = !t.IsZero() && t.Before(time.Now())
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.pastDeadline = !t.IsZero() && t.Before(time.Now())
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func (c *fakeConn) requestBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written.Bytes()...)
}

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

// newTestClaimer builds a production Claimer backed by a fake connection. The
// claimer's background publisher is primed synchronously so tryClaim takes the
// same "bytes already published" fast path it takes in a live run.
func newTestClaimer(t *testing.T, guildID, vanity string) (*Claimer, *fakeConn) {
	t.Helper()
	c, conns := newTestClaimerWithBurst(t, guildID, vanity, 1)
	return c, conns[0]
}

func newTestClaimerWithBurst(t *testing.T, guildID, vanity string, burst int) (*Claimer, []*fakeConn) {
	t.Helper()

	target := &Target{GuildID: guildID, Vanity: vanity, Token: "test-token"}
	cfg := &Conf{
		BurstCount: burst,
		Fingerprint: Fingerprint{
			UserAgent:     "test-ua",
			SuperPropsB64: "test-super-props",
		},
	}

	sessions := NewSessionStore(filepath.Join(t.TempDir(), "session_state.json"))
	mfa := NewMFAHandler(target, sessions, "", "", nil, &cfg.Fingerprint)
	stats := &Stats{StartTime: time.Now()}

	conns := make([]*fakeConn, burst)
	poolConns := make([]pooledConn, 0, burst)
	for i := 0; i < burst; i++ {
		fc := newFakeConn(vanity)
		conns[i] = fc
		poolConns = append(poolConns, pooledConn{conn: fc, idledAt: time.Now()})
	}
	pool := &ConnPool{
		addr:   "discord.com:443",
		target: burst,
		conns:  poolConns,
	}

	c := NewClaimer(target, cfg, []*ConnPool{pool}, mfa, stats, nil, NewRateLimiter(),
		burst, false, 1, 1, nil)
	c.publishBytes()

	t.Cleanup(func() {
		close(c.stop)
		c.sentryWG.Wait()
	})
	return c, conns
}

// TestStartAllStartsEveryConfiguredTarget proves one command starts every
// target in an N-target config, concurrently and exactly once.
func TestStartAllStartsEveryConfiguredTarget(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	const configJSON = `{
	  "targets": [
	    {"guild_id": "111", "vanity": "alpha", "token": "test-token"},
	    {"guild_id": "222", "vanity": "beta",  "token": "test-token"},
	    {"guild_id": "333", "vanity": "gamma", "token": "test-token"}
	  ]
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := len(cfg.Targets); got != 3 {
		t.Fatalf("targets = %d, want 3", got)
	}

	o := &Orchestrator{cfg: cfg, stopCh: make(chan struct{})}
	for i := range cfg.Targets {
		o.runners = append(o.runners, &TargetRunner{target: &cfg.Targets[i]})
	}

	// The hook stands in for TargetRunner.Start. It must be entered for every
	// target without the loop waiting on any one of them: all three entered
	// signals are collected while the hook goroutines are still blocked.
	entered := make(chan string, len(o.runners))
	release := make(chan struct{})
	var startedMu sync.Mutex
	started := make(map[string]int)
	o.startHook = func(r *TargetRunner) {
		go func(vanity string) {
			startedMu.Lock()
			started[vanity]++
			startedMu.Unlock()
			entered <- vanity
			<-release
		}(r.target.Vanity)
	}

	done := make(chan struct{})
	go func() {
		o.StartAll()
		close(done)
	}()

	for i := 0; i < len(o.runners); i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d/%d targets were launched concurrently", i, len(o.runners))
		}
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartAll did not return after all targets launched")
	}

	// A second call must be a no-op, not a second arming of every target.
	o.StartAll()

	startedMu.Lock()
	defer startedMu.Unlock()
	for _, vanity := range []string{"alpha", "beta", "gamma"} {
		if started[vanity] != 1 {
			t.Errorf("target %s started %d times, want 1", vanity, started[vanity])
		}
	}
}

type claimLane struct {
	claimer *Claimer
	conn    *fakeConn
	target  *Target
}

// TestFreedTargetClaimsItsOwnVanityCode exercises the real claim path for each
// target: an availability signal wakes the pre-armed sentry, which writes the
// PATCH that belongs to THAT target's guild and vanity. No network is used.
func TestFreedTargetClaimsItsOwnVanityCode(t *testing.T) {
	lanes := []claimLane{
		mustLane(t, "111111111111111111", "alpha"),
		mustLane(t, "222222222222222222", "beta"),
		mustLane(t, "333333333333333333", "gamma"),
	}

	// Only the second target becomes free; the other two must stay untouched.
	claimDone := make(chan struct{})
	go func() {
		defer close(claimDone)
		lanes[1].claimer.tryClaim(time.Now())
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		lanes[1].target.mu.Lock()
		claimed := lanes[1].target.claimed
		lanes[1].target.mu.Unlock()
		if claimed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("freed target did not claim within 2s")
		}
		time.Sleep(time.Millisecond)
	}
	<-claimDone

	for i, l := range lanes {
		l.target.mu.Lock()
		claimed := l.target.claimed
		l.target.mu.Unlock()
		if i == 1 && !claimed {
			t.Errorf("target %s was free but was not claimed", l.target.Vanity)
		}
		if i != 1 && claimed {
			t.Errorf("target %s claimed although it never signalled free", l.target.Vanity)
		}
	}

	// The winning request must be for the target's own guild and vanity code.
	req := string(lanes[1].conn.requestBytes())
	wantLine := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1", lanes[1].target.GuildID)
	if !bytes.Contains([]byte(req), []byte(wantLine)) {
		t.Errorf("request line missing for own guild:\n%s", req)
	}
	wantBody := fmt.Sprintf(`{"code":%q}`, lanes[1].target.Vanity)
	if !bytes.Contains([]byte(req), []byte(wantBody)) {
		t.Errorf("request body missing own vanity %q:\n%s", lanes[1].target.Vanity, req)
	}
	for i, other := range lanes {
		if i == 1 {
			continue
		}
		otherBody := fmt.Sprintf(`{"code":%q}`, other.target.Vanity)
		if bytes.Contains([]byte(req), []byte(otherBody)) {
			t.Errorf("target %s request leaked another target's code %q", lanes[1].target.Vanity, other.target.Vanity)
		}
	}
}

// TestGatewaySignalClaimsOverTheWire exercises the real trigger chain: a
// compact GUILD_UPDATE frame enters the gateway's pre-decode fast path, lands on
// the claimer's availability channel, and the production claim loop fires the
// PATCH for that target. Nothing but the socket is faked.
func TestGatewaySignalClaimsOverTheWire(t *testing.T) {
	const guildID = "123456789012345678"
	claimer, conn := newTestClaimer(t, guildID, "wanted")
	gateway := NewGateway(claimer.target, claimer.available,
		NewSessionStore(filepath.Join(t.TempDir(), "sessions.json")))

	go claimer.claimLoop()

	frame := []byte(`{"t":"GUILD_UPDATE","s":42,"op":0,"d":{"id":"` + guildID + `","vanity_url_code":"other"}}`)
	if !gateway.handleRawGuildUpdateFrame(frame, time.Now()) {
		t.Fatal("gateway did not handle a compact GUILD_UPDATE frame")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		claimer.target.mu.Lock()
		claimed := claimer.target.claimed
		claimer.target.mu.Unlock()
		if claimed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("gateway availability signal never reached the wire")
		}
		time.Sleep(time.Millisecond)
	}

	req := string(conn.requestBytes())
	if !bytes.Contains([]byte(req), []byte(`{"code":"wanted"}`)) {
		t.Errorf("claim on the wire does not carry the target vanity:\n%s", req)
	}
	if !bytes.Contains([]byte(req), []byte("PATCH /api/v9/guilds/"+guildID+"/vanity-url")) {
		t.Errorf("claim on the wire targets the wrong guild:\n%s", req)
	}
}

// TestBurstFiveWritesEverySentry covers the default multi-sentry burst after the
// wake mechanism changed: all five pre-armed sentries must wake, write, and
// report, and runBurst must drain exactly five results.
func TestBurstFiveWritesEverySentry(t *testing.T) {
	claimer, conns := newTestClaimerWithBurst(t, "888888888888888888", "bursty", 5)

	claimer.tryClaim(time.Now())

	claimer.target.mu.Lock()
	claimed := claimer.target.claimed
	claimer.target.mu.Unlock()
	if !claimed {
		t.Fatal("burst did not claim")
	}

	want := `{"code":"bursty"}`
	for i, fc := range conns {
		req := string(fc.requestBytes())
		if !bytes.Contains([]byte(req), []byte(want)) {
			t.Errorf("sentry %d did not write its claim:\n%s", i, req)
		}
	}
}

// TestEveryFreedTargetClaimsConcurrently proves the lanes are independent: when
// several targets become free at once, each fires its own request without
// blocking or overwriting another target's claim.
func TestEveryFreedTargetClaimsConcurrently(t *testing.T) {
	lanes := []claimLane{
		mustLane(t, "555555555555555555", "one"),
		mustLane(t, "666666666666666666", "two"),
		mustLane(t, "777777777777777777", "three"),
	}

	var wg sync.WaitGroup
	for _, l := range lanes {
		wg.Add(1)
		go func(c *Claimer) {
			defer wg.Done()
			c.tryClaim(time.Now())
		}(l.claimer)
	}
	wg.Wait()

	for _, l := range lanes {
		l.target.mu.Lock()
		claimed := l.target.claimed
		l.target.mu.Unlock()
		if !claimed {
			t.Errorf("target %s did not claim", l.target.Vanity)
		}

		req := string(l.conn.requestBytes())
		want := fmt.Sprintf(`{"code":%q}`, l.target.Vanity)
		if !bytes.Contains([]byte(req), []byte(want)) {
			t.Errorf("target %s wrote the wrong code, want %s:\n%s", l.target.Vanity, want, req)
		}
	}
}

// TestClaimTemplateUsesFinalVanity covers the regression the old CLI caused:
// the vanity was renamed after NewClaimer, so the poller watched the new name
// while the PATCH still carried the old one. Run's ensureTemplate re-derives
// the request from the final name.
func TestClaimTemplateUsesFinalVanity(t *testing.T) {
	claimer, conn := newTestClaimer(t, "444444444444444444", "old-name")

	claimer.target.mu.Lock()
	claimer.target.Vanity = "final-name"
	claimer.target.mu.Unlock()

	claimer.ensureTemplate()
	claimer.tryClaim(time.Now())

	req := string(conn.requestBytes())
	if !bytes.Contains([]byte(req), []byte(`{"code":"final-name"}`)) {
		t.Errorf("claim request does not carry the final vanity:\n%s", req)
	}
	if bytes.Contains([]byte(req), []byte(`{"code":"old-name"}`)) {
		t.Errorf("claim request still carries the pre-rename vanity:\n%s", req)
	}
}

func mustLane(t *testing.T, guildID, vanity string) claimLane {
	t.Helper()
	c, fc := newTestClaimer(t, guildID, vanity)
	return claimLane{claimer: c, conn: fc, target: c.target}
}
