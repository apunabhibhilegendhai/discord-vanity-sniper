package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// Poller monitors a guild's vanity URL via a tight GET loop and signals the
// claimer's available channel the moment the target vanity becomes free.
//
// It maintains ONE persistent TLS socket (keepalive) and writes a tiny 6-header
// GET request every ~30ms. When the response shows the guild's vanity_url_code
// is no longer our target (or is empty/null), it pushes a timestamp to the
// available channel so the claimer fires the burst immediately — no gateway
// GUILD_UPDATE propagation delay.
//
// The GET loop runs in parallel with the WebSocket gateway. The gateway still
// provides GUILD_UPDATE events (which also feed available), but the poller
// catches changes ~50-200ms faster because it polls at 30ms with no server-side
// event batching. The two sources are complementary: whichever fires first wins.
type Poller struct {
	guildID string
	vanity  string
	token   string
	ua      string
	sp      string

	reqBuf  []byte // pre-built GET request
	readBuf []byte

	conn      Conn
	available chan<- time.Time
	stop      <-chan struct{}
	done      chan struct{}

	backoffUntil time.Time
}

// NewPoller creates a poller for the given guild/vanity/token. It does NOT
// start the loop — call Run() in a goroutine.
func NewPoller(guildID, vanity, token, ua, sp string, available chan<- time.Time, stop <-chan struct{}) *Poller {
	req := buildPollerGetRequest(guildID, token, ua, sp)
	return &Poller{
		guildID:   guildID,
		vanity:    vanity,
		token:     token,
		ua:        ua,
		sp:        sp,
		reqBuf:    []byte(req),
		readBuf:   make([]byte, 2048),
		available: available,
		stop:      stop,
		done:      make(chan struct{}),
	}
}

// Run starts the 30ms polling loop. Blocks until stop is signaled. Spawn in a
// goroutine.
func (p *Poller) Run() {
	defer close(p.done)

	const baseInterval = 30 * time.Millisecond

	for {
		select {
		case <-p.stop:
			p.closeConn()
			return
		default:
		}

		// Respect backoff from rate limiting
		if !p.backoffUntil.IsZero() && time.Now().Before(p.backoffUntil) {
			sleepFor := p.backoffUntil.Sub(time.Now())
			select {
			case <-p.stop:
				p.closeConn()
				return
			case <-time.After(sleepFor):
			}
			continue
		}

		p.poll()

		// Jitter: [-5ms, +5ms] on 30ms base to avoid deterministic pattern
		jitter := time.Duration(rand.Intn(10)-5) * time.Millisecond
		sleepFor := baseInterval + jitter
		if sleepFor < 10*time.Millisecond {
			sleepFor = 10 * time.Millisecond
		}

		select {
		case <-p.stop:
			p.closeConn()
			return
		case <-time.After(sleepFor):
		}
	}
}

// poll performs one GET request cycle: ensure conn, write, read, parse, signal.
func (p *Poller) poll() {
	if err := p.ensureConn(); err != nil {
		return
	}

	p.conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := p.conn.Write(p.reqBuf); err != nil {
		p.closeConn()
		return
	}

	n, err := p.conn.Read(p.readBuf)
	if err != nil || n == 0 {
		p.closeConn()
		return
	}
	resp := p.readBuf[:n]

	status := parseStatusCode(resp)
	switch {
	case status == 429:
		p.closeConn()
		p.backoffUntil = time.Now().Add(2 * time.Second)
		return
	case status != 200 && status != 0:
		p.closeConn()
		return
	}

	code := extractVanityCode(resp)
	if code != p.vanity {
		select {
		case p.available <- time.Now():
		default:
		}
	}
}

// ensureConn returns a working connection, dialing fresh if needed.
func (p *Poller) ensureConn() error {
	if p.conn != nil {
		return nil
	}
	conn, err := discordDialTLS("discord.com", 5*time.Second)
	if err != nil {
		return err
	}
	p.conn = conn
	return nil
}

func (p *Poller) closeConn() {
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}

func (p *Poller) Stop() {
	<-p.done
}

// buildPollerGetRequest builds the raw GET request bytes for the vanity-url
// endpoint. Minimal headers — no Content-Type, no Content-Length, no body.
// S-pectral/UrlSniper uses the same minimal set in its 30ms aggressive loop.
func buildPollerGetRequest(guildID, token, ua, sp string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n", guildID)
	sb.WriteString("Host: discord.com\r\n")
	sb.WriteString("Connection: keep-alive\r\n")
	fmt.Fprintf(&sb, "Authorization: %s\r\n", token)
	if sp != "" {
		fmt.Fprintf(&sb, "X-Super-Properties: %s\r\n", sp)
	}
	if ua != "" {
		fmt.Fprintf(&sb, "User-Agent: %s\r\n", ua)
	}
	sb.WriteString("\r\n")
	return sb.String()
}

// extractVanityCode parses the "code" field from a GET /vanity-url response
// body. Uses a simple byte scan (no JSON allocation) for speed:
//   {"code":null}       → ""            (no vanity set — free to claim)
//   {"code":"deltafinal"} → "deltafinal" (already claimed)
//   {"code":"other"}    → "other"       (different vanity — our target is free)
//
// Returns empty string on any parse error (caller treats "" as "not our target"
// and signals available, which is safe — it may cause one extra claim attempt
// on a malformed response, but will not miss a real opportunity).
func extractVanityCode(resp []byte) string {
	headerEnd := bytes.Index(resp, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return ""
	}
	body := resp[headerEnd+4:]
	if len(body) == 0 {
		return ""
	}

	idx := bytes.Index(body, []byte(`"code"`))
	if idx < 0 {
		return ""
	}
	idx += 6 // skip "code"
	// skip whitespace + colon
	for idx < len(body) && (body[idx] == ' ' || body[idx] == ':' || body[idx] == '\t') {
		idx++
	}
	if idx >= len(body) {
		return ""
	}
	// null
	if idx+4 <= len(body) && bytes.Equal(body[idx:idx+4], []byte("null")) {
		return ""
	}
	// quoted string
	if body[idx] != '"' {
		return ""
	}
	idx++
	end := bytes.IndexByte(body[idx:], '"')
	if end < 0 {
		return ""
	}
	return string(body[idx : idx+end])
}


