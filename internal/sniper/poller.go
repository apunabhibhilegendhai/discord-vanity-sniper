package sniper

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
// GET request on a 5ms cycle target. The interval is measured from the START of
// the request, so on an RTT-bound link the next request leaves immediately after
// the response and the observation cadence is one RTT — not RTT+5ms. When the
// response shows the guild's vanity_url_code is no longer our target (or is
// empty/null), it pushes a timestamp to the available channel so the claimer
// fires the burst immediately — no gateway GUILD_UPDATE propagation delay.
//
// The GET loop runs in parallel with the WebSocket gateway. The gateway still
// provides GUILD_UPDATE events (which also feed available). The two sources are
// complementary: whichever fires first wins. One request is in flight at a time,
// so on this host's ~56ms RTT the cadence is one observation per ~56ms, not one
// per 5ms; the 5ms floor only binds on fast links. The gateway push is therefore
// normally the faster trigger; the poller is the backup for missed or delayed
// events.
type Poller struct {
	target *Target
	token  string
	ua     string
	sp     string

	reqBuf  []byte // pre-built GET request
	readBuf []byte

	conn      Conn
	available chan<- time.Time
	stop      <-chan struct{}
	done      chan struct{}

	stats *Stats // nil in tests that do not inspect observation counts

	backoffUntil time.Time
}

// NewPoller creates a poller for the given target/token. It does NOT start the
// loop — call Run() in a goroutine. The target is held so every poll reads its
// vanity through currentVanity(), under target.mu, and asks vanityFree whether
// the observed code means free.
func NewPoller(target *Target, token, ua, sp string, available chan<- time.Time, stop <-chan struct{}) *Poller {
	req := buildPollerGetRequest(target.GuildID, token, ua, sp)
	return &Poller{
		target:    target,
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

// Run starts the cycle-target polling loop. Blocks until stop is signaled.
// Spawn in a goroutine.
func (p *Poller) Run() {
	defer close(p.done)

	const pollCycle = 5 * time.Millisecond

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

		started := time.Now()
		p.poll()

		// Micro-jitter: [-1ms, +1ms] on the 5ms cycle target to avoid a
		// deterministic pattern. Subtract the request time so a slow response
		// does not get an extra fixed sleep appended: S-pectral's aggressive
		// loop uses the same deadline-from-start pattern, and it is the
		// difference between an RTT cadence and an RTT+5ms cadence.
		jitter := time.Duration(rand.Intn(3)-1) * time.Millisecond
		sleepFor := pollCycle + jitter - time.Since(started)
		if sleepFor < 0 {
			sleepFor = 0
		}

		select {
		case <-p.stop:
			p.closeConn()
			return
		case <-time.After(sleepFor):
		}
	}
}

// poll performs one GET request cycle: ensure conn, write, read a COMPLETE
// response, parse, signal. A truncated or unparseable response is never
// treated as "free": a false trigger spends the shot and looks like abuse.
func (p *Poller) poll() {
	if err := p.ensureConn(); err != nil {
		return
	}

	// A poll response is tiny; cap the read at 100ms so one stalled response
	// cannot block the 5ms loop for seconds. Incomplete reads are discarded.
	p.conn.SetDeadline(time.Now().Add(100 * time.Millisecond))

	if _, err := p.conn.Write(p.reqBuf); err != nil {
		p.closeConn()
		return
	}

	resp, complete := p.readResponse()
	if !complete {
		p.closeConn()
		return
	}

	status := parseStatusCode(resp)
	switch {
	case status == 429:
		p.closeConn()
		p.backoffUntil = time.Now().Add(2 * time.Second)
		return
	case status != 200:
		p.closeConn()
		return
	}

	code, ok := parseVanityCode(resp)
	currentVanity := p.target.currentVanity()
	if observeVanity(p.stats, currentVanity, code, ok) {
		select {
		case p.available <- time.Now():
		default:
		}
	}
}

// readResponse reads until the HTTP response is complete (headers plus the
// Content-Length body, or a chunked terminator). Returns complete=false on a
// timeout, an early EOF, or a malformed/oversized response.
func (p *Poller) readResponse() ([]byte, bool) {
	return readCompleteResponse(p.conn, p.readBuf)
}

// readCompleteResponse is shared by the poller and the REST check so both
// detection routes agree on what a complete response is. A partial response
// must never reach the free/not-free decision.
func readCompleteResponse(conn Conn, readBuf []byte) ([]byte, bool) {
	var resp []byte
	for {
		n, err := conn.Read(readBuf)
		if n > 0 {
			resp = append(resp, readBuf[:n]...)
		}
		if headerEnd := bytes.Index(resp, []byte("\r\n\r\n")); headerEnd >= 0 {
			if cl := contentLength(resp); cl >= 0 {
				if len(resp) >= headerEnd+4+cl {
					return resp, true
				}
			} else if bytes.Contains(resp[:headerEnd], []byte("Transfer-Encoding: chunked")) ||
				bytes.Contains(resp[:headerEnd], []byte("transfer-encoding: chunked")) {
				if bytes.Contains(resp[headerEnd+4:], []byte("\r\n0\r\n")) {
					return resp, true
				}
			} else {
				// No framing header: the header block is all we can rely on.
				return resp, true
			}
		}
		if err != nil {
			return resp, false
		}
		if len(resp) > 64*1024 {
			return resp, false
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

// parseVanityCode parses the "code" field from a GET /vanity-url response.
// The boolean distinguishes a successfully parsed code from a malformed body:
//
//	{"code":null}        -> "", true   (no vanity set — free to claim)
//	{"code":"delta"}    -> "delta", true
//	{"code":"other"}    -> "other", true
//	<truncated/garbage>  -> "", false  (must NOT be treated as free)
//
// The old version returned "" for both null and parse failure, and the poller
// read that as "our target is free" — a wrong trigger that wasted the shot.
func parseVanityCode(resp []byte) (string, bool) {
	headerEnd := bytes.Index(resp, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return "", false
	}
	body := resp[headerEnd+4:]
	if len(body) == 0 {
		return "", false
	}

	idx := bytes.Index(body, []byte(`"code"`))
	if idx < 0 {
		return "", false
	}
	idx += 6 // skip "code"
	for idx < len(body) && (body[idx] == ' ' || body[idx] == ':' || body[idx] == '\t') {
		idx++
	}
	if idx >= len(body) {
		return "", false
	}
	if idx+4 <= len(body) && bytes.Equal(body[idx:idx+4], []byte("null")) {
		return "", true
	}
	if body[idx] != '"' {
		return "", false
	}
	idx++
	end := bytes.IndexByte(body[idx:], '"')
	if end < 0 {
		return "", false
	}
	return string(body[idx : idx+end]), true
}
