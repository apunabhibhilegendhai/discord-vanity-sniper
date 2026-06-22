package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// latencyDebug is set at init from the SNIPER_LATENCY_DEBUG env var. When 1,
// every successful claim logs the frame→wire latency breakdown (dispatch /
// local / rtt / total) so the operator can see where the ms actually go.
var latencyDebug = os.Getenv("SNIPER_LATENCY_DEBUG") == "1"

// claimBytesDebug is set at init from the SNIPER_CLAIM_BYTES_DEBUG env var. When
// 1, the EXACT bytes written on the first claim attempt are logged once (token
// and MFA value redacted) so a malformed request can be diagnosed byte-for-byte
// against a known-good capture. The dump is one-shot (claimBytesDumped) so a
// burst of N sentries doesn't flood the log with N copies of the same bytes.
var claimBytesDebug = os.Getenv("SNIPER_CLAIM_BYTES_DEBUG") == "1"
var claimBytesDumped uint32 // atomic; set to 1 after the first dump

// redactedRequest returns the raw claim request bytes as a string with the
// sensitive header VALUES redacted (token, MFA JWT, super-properties) while
// keeping the rest verbatim — request line, header NAMES, cookie NAMES, body,
// and CRLF structure are all shown exactly as written on the wire. This is the
// decisive diagnostic for malformed-claim failures: the redacted dump can be
// diffed against a known-good browser capture header-for-header.
//
// Cookie VALUES are also redacted (they're per-device secrets), but cookie
// names and order are preserved.
func redactedRequest(b []byte) string {
	s := string(b)
	lines := strings.Split(s, "\r\n")
	for i, ln := range lines {
		lower := strings.ToLower(ln)
		switch {
		case strings.HasPrefix(lower, "authorization:"):
			lines[i] = "Authorization: <redacted>"
		case strings.HasPrefix(lower, "x-discord-mfa-authorization:"),
			strings.HasPrefix(lower, "x-discord-mfa:"):
			lines[i] = ln[:strings.IndexByte(ln, ':')] + ": <redacted>"
		case strings.HasPrefix(lower, "x-super-properties:"):
			lines[i] = "X-Super-Properties: <redacted>"
		case strings.HasPrefix(lower, "cookie:"):
			lines[i] = "Cookie: <redacted>"
		}
	}
	return strings.Join(lines, "\r\n")
}

func durStr(d time.Duration) string {
	us := d.Microseconds()
	if us < 1000 {
		return fmt.Sprintf("%dµs", us)
	}
	return fmt.Sprintf("%.2fms", float64(us)/1000)
}

// Claimer owns the claim hot path for one target. It pre-arms a pool of
// persistent "sentry" goroutines — one per burst worker — that each hold a warm
// TLS conn and block on a broadcast signal. When the gateway reports the vanity
// is available, the claimer publishes the pre-built PATCH bytes once (atomic
// store) and closes the fire channel: every sentry wakes simultaneously and
// writes its conn immediately, with NO pool lock, NO liveness probe, NO
// goroutine spawn, and NO template build on the critical line between event
// arrival and wire write.
//
// Sentries are partitioned across one or more connection pools (one per proxy),
// so when multiple proxies are configured the burst fires from every IP at once
// — the #1 win for stealing a dropped vanity (anti-abuse throttles per-IP;
// different routes have different RTT; residential proxies look like real users).
type Claimer struct {
	target  *Target
	cfg     *Conf
	pools   []*ConnPool // one per proxy entry (pools[0] is always the direct pool)
	mfa     *MFAHandler
	stats   *Stats
	webhook *WebhookSender
	rateLim *RateLimiter
	guard   *Guard

	available chan time.Time
	stop      chan struct{}
	done      chan struct{}

	// Latency-span scratch fields for the in-flight episode. Set in tryClaim
	// (carrying the frame-arrival T0 from the gateway), read in
	// fireFirstSuccess → buildSample. Single-writer (the Run goroutine) except
	// epT2/epT3, which are written by the winning sentry inside fireFirstSuccess
	// (guarded by firstSuccessOnce). No separate mutex: firstSuccessOnce is the
	// happens-before edge.
	epT0 time.Time // frame arrival (from gateway via available chan)
	epT1 time.Time // fire() close (set inside fire())
	epT2 time.Time // winning sentry conn.Write return
	epT3 time.Time // winning sentry first-200 read

	// burstCount is the total number of sentry workers. With P pools, each pool
	// gets burstCount/P sentries (remainder to pool 0).
	burstCount int

	// Vanity Guard config (snapshot at construction so the hot path doesn't
	// touch the shared *Conf).
	guardEnabled   bool
	reclaimMax     int
	reclaimBackoff time.Duration

	directMu           sync.Mutex
	directBlockedUntil time.Time

	claimStart time.Time

	// firstSuccessOnce guarantees the success handler runs exactly once per
	// claim episode. See fireFirstSuccess for the full rationale.
	firstSuccessOnce sync.Once
	reclaimMode      bool

	// Pre-armed sentry machinery. Sentries are spawned once at NewClaimer and
	// live for the claimer's lifetime; each owns one warm conn from its assigned
	// pool. fireCh is closed to broadcast a fire; a fresh channel replaces it.
	// currentBytes holds the full PATCH bytes; rebuilt once per token rotation.
	// activeResults is the results channel sentries report to for the in-flight
	// burst; set under fireMu immediately before the fire channel is closed so a
	// sentry that wakes on the close reads a consistent channel.
	fireMu         sync.Mutex
	fireCh         chan struct{}
	activeResults  chan bool
	currentBytes   atomic.Pointer[[]byte]

	// tpl is the PATCH request template (prefix + placeholder MFA slot + suffix),
	// built ONCE at NewClaimer from the immutable target+cfg. publishBytesWithName
	// splices the current MFA token into it via RenderClaimBytesWith — the only
	// per-publish work is a single buffer copy, no strings.Builder, no header
	// re-render. target and cfg do not change for a claimer's lifetime, so this
	// is safe to cache.
	tpl *ClaimRequest

	sentryWG sync.WaitGroup
}

// NewClaimer constructs a Claimer and arms its sentry workers. pools must have
// at least one entry (the direct pool at index 0); subsequent entries are proxy
// pools. Sentries are partitioned round-robin across pools. guard may be nil
// (guard disabled); when non-nil and guardEnabled is set, reclaim() launches
// guard.Quarantine() in parallel with the reclaim burst.
func NewClaimer(t *Target, cfg *Conf, pools []*ConnPool, mfa *MFAHandler, stats *Stats, wh *WebhookSender, rl *RateLimiter, burstCount int, guardEnabled bool, reclaimMax int, reclaimBackoffMS int, guard *Guard) *Claimer {
	burst := burstCount
	if burst < 1 {
		// Default to 3 parallel attempts. Higher bursts (5+) look non-human to
		// Discord's anti-abuse layer — a real client issues ONE PATCH per user
		// action. 3 is a compromise: enough to win a race against a single
		// competitor while staying under the burst threshold that triggers the
		// 403/10008 anti-abuse block. Operators who want more can set
		// burst_count in config, but should be aware >5 raises the block risk.
		burst = 3
	}
	max := reclaimMax
	if max < 1 {
		max = 5
	}
	backoff := time.Duration(reclaimBackoffMS) * time.Millisecond
	if backoff <= 0 {
		backoff = 500 * time.Millisecond
	}
	if len(pools) == 0 {
		// Defensive: orchestrator always passes at least the direct pool.
		pools = []*ConnPool{{addr: "discord.com:443"}}
	}

	c := &Claimer{
		target:         t,
		cfg:            cfg,
		pools:          pools,
		mfa:            mfa,
		stats:          stats,
		webhook:        wh,
		rateLim:        rl,
		guard:          guard,
		tpl:            BuildClaimRequest(t, cfg),
		available:      make(chan time.Time, 10),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
		burstCount:     burst,
		guardEnabled:   guardEnabled,
		reclaimMax:     max,
		reclaimBackoff: backoff,
		fireCh:         make(chan struct{}),
	}

	c.armSentries()
	return c
}

// armSentries spawns burstCount persistent sentry goroutines, partitioned
// round-robin across the configured pools. Each sentry grabs one warm conn from
// its pool at arm time and blocks on the fire channel; on fire it writes the
// current pre-built bytes, reports the result, then refreshes its conn and
// re-blocks on the next fire channel.
func (c *Claimer) armSentries() {
	for i := 0; i < c.burstCount; i++ {
		pool := c.pools[i%len(c.pools)]
		c.sentryWG.Add(1)
		go c.sentry(pool)
	}
}

// fire broadcasts a claim to all sentries by closing the current fire channel
// and replacing it with a fresh one. Returns the channel the sentries will
// report results on. The caller must drain exactly burstCount results.
func (c *Claimer) fire() chan bool {
	results := make(chan bool, c.burstCount)
	c.fireMu.Lock()
	fire := c.fireCh
	c.fireCh = make(chan struct{})
	// Publish the results channel under the same lock window as the fire swap,
	// and BEFORE closing fire, so a sentry that wakes on the close reads a
	// consistent results channel.
	c.activeResults = results
	c.fireMu.Unlock()
	c.epT1 = time.Now() // T1: fire broadcast (bytes published, sentries about to wake)
	close(fire)
	return results
}

// sentry is a persistent claim worker. It owns one warm conn and loops:
// block on fire → write current bytes → read response → report result →
// refresh conn → re-block. It lives for the claimer's lifetime, so the fire
// path is: read atomic bytes → conn.Write. No spawn, no pool lock, no template
// build on the critical line.
//
// Held-conn staleness: a sentry grabs its warm conn at arm time and holds it
// idle until the next fire. Cloudflare silently half-closes idle TLS conns
// after ~15s (the kernel still accepts the Write, but the server discards it
// and the read returns EOF with no HTTP status — the "empty response" symptom).
// The cold-start window alone (pool warm-up + gateway READY + MFA solve) is
// ~15s, so every first-claim burst used to hit a stale conn. isConnAlive can't
// detect this (a half-closed conn is open locally → probe times out → "alive").
//
// Fix: track connAcquiredAt and refresh the held conn if it's been idle longer
// than maxIdleAge (10s, comfortably under the ~15s server limit). The refresh
// runs on the wake→write path but ONLY when the conn is actually stale — after
// the first claim, runOnce replaces the conn via pool.Get() on retry, so
// connAcquiredAt is freshly stamped and steady-state fires skip the refresh
// (time.Since < maxIdleAge). The zero-lock hot path is preserved in steady
// state; the cost is paid only on cold start where a stale conn is guaranteed.
func (c *Claimer) sentry(pool *ConnPool) {
	defer c.sentryWG.Done()

	// Grab the initial warm conn. A failure here is non-fatal — the sentry will
	// dial fresh on demand inside runOnce when the conn is nil.
	conn, _ := pool.Get()
	connAcquiredAt := time.Now()

	// Track the fire channel we're currently blocked on so we can detect when a
	// new fire has been issued (channel changed) versus a stale wakeup.
	c.fireMu.Lock()
	fire := c.fireCh
	c.fireMu.Unlock()

	for {
		// Block until fired or stopped. A close(fire) wakes all sentries at once.
		select {
		case <-fire:
		case <-c.stop:
			if conn != nil {
				conn.Close()
			}
			return
		}

		// Read the results channel for this burst under the lock (consistent
		// with the fire swap in fire()).
		c.fireMu.Lock()
		results := c.activeResults
		c.fireMu.Unlock()

		// HOT PATH: atomic load of pre-built bytes, then immediate write. No
		// lock, no probe, no allocation between wake and wire.
		bytesPtr := c.currentBytes.Load()
		if bytesPtr == nil || len(*bytesPtr) == 0 {
			// No bytes published (e.g. MFA token not ready at fire time). Report
			// failure so the episode's drain count is correct.
			if results != nil {
				results <- false
			}
			// Re-arm on the latest fire channel and wait for the next fire.
			c.fireMu.Lock()
			fire = c.fireCh
			c.fireMu.Unlock()
			continue
		}
		reqBuf := *bytesPtr

		// Ensure we have a conn. If the previous one was spent/closed, grab a
		// fresh warm one now. This is OFF the critical wake→write line for the
		// common case (conn is warm from the previous cycle).
		if conn == nil {
			conn, _ = pool.Get()
			connAcquiredAt = time.Now()
		}

		// Held-conn staleness guard: if the conn has been idle longer than
		// maxIdleAge, Cloudflare has almost certainly half-closed it server-side.
		// The isConnAlive probe below cannot detect this (the conn is still open
		// locally), so we refresh by AGE first. This is the cold-start fix: a
		// sentry armed at startup holds its conn across pool warm-up + gateway
		// READY + MFA solve (~15s), which exceeds the ~15s server idle limit.
		// Steady-state fires see a conn freshly replaced by runOnce's retry, so
		// time.Since(connAcquiredAt) is small and this branch is skipped.
		if conn != nil && time.Since(connAcquiredAt) > maxIdleAge {
			conn.Close()
			conn, _ = pool.Get()
			connAcquiredAt = time.Now()
		}

		// Defense in depth: probe the held conn right before writing. This
		// catches conns the server hard-reset (RST/EOF) — a disjoint failure
		// mode from the idle half-close above, which the age guard already
		// handles. The O(1) past-deadline probe (see isConnAlive) costs
		// ~nothing on the hot path.
		if conn != nil && !isConnAlive(conn) {
			conn.Close()
			conn, _ = pool.Get()
			connAcquiredAt = time.Now()
		}

		ok := c.runOnce(pool, &conn, reqBuf, 0)

		// runOnce may have replaced conn on a retry (pool.Get on fresh conn).
		// Re-stamp the acquisition time so the staleness guard above reflects
		// the conn we actually hold, not the one we entered with.
		if conn == nil {
			// conn was closed and not replaced; the next loop iteration's
			// nil-check will re-acquire and stamp.
		} else {
			connAcquiredAt = time.Now()
		}

		// Report the result for this burst (if a results channel is registered).
		if results != nil {
			results <- ok
		}

		// Re-arm on the latest fire channel for the next burst.
		c.fireMu.Lock()
		fire = c.fireCh
		c.fireMu.Unlock()
	}
}

// runOnce performs one claim attempt on conn. It writes reqBuf, reads the
// response, classifies it, and on success fires the first-success handler. On
// transient failure (429/60003) it solves MFA and retries on a fresh conn from
// pool. The conn pointer is updated in place (caller-owned) so the sentry's
// conn state stays correct across retries.
//
// conn is *Conn (a pointer-to-pointer in the sentry so it can be replaced on
// retry); reqBuf is the pre-built PATCH bytes.
func (c *Claimer) runOnce(pool *ConnPool, connPtr *Conn, reqBuf []byte, attempt int) bool {
	conn := *connPtr
	rlKey := c.target.GuildID

	if conn == nil {
		c.stats.AddError()
		return false
	}

	// Only gate on the rate limiter for retries (the 429-retry path). The first
	// attempt's burst fires N workers against a fresh bucket simultaneously;
	// having them serialize through Wait() adds mutex contention with zero
	// benefit.
	if attempt > 0 {
		c.rateLim.Wait(rlKey)
	}

	// One deadline covers both Write and the read loop. Set once, not per Read.
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// DEBUG: dump the exact claim bytes once (env-gated) so a malformed request
	// can be compared byte-for-byte against a known-good browser capture. This is
	// the decisive diagnostic for the 403/10008 "Unknown Message" failures: if
	// the bytes here differ from a working PATCH in any structural way (header
	// order, missing header, CRLF placement, body), that's the bug. Token and MFA
	// JWT values are redacted; everything else (request line, header names,
	// cookie names, body, CRLF structure) is shown verbatim.
	if claimBytesDebug && attempt == 0 && atomic.LoadUint32(&claimBytesDumped) == 0 {
		atomic.StoreUint32(&claimBytesDumped, 1)
		log.Printf("[claim %s] === DEBUG: first claim request bytes (%d) ===\n%s",
			c.target.Vanity, len(reqBuf), redactedRequest(reqBuf))
	}

	if _, err := conn.Write(reqBuf); err != nil {
		c.stats.AddError()
		log.Printf("[claim %s] Write failed (attempt %d): %v", c.target.Vanity, attempt, err)
		conn.Close()
		*connPtr = nil
		// A Write failure on the first attempt is almost always a stale pooled
		// conn. Retry once on a fresh connection.
		if attempt == 0 {
			fresh, ferr := pool.Get()
			if ferr == nil {
				*connPtr = fresh
				return c.runOnce(pool, connPtr, reqBuf, attempt+1)
			}
		}
		return false
	}

	// T2: bytes on the wire (per-sentry; the winning sentry's T2 is what counts
	// for the latency breakdown). Set now so it's available if this is the winning
	// attempt. A syscall-level Write returns after kernel accept, not after the
	// packet hits the wire — that's fine; it measures our side of the RTT.
	writeDone := time.Now()

	var resp []byte
	readBuf := respBufPool.Get().([]byte)
	bodyLen := -1
	curr := conn
	for {
		n, err := curr.Read(readBuf)
		if n > 0 {
			resp = append(resp, readBuf[:n]...)
		}
		if err != nil {
			break
		}
		if bodyLen < 0 {
			bodyLen = contentLength(resp)
		}
		headerEnd := bytes.Index(resp, []byte("\r\n\r\n"))
		if headerEnd < 0 {
			continue
		}
		isChunked := bytes.Contains(resp, []byte("Transfer-Encoding: chunked"))
		if isChunked {
			if bytes.Contains(resp, []byte("\r\n0\r\n")) {
				break
			}
		} else if bodyLen >= 0 {
			bodyReceived := len(resp) - headerEnd - 4
			if bodyReceived >= bodyLen {
				break
			}
		} else {
			break
		}
	}
	respBufPool.Put(readBuf)

	// Empty response: server closed the idle pooled conn before we read. Close,
	// then retry once on a fresh conn so a poisoned pool entry doesn't lose the
	// burst.
	if len(resp) == 0 {
		c.stats.AddError()
		log.Printf("[claim %s] empty response (attempt %d)", c.target.Vanity, attempt)
		conn.Close()
		*connPtr = nil
		if attempt == 0 {
			fresh, ferr := pool.Get()
			if ferr == nil {
				*connPtr = fresh
				return c.runOnce(pool, connPtr, reqBuf, attempt+1)
			}
		}
		return false
	}

	statusCode := parseStatusCode(resp)
	statusOK := statusCode == 200 || statusCode == 204

	// T3: response fully read. Stamp the episode T2/T3 so fireFirstSuccess can
	// build the latency sample. On retries (attempt > 0) we still overwrite —
	// only the winning sentry's call to fireFirstSuccess reads these, and
	// firstSuccessOnce guarantees exactly one winner.
	c.epT2 = writeDone
	c.epT3 = time.Now()

	conn.Close()
	*connPtr = nil

	if statusOK {
		// AUTHORITATIVE success gate: a 2xx from PATCH /vanity-url means Discord
		// accepted the claim. (Body can be {"code":null} on a 200, so we don't
		// gate on the body echoing the target code.)
		c.fireFirstSuccess(true)
		return true
	}

	// ---- Failure paths (only here, off the snipe-critical line) ----
	responseBody := extractBody(resp)
	statusLine := extractStatusLine(resp)
	vanityMatch := bytes.Contains(resp, []byte(`"code":"`+c.target.Vanity+`"`))
	has429 := statusCode == 429
	has60003 := bytes.Contains(resp, []byte(`"code":60003`))

	log.Printf("[claim %s] attempt %d — status: %s body: %s", c.target.Vanity, attempt, statusLine, responseBody)

	if has429 {
		log.Printf("[claim %s] rate limited (429, attempt %d)", c.target.Vanity, attempt)
		headers := parseHeaders(resp)
		c.rateLim.HandleResponse(rlKey, headers)
		isDirect := pool.proxy == ""
		if isDirect && isGlobal429(resp) {
			c.blockDirect()
		}

		ticket, _ := extractTicket(resp)
		if ticket != "" {
			log.Printf("[claim %s] found MFA ticket in 429 response, solving...", c.target.Vanity)
			c.handleMFAChallenge(ticket)
		}

		if attempt < 3 {
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
			c.rateLim.Wait(rlKey)
			// Reload bytes: the solve above may have rotated the token.
			bytesPtr := c.currentBytes.Load()
			if bytesPtr == nil || len(*bytesPtr) == 0 {
				return false
			}
			fresh, ferr := pool.Get()
			if ferr != nil {
				return false
			}
			*connPtr = fresh
			return c.runOnce(pool, connPtr, *bytesPtr, attempt+1)
		}
	}

	if has60003 {
		cookies := extractSetCookies(resp)
		c.mfa.setTicketCookies(cookies)

		ticket, _ := extractTicket(resp)
		if ticket != "" {
			log.Printf("[claim %s] MFA required (60003), solving...", c.target.Vanity)
			c.handleMFAChallenge(ticket)
			if attempt < 3 {
				// Retry on a FRESH connection with the freshly solved token.
				bytesPtr := c.currentBytes.Load()
				if bytesPtr == nil || len(*bytesPtr) == 0 {
					return false
				}
				fresh, ferr := pool.Get()
				if ferr != nil {
					return false
				}
				*connPtr = fresh
				return c.runOnce(pool, connPtr, *bytesPtr, attempt+1)
			}
		}
	}

	if !statusOK && !has429 && !has60003 {
		if vanityMatch {
			log.Printf("[claim %s] body echoed vanity but status was %s — treating as failure", c.target.Vanity, statusLine)
		}
		log.Printf("[claim %s] unexpected response — status: %s body: %s", c.target.Vanity, statusLine, responseBody)
		headerEnd := bytes.Index(resp, []byte("\r\n\r\n"))
		if headerEnd > 0 {
			headerBlock := string(resp[:headerEnd])
			for _, line := range strings.Split(headerBlock, "\r\n") {
				if strings.HasPrefix(line, "X-") || strings.HasPrefix(line, "x-") || strings.HasPrefix(line, "cf-") || strings.HasPrefix(line, "Set-Cookie") || strings.HasPrefix(line, "set-cookie") {
					log.Printf("[claim %s] response header: %s", c.target.Vanity, line)
				}
			}
		}
	}

	return false
}

// publishBytes rebuilds the full claim PATCH bytes for the current MFA token and
// atomically publishes them so all sentries read the same bytes on the next
// fire. Called once before each burst (and after any MFA solve that rotates the
// token). Returns false if no usable token is available.
//
// This is the "no header in hand" entry point: it fetches the MFA header itself.
// Callers that already have the header (firstClaim, reclaim) should call
// publishBytesWithName to avoid a redundant GetHeader mutex acquire.
func (c *Claimer) publishBytes() bool {
	mfaName, mfaValue := c.mfa.GetHeader()
	return c.publishBytesWithName(mfaName, mfaValue)
}

// publishBytesWithName renders the claim PATCH from the cached template and
// atomically publishes it. The hot-path callers (firstClaim, reclaim) already
// fetched the header for their token-ready gate check, so passing it here skips
// a second GetHeader mutex acquire on every publish — one less lock per claim
// episode. Returns false if the template is missing or no usable token was
// supplied (caller must bail rather than fire a bare PATCH, which Discord's
// anti-abuse filter rejects with 403/10008).
func (c *Claimer) publishBytesWithName(mfaName, mfaValue string) bool {
	buf := RenderClaimBytesWith(c.tpl, mfaName, mfaValue)
	if buf == nil {
		return false
	}
	c.currentBytes.Store(&buf)
	return true
}

func (c *Claimer) SignalAvailable() {
	select {
	case c.available <- time.Now():
	default:
	}
}

func (c *Claimer) Run() {
	defer close(c.done)

	for {
		select {
		case t0 := <-c.available:
			c.tryClaim(t0)
		case <-c.stop:
			return
		}
	}
}

func (c *Claimer) tryClaim(t0 time.Time) {
	c.epT0 = t0
	c.target.mu.Lock()
	claimed := c.target.claimed
	guardArmed := c.target.guardArmed
	lost := c.target.lost
	c.target.mu.Unlock()

	if !claimed {
		// First claim: the vanity is free (or never held). Normal flow.
		c.firstClaim()
		return
	}

	// Already claimed. Without Vanity Guard this is a no-op — the original
	// behavior was `if claimed { return }`, silently dropping every later
	// availability signal. That meant a competitor stealing the vanity back was
	// never re-claimed even though the gateway still fires GUILD_UPDATE.
	if !c.guardEnabled || !guardArmed || lost {
		return
	}

	// Vanity Guard: a GUILD_UPDATE showed the guild's vanity is no longer ours
	// (the gateway only signals available when VanityURLCode != target). Reclaim it.
	c.reclaim()
}

// firstClaim is the hot-path entry point: the gateway just signaled that our
// guild's vanity is no longer the target, so the target code is now up for
// grabs.
//
// What we do NOT do here (and why) — see the prior implementation's doc comment
// for the full rationale: no isVanityGloballyFree() pre-flight (saves a 200-
// 400ms GET RTT), no verifyClaim() after (the 200 is authoritative), and MFA is
// kept warm by the pre-solver with a synchronous fallback only on cold start.
func (c *Claimer) firstClaim() {
	c.claimStart = time.Now()
	c.resetSuccessGate(false)
	log.Printf("[claim %s] vanity available! claiming...", c.target.Vanity)

	// On cold start the MFA pre-solver may not have produced a token yet. We
	// MUST have a valid MFA token before firing — a bare PATCH returns
	// 403/10008, not the 60003 ticket we'd need for a retry.
	//
	// We thread both name AND value through to publishBytesWithName so the
	// publish step skips a second GetHeader mutex acquire — one less lock on
	// the wake→wire path. The value is only valid if the token didn't rotate
	// between fetch and publish; publishBytesWithName re-checks via the cached
	// template + the supplied value, and returns false if stale/empty.
	mfaName, mfaValue := c.mfa.GetHeader()
	if mfaName == "" {
		log.Printf("[claim %s] no MFA token cached, waiting up to 15s for pre-solver...", c.target.Vanity)
		mfaName, mfaValue = c.mfa.WaitForToken(15 * time.Second)
	}
	if mfaName == "" {
		log.Printf("[claim %s] pre-solver slow — solving MFA synchronously...", c.target.Vanity)
		if c.mfa.EnsureValid() {
			mfaName, mfaValue = c.mfa.GetHeader()
		}
	}
	if mfaName == "" {
		log.Printf("[claim %s] ❌ could not obtain MFA token — skipping claim (will retry on next signal)", c.target.Vanity)
		return
	}
	log.Printf("[claim %s] MFA token ready, firing burst", c.target.Vanity)

	// Publish the bytes ONCE for all sentries to read atomically. Pass the
	// header we already hold so publishBytesWithName doesn't re-acquire the
	// MFA mutex.
	if !c.publishBytesWithName(mfaName, mfaValue) {
		log.Printf("[claim %s] ❌ could not build claim bytes — skipping (will retry on next signal)", c.target.Vanity)
		return
	}

	c.runBurst()
}

// runBurst fires all sentries and drains their results. Returns true if any
// worker reported a 200. Shared by firstClaim and reclaim. The first 200 fires
// the success handler inside runOnce (via fireFirstSuccess) so the operator is
// notified before the remaining sentries drain.
func (c *Claimer) runBurst() bool {
	results := c.fire()
	success := false
	for i := 0; i < c.burstCount; i++ {
		if ok := <-results; ok {
			success = true
			// Don't break: drain remaining sentries so we don't deadlock them
			// (they each do one buffered send per fire).
		}
	}
	return success
}

// reclaim defends an already-claimed vanity that a GUILD_UPDATE reported as
// lost. Runs up to reclaimMax bursts, each firing the sentries with whatever
// MFA token is currently cached. In parallel (guard enabled), launches the
// Vanity Guard quarantine so the offender is neutralized while we race to
// revert — the quarantine never delays the snipe because it runs in its own
// goroutine.
func (c *Claimer) reclaim() {
	c.target.mu.Lock()
	episodeStart := c.target.reclaimAttempts == 0
	attemptNum := c.target.reclaimAttempts
	c.target.mu.Unlock()

	if episodeStart {
		log.Printf("[guard %s] 🚨 vanity lost! reclaiming (max %d attempts)...", c.target.Vanity, c.reclaimMax)
		c.webhook.Send("🚨 Vanity Lost!", 0xFF0000, map[string]string{
			"Vanity": "discord.gg/" + c.target.Vanity,
			"Guild":  c.target.GuildID,
			"Max":    fmt.Sprintf("%d", c.reclaimMax),
			"Time":   time.Now().Format(time.RFC3339),
		})

		// Launch the guard quarantine in parallel with the reclaim burst. The
		// audit-log fetch + kick/ban are independent of the PATCH race, so they
		// never delay the snipe. nil-guard (guard disabled) is a no-op.
		if c.guard != nil {
			go c.guard.Quarantine()
		}
	} else {
		log.Printf("[guard %s] reclaim attempt %d/%d", c.target.Vanity, attemptNum+1, c.reclaimMax)
	}

	c.claimStart = time.Now()
	c.resetSuccessGate(true)

	for attempt := 0; attempt < c.reclaimMax; attempt++ {
		// Thread the header value through to publishBytesWithName so the
		// publish step skips a redundant GetHeader mutex acquire — one less
		// lock per reclaim attempt.
		mfaName, mfaValue := c.mfa.GetHeader()
			if mfaName == "" {
				mfaName, mfaValue = c.mfa.WaitForToken(10 * time.Second)
			}
			if mfaName == "" {
				if c.mfa.EnsureValid() {
					mfaName, mfaValue = c.mfa.GetHeader()
				}
			}
		if mfaName == "" {
			log.Printf("[guard %s] no MFA token, skipping reclaim attempt %d", c.target.Vanity, attempt+1)
			continue
		}

		c.target.mu.Lock()
		c.target.reclaimAttempts = attempt + 1
		c.target.mu.Unlock()

		// Publish fresh bytes for this attempt (token may have rotated).
		if !c.publishBytesWithName(mfaName, mfaValue) {
			log.Printf("[guard %s] could not build claim bytes, skipping attempt %d", c.target.Vanity, attempt+1)
			continue
		}

		ok := c.runBurst()
		if ok {
			return
		}

		// Back off before the next attempt (skip after the last one).
		if attempt < c.reclaimMax-1 {
			select {
			case <-time.After(c.reclaimBackoff):
			case <-c.stop:
				return
			}
		}
	}

	// Cap exhausted without recovery. Mark lost so further signals are dropped.
	c.target.mu.Lock()
	c.target.lost = true
	c.target.mu.Unlock()
	c.stats.AddLoss()

	log.Printf("[guard %s] ⛔ guard exhausted after %d attempts — giving up", c.target.Vanity, c.reclaimMax)
	c.webhook.Send("⛔ Guard Exhausted", 0x8B0000, map[string]string{
		"Vanity":   "discord.gg/" + c.target.Vanity,
		"Guild":    c.target.GuildID,
		"Attempts": fmt.Sprintf("%d", c.reclaimMax),
		"Time":     time.Now().Format(time.RFC3339),
	})
}

// reclaimSuccess handles a successful re-claim after a loss episode.
func (c *Claimer) reclaimSuccess(latency time.Duration) {
	c.target.mu.Lock()
	c.target.reclaimAttempts = 0
	c.target.lost = false
	c.target.mu.Unlock()

	c.stats.AddReclaim()

	log.Printf("[guard %s] 🛡️ re-claimed! discord.gg/%s (%dms)", c.target.Vanity, c.target.Vanity, latency.Milliseconds())
	c.webhook.Send("🛡️ Vanity Re-claimed!", 0x00CCFF, map[string]string{
		"Vanity":  "discord.gg/" + c.target.Vanity,
		"Guild":   c.target.GuildID,
		"Latency": fmt.Sprintf("%dms", latency.Milliseconds()),
		"Time":    time.Now().Format(time.RFC3339),
	})
}

func (c *Claimer) claimSuccess() {
	latency := time.Since(c.claimStart)
	c.target.mu.Lock()
	c.target.claimed = true
	if c.guardEnabled {
		c.target.guardArmed = true
		c.target.reclaimAttempts = 0
		c.target.lost = false
	}
	c.target.mu.Unlock()

	c.stats.AddClaim()

	guardNote := ""
	if c.guardEnabled {
		guardNote = " | guard armed"
	}
	log.Printf("[claim %s] ✅ SNIPED! discord.gg/%s (%dms%s)", c.target.Vanity, c.target.Vanity, latency.Milliseconds(), guardNote)
	c.webhook.Send("✅ Vanity Sniped!", 0x00FF00, map[string]string{
		"Vanity":  "discord.gg/" + c.target.Vanity,
		"Guild":   c.target.GuildID,
		"Latency": fmt.Sprintf("%dms", latency.Milliseconds()),
		"Time":    time.Now().Format(time.RFC3339),
	})
}

// fireFirstSuccess reports a claim landing exactly once per claim episode. Builds
// the latency breakdown sample (T0→T1→T2→T3) from the episode scratch fields
// and records it in the stats tracker for the dashboard p50/p99.
func (c *Claimer) fireFirstSuccess(success bool) {
	if !success {
		return
	}
	c.firstSuccessOnce.Do(func() {
		if c.epT0 != (time.Time{}) && c.epT3 != (time.Time{}) {
			sample := latSample{
				dispatch: c.epT1.Sub(c.epT0), // gateway decode → fire publish
				local:    c.epT2.Sub(c.epT1), // fire close → conn.Write return
				rtt:      c.epT3.Sub(c.epT2), // Write return → first 200 read
				total:    c.epT3.Sub(c.epT0), // frame arrival → claim landed
			}
			c.stats.RecordLatency(sample)

			if latencyDebug {
				log.Printf("[latency %s] dispatch=%s local=%s rtt=%s total=%s",
					c.target.Vanity,
					durStr(sample.dispatch), durStr(sample.local),
					durStr(sample.rtt), durStr(sample.total))
			}
		}
		if c.reclaimMode {
			c.reclaimSuccess(time.Since(c.claimStart))
		} else {
			c.claimSuccess()
		}
	})
}

func (c *Claimer) resetSuccessGate(reclaim bool) {
	c.firstSuccessOnce = sync.Once{}
	c.reclaimMode = reclaim
}

func (c *Claimer) handleMFAChallenge(ticket string) {
	// Try TOTP first (primary method for accounts with TOTP enabled)
	if c.mfa.totpSecret != "" {
		log.Printf("[mfa %s] solving ticket via totp", c.target.Vanity)
		token, expiresIn, err := c.mfa.solveTOTP(ticket)
		if err == nil && token != "" {
			c.mfa.SetToken(token, expiresIn)
			// Re-publish bytes with the fresh token so any in-flight or next
			// burst reads the new token via atomic load.
			c.publishBytes()
			return
		}
		log.Printf("[mfa %s] totp failed: %v", c.target.Vanity, err)
	}

	// Try backup codes if available
	if len(c.mfa.backupCodes) > 0 {
		log.Printf("[mfa %s] solving ticket via backup code", c.target.Vanity)
		token, expiresIn, err := c.mfa.solveBackup(ticket)
		if err == nil && token != "" {
			c.mfa.SetToken(token, expiresIn)
			c.publishBytes()
			return
		}
		log.Printf("[mfa %s] backup failed: %v", c.target.Vanity, err)
	}

	// Fall back to password if available
	if c.mfa.autoSolve {
		log.Printf("[mfa %s] solving ticket via password", c.target.Vanity)
		sp, ua, ck := c.mfa.getSolveHeaders()
		token, expiresIn, err := solveTicket(ticket, c.mfa.password, c.target.Token, sp, ua, ck)
		if err == nil && token != "" {
			c.mfa.SetToken(token, expiresIn)
			c.publishBytes()
			return
		}
		log.Printf("[mfa %s] password failed: %v", c.target.Vanity, err)
	}
}

func (c *Claimer) blockDirect() {
	c.directMu.Lock()
	c.directBlockedUntil = time.Now().Add(60 * time.Second)
	c.directMu.Unlock()
	log.Printf("[claim %s] rate limited on direct, blocking 60s", c.target.Vanity)
}

func (c *Claimer) isDirectBlocked() bool {
	c.directMu.Lock()
	blocked := time.Now().Before(c.directBlockedUntil)
	c.directMu.Unlock()
	return blocked
}

func (c *Claimer) Stop() {
	close(c.stop)
	// Don't wait on sentryWG here: sentries select on c.stop and will exit on
	// their own; waiting could deadlock if a sentry is mid-Write. The done
	// channel (closed by Run on stop) is the join point the orchestrator waits on.
	<-c.done
}

func extractStatusLine(resp []byte) string {
	end := bytes.IndexByte(resp, '\r')
	if end < 0 {
		return "unknown"
	}
	return string(resp[:end])
}

// parseStatusCode extracts the numeric HTTP status code from the status line.
func parseStatusCode(resp []byte) int {
	sp := bytes.IndexByte(resp, ' ')
	if sp < 0 {
		return 0
	}
	rest := resp[sp+1:]
	end := bytes.IndexByte(rest, ' ')
	if end < 0 {
		if end = bytes.IndexByte(rest, '\r'); end < 0 {
			return 0
		}
	}
	code, err := strconv.Atoi(string(rest[:end]))
	if err != nil {
		return 0
	}
	return code
}

func isStatusOK(resp []byte) bool {
	c := parseStatusCode(resp)
	return c >= 200 && c < 300
}

// buildCookieHeader assembles the Cookie header value for the claim PATCH from
// the configured device identity and any cookies captured during the MFA solve.
func buildCookieHeader(dcfDuid, sdcfDuid, ticketCookies string) string {
	merged := make(map[string]string)
	if dcfDuid != "" {
		merged["__dcfduid"] = dcfDuid
	}
	if sdcfDuid != "" {
		merged["__sdcfduid"] = sdcfDuid
	}
	for _, part := range strings.Split(ticketCookies, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		merged[strings.TrimSpace(part[:eq])] = strings.TrimSpace(part[eq+1:])
	}
	if len(merged) == 0 {
		return ""
	}
	var names []string
	for n := range merged {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s=%s", n, merged[n])
	}
	return b.String()
}

func extractBody(resp []byte) string {
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return ""
	}
	body := bytes.TrimSpace(resp[idx+4:])
	if len(body) > 300 {
		return string(body[:300]) + "..."
	}
	return string(body)
}

func parseHeaders(resp []byte) []string {
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil
	}
	headerBlock := resp[:idx]
	lines := bytes.Split(headerBlock, []byte("\r\n"))

	var result []string
	for _, line := range lines {
		if bytes.Contains(line, []byte(":")) {
			result = append(result, string(line))
		}
	}
	return result
}

func contentLength(resp []byte) int {
	idx := bytes.Index(resp, []byte("Content-Length: "))
	if idx < 0 {
		idx = bytes.Index(resp, []byte("content-length: "))
		if idx < 0 {
			return -1
		}
	}
	start := idx + 16
	end := bytes.Index(resp[start:], []byte("\r\n"))
	if end < 0 {
		return -1
	}
	n, err := strconv.Atoi(string(resp[start : start+end]))
	if err != nil {
		return -1
	}
	return n
}

func isGlobal429(resp []byte) bool {
	return bytes.Contains(resp, []byte("X-RateLimit-Global: true")) ||
		bytes.Contains(resp, []byte("x-ratelimit-global: true")) ||
		bytes.Contains(resp, []byte(`"global":true`))
}
