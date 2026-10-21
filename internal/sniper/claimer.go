package sniper

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime/debug"
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
// Sentries are partitioned round-robin across one or more connection pools (one
// per proxy). burstCount is the hard cap on simultaneous PATCH writes, so when
// burstCount is at least the pool count every proxy fires at once; when it is
// smaller, only pools 0..burstCount-1 receive a sentry and the remaining pools
// stay idle. Firing from multiple IPs is the #1 win for stealing a dropped
// vanity (anti-abuse throttles per-IP; different routes have different RTT;
// residential proxies look like real users).
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
	// (carrying the frame-arrival T0 from the gateway) and fire(), then read in
	// fireFirstSuccess. They are written before the sentry wake, so the channel
	// send is the happens-before edge; T2/T3 are passed by the winning sentry as
	// arguments rather than stored here, because several sentries race and only
	// the winner's timestamps may be used.
	epT0 time.Time // frame arrival (from gateway via available chan)
	epT1 time.Time // fire() close (set inside fire())

	// burstCount is the total number of sentry workers and the hard cap on
	// simultaneous PATCH writes. Sentries are assigned round-robin: with P pools,
	// pool i receives a sentry iff i < burstCount. Pools at index >= burstCount
	// never fire.
	burstCount int

	// Vanity Guard config (snapshot at construction so the hot path doesn't
	// touch the shared *Conf).
	guardEnabled   bool
	reclaimMax     int
	reclaimBackoff time.Duration

	directMu           sync.Mutex
	directBlockedUntil time.Time

	// solveMu single-flights MFA ticket solves across the burst's sentries;
	// lastSolvedTicket dedupes repeats of the same challenge.
	solveMu          sync.Mutex
	lastSolvedTicket string

	claimStart time.Time

	// firstSuccessOnce guarantees the success handler runs exactly once per
	// claim episode. See fireFirstSuccess for the full rationale.
	firstSuccessOnce sync.Once
	reclaimMode      bool

	// Fire mechanism: each sentry has its own buffered wake channel. fire()
	// enqueues exactly one token per sentry, so a fast sentry can never consume
	// another sentry's wake (a shared token pool had exactly that bug). Sentries
	// block instead of busy-spinning and report results over resultCh, which
	// runBurst drains. No channel is allocated per fire and no wake is lost if a
	// sentry has not reached its receive yet.
	sentryWake   []chan struct{}
	resultCh     chan int32
	currentBytes atomic.Pointer[[]byte]

	// fallbackBytes holds pre-built PATCH bytes for the legacy dual-endpoint
	// fallback (PATCH /api/v9/guilds/{id} with duplicate keys). Published
	// alongside currentBytes by the background publish goroutine. Sentries try
	// the fallback when the primary endpoint returns 10008/404/400.
	currentFallbackBytes atomic.Pointer[[]byte]

	// tpl is the PATCH request template (prefix + placeholder MFA slot + suffix).
	// It is initially built at NewClaimer, then re-derived by ensureTemplate at
	// Run time from the target's FINAL vanity name (the name may be supplied or
	// changed by the entry point after construction). publishBytesWithName
	// splices the current MFA token into it via RenderClaimBytesWith — the only
	// per-publish work is a single buffer copy, no strings.Builder, no header
	// re-render.
	//
	// tplMu guards tpl/fallbackTpl/tplVanity against the background publisher,
	// which can run concurrently with ensureTemplate's rebuild.
	tplMu     sync.RWMutex
	tplVanity string
	tpl       *ClaimRequest

	// fallbackTpl is the same concept but for the legacy dual-endpoint PATCH:
	// PATCH /api/v9/guilds/{id} with body {"code":"vanity","vanity_code":"vanity"}.
	// Only used when the primary endpoint returns a non-fatal error.
	fallbackTpl *ClaimRequest

	poller   *Poller
	pollerWG sync.WaitGroup

	sentryWG sync.WaitGroup

	// wireHook is a test/harness seam invoked immediately after a claim PATCH
	// write returns. Production leaves it nil. It lets the latency harness stamp
	// the exact free→wire moment without changing the wire path itself.
	wireHook func()
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
		fallbackTpl:    BuildFallbackClaimRequest(t, cfg),
		tplVanity:      t.Vanity,
		available:      make(chan time.Time, 10),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
		burstCount:     burst,
		sentryWake:     makeSentryWakes(burst),
		resultCh:       make(chan int32, burst),
		guardEnabled:   guardEnabled,
		reclaimMax:     max,
		reclaimBackoff: backoff,
	}

	c.armSentries()
	c.startBackgroundPublish()
	return c
}

// armSentries spawns burstCount persistent sentry goroutines, partitioned
// round-robin across the configured pools. Because the loop is bounded by
// burstCount, extra pools beyond that count get no sentry and never fire; this
// keeps burstCount an honest cap on simultaneous PATCH writes. Each sentry
// grabs one warm conn from its pool at arm time and blocks on the fire channel;
// on fire it writes the current pre-built bytes, reports the result, then
// refreshes its conn and re-blocks on the next fire channel.
func makeSentryWakes(n int) []chan struct{} {
	wakes := make([]chan struct{}, n)
	for i := range wakes {
		wakes[i] = make(chan struct{}, 1)
	}
	return wakes
}

func (c *Claimer) armSentries() {
	for i := 0; i < c.burstCount; i++ {
		pool := c.pools[i%len(c.pools)]
		c.sentryWG.Add(1)
		go c.sentry(pool, c.sentryWake[i])
	}
}

// startPoller launches the GET polling loop in a goroutine. The poller
// monitors the guild's vanity URL independently of the gateway and signals the
// same available channel when the target becomes free. Its 5ms cycle target is
// measured from request start, so a slow link observes once per RTT rather than
// once per RTT+5ms.
func (c *Claimer) startPoller() {
	c.tplMu.RLock()
	ready := c.tpl != nil
	c.tplMu.RUnlock()
	if !ready {
		return
	}
	c.poller = NewPoller(
		c.target,
		c.target.Token,
		c.cfg.Fingerprint.UserAgent,
		c.cfg.Fingerprint.SuperPropsB64,
		c.available,
		c.stop,
	)
	c.poller.stats = c.stats
	c.pollerWG.Add(1)
	go func() {
		defer c.pollerWG.Done()
		c.poller.Run()
	}()
}

// startBackgroundPublish keeps the claim PATCH bytes fresh by re-rendering
// them every time the MFA token is refreshed. Runs in a background goroutine
// so the hot path (firstClaim/reclaim) can fire without calling publishBytes.
//
// The goroutine immediately publishes at startup (if a cached session token
// exists) and re-publishes every 1s thereafter. firstClaim/reclaim still have
// a synchronous fallback: if currentBytes is nil at fire time (cold start
// before any solve completes or before the first tick), they fall through to
// the old GetHeader+WaitForToken+publishBytesWithName synchronous flow.
func (c *Claimer) startBackgroundPublish() {
	go func() {
		// Immediate publish on start: cached token → bytes ready before signal.
		c.publishBytes()

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-c.stop:
				return
			case <-ticker.C:
				c.publishBytes()
			}
		}
	}()
}

// fire wakes every sentry by enqueueing one token on its own channel. Each
// channel is buffered to one and runBurst drains every result before the next
// fire, so the sends never block and no wake is lost. No allocation and no spin
// loop on the wake path.
func (c *Claimer) fire() {
	c.epT1 = time.Now()
	for _, wake := range c.sentryWake {
		wake <- struct{}{}
	}
}

// sentry is a persistent claim worker. It blocks on its own wake channel
// instead of busy-polling, so an idle sniper consumes no CPU and a wake costs
// one buffered send rather than a Gosched round-trip. On wake it reads the
// pre-built bytes, writes them to its warm conn, reads the response, and sends
// its result to runBurst over resultCh. Each sentry has a dedicated channel, so
// a fast sentry cannot steal another sentry's wake.
//
// conn staleness: the age guard (maxIdleAge) refreshes conns idle >10s to avoid
// Cloudflare's silent half-close. It stays on the wake path because a stale
// held conn would lose the shot; the branch is cheap and only the rare refresh
// calls pool.Get().
func (c *Claimer) sentry(pool *ConnPool, wake <-chan struct{}) {
	defer c.sentryWG.Done()

	// Grab the initial warm conn. A failure here is non-fatal — the sentry will
	// dial fresh on demand when conn is nil.
	conn, _ := pool.Get()
	connAcquiredAt := time.Now()

	// Persistent read buffer for this sentry's lifetime.
	readBuf := make([]byte, 4096)

	for {
		// Prefer shutdown over a pending wake.
		select {
		case <-c.stop:
			if conn != nil {
				conn.Close()
			}
			return
		default:
		}

		select {
		case <-c.stop:
			if conn != nil {
				conn.Close()
			}
			return
		case <-wake:
		}

		// One wake→claim cycle; result -1 on panic keeps the burst protocol
		// alive (runBurst waits for exactly one result per sentry).
		result := c.fireOnWake(pool, &conn, &connAcquiredAt, readBuf)

		c.resultCh <- result
	}
}

// fireOnWake performs one wake→claim cycle and contains its own panics.
//
// Containment rationale: runBurst drains EXACTLY one result per sentry, so a
// panic that killed the sentry goroutine would leave runBurst waiting on a
// result that never arrives — the burst stalls until the process is killed.
// And a panic reaching the goroutine's root kills the whole process: fine on an
// interactive desktop, but on a 6-hour unattended Actions-hosted session one
// malformed burst response would end the entire session window. Recovered
// here, a bad cycle costs one wiring error and the pipeline keeps running. The
// conn may have panicked mid-write; it is closed and niled so the next cycle
// re-acquires.
func (c *Claimer) fireOnWake(pool *ConnPool, connPtr *Conn, acquiredAt *time.Time, readBuf []byte) (result int32) {
	conn := *connPtr
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[claim %s] recovered from panic on the claim hot path: %v\n%s",
				c.target.Vanity, r, debug.Stack())
			c.stats.AddError()
			if conn != nil {
				conn.Close()
			}
			*connPtr = nil
			result = -1
		}
	}()

	result = int32(-1)

	// HOT PATH: atomic load of pre-built bytes, then immediate write.
	bytesPtr := c.currentBytes.Load()
	if bytesPtr != nil && len(*bytesPtr) > 0 {
		reqBuf := *bytesPtr

		if conn == nil {
			conn, _ = pool.Get()
			*acquiredAt = time.Now()
		}
		if conn != nil && time.Since(*acquiredAt) > maxIdleAge {
			conn.Close()
			conn, _ = pool.Get()
			*acquiredAt = time.Now()
		}

		ok := c.runOnce(pool, &conn, reqBuf, 0, readBuf)

		// Dual-endpoint fallback: if the primary PATCH to /vanity-url failed
		// with a non-fatal error (10008/404/400), try the legacy endpoint:
		// PATCH /api/v9/guilds/{id} with {"code":"vanity","vanity_code":"vanity"}.
		// This hits an older Discord code path that sometimes accepts the request
		// when the primary endpoint returns generic errors.
		if !ok && c.fallbackTpl != nil {
			fbPtr := c.currentFallbackBytes.Load()
			if fbPtr != nil && len(*fbPtr) > 0 {
				fbBuf := *fbPtr
				if conn == nil {
					conn, _ = pool.Get()
					*acquiredAt = time.Now()
				}
				if conn != nil {
					ok = c.runOnce(pool, &conn, fbBuf, 1, readBuf)
				}
			}
		}

		if conn == nil {
			// closed by runOnce error path; next fire re-acquires
		} else {
			*acquiredAt = time.Now()
		}

		if ok {
			result = 1
		}
	}

	*connPtr = conn
	return result
}

// runOnce performs one claim attempt on conn. It writes reqBuf, reads the
// response, classifies it, and on success fires the first-success handler. On
// transient failure (429/60003) it solves MFA and retries on a fresh conn from
// pool. The conn pointer is updated in place (caller-owned) so the sentry's
// conn state stays correct across retries.
//
// conn is *Conn (a pointer-to-pointer in the sentry so it can be replaced on
// retry); reqBuf is the pre-built PATCH bytes.
func (c *Claimer) runOnce(pool *ConnPool, connPtr *Conn, reqBuf []byte, attempt int, readBuf []byte) bool {
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
				return c.runOnce(pool, connPtr, reqBuf, attempt+1, readBuf)
			}
		}
		return false
	}

	// T2: bytes on the wire (per-sentry; the winning sentry's T2 is what counts
	// for the latency breakdown). Set now so it's available if this is the winning
	// attempt. A syscall-level Write returns after kernel accept, not after the
	// packet hits the wire — that's fine; it measures our side of the RTT.
	writeDone := time.Now()
	if c.wireHook != nil {
		c.wireHook()
	}

	var resp []byte
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
		headerEnd := bytes.Index(resp, []byte("\r\n\r\n"))
		if headerEnd < 0 {
			continue
		}
		if bodyLen < 0 {
			bodyLen = contentLength(resp)
		}
		status := parseStatusCode(resp)
		if status == 200 || status == 204 {
			if bodyLen >= 0 {
				want := headerEnd + 4 + bodyLen
				if len(resp) >= want {
					break
				}
			} else {
				break
			}
			continue
		}
		isChunked := bytes.Contains(resp, []byte("Transfer-Encoding: chunked")) ||
			bytes.Contains(resp, []byte("transfer-encoding: chunked"))
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
				return c.runOnce(pool, connPtr, reqBuf, attempt+1, readBuf)
			}
		}
		return false
	}

	statusCode := parseStatusCode(resp)
	statusOK := statusCode == 200 || statusCode == 204

	// T3: response fully read. Pass T2/T3 to the success handler so the latency
	// sample uses THIS sentry's timestamps; storing them on the Claimer would
	// race with the other sentries in the burst.
	readDone := time.Now()

	if statusOK {
		// HTTP keepalive: Discord sends Connection: keep-alive by default; only
		// close if the response explicitly asks for it. Keeping the conn alive
		// eliminates pool.Get() mutex contention and TLS session resume on the
		// next fire — the sentry reuses the same TCP+TLS conn.
		if !connectionClose(resp) {
			c.fireFirstSuccess(true, writeDone, readDone)
			return true
		}
	}

	// Close the conn for all non-keepalive paths (failure, or server-requested
	// close on success). On failure the sentry's nil-check triggers pool.Get()
	// for a fresh conn on the next fire.
	conn.Close()
	*connPtr = nil

	if statusOK {
		c.fireFirstSuccess(true, writeDone, readDone)
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
			// Wait out the delay Discord stated; the fixed pause applies only when
			// the response states none.
			c.rateLim.WaitRetry(rlKey, resp, attempt)
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
			return c.runOnce(pool, connPtr, *bytesPtr, attempt+1, readBuf)
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
				return c.runOnce(pool, connPtr, *bytesPtr, attempt+1, readBuf)
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
//
// Also publishes the fallback template bytes for the dual-endpoint retry.
func (c *Claimer) publishBytesWithName(mfaName, mfaValue string) bool {
	c.tplMu.RLock()
	tpl := c.tpl
	fallbackTpl := c.fallbackTpl
	c.tplMu.RUnlock()
	if tpl == nil {
		return false
	}

	// If we have an MFA token, publish with the MFA header. Otherwise fall back
	// to a no-MFA request — the guild may not require MFA for admin actions,
	// and Discord accepts the PATCH without the header. If it returns 60003,
	// the sentry / runOnce path will solve MFA on the fly and re-publish.
	var buf []byte
	if mfaName != "" && mfaValue != "" {
		buf = RenderClaimBytesWith(tpl, mfaName, mfaValue)
	} else {
		buf = tpl.BuildNoMFA()
	}
	if buf == nil || len(buf) == 0 {
		return false
	}
	c.currentBytes.Store(&buf)

	// Also publish fallback bytes so the dual-endpoint retry in the sentry has
	// pre-rendered bytes ready (no synchronous render on the retry path).
	if fallbackTpl != nil {
		var fb []byte
		if mfaName != "" && mfaValue != "" {
			fb = RenderClaimBytesWith(fallbackTpl, mfaName, mfaValue)
		} else {
			fb = fallbackTpl.BuildNoMFA()
		}
		if fb != nil {
			c.currentFallbackBytes.Store(&fb)
		}
	}

	return true
}

// ensureTemplate rebuilds the claim PATCH if the target's vanity name differs
// from the template that was built at construction. Run calls this before any
// detection starts, so an entry point that finalises the vanity after
// NewClaimer (CLI prompts, config reload, tests) cannot leave the poller
// watching one name while the wire request claims another.
func (c *Claimer) ensureTemplate() {
	c.target.mu.Lock()
	vanity := c.target.Vanity
	c.target.mu.Unlock()

	c.tplMu.RLock()
	same := c.tpl != nil && c.tplVanity == vanity
	c.tplMu.RUnlock()
	if same {
		return
	}

	tpl := BuildClaimRequest(c.target, c.cfg)
	fallbackTpl := BuildFallbackClaimRequest(c.target, c.cfg)

	c.tplMu.Lock()
	c.tpl = tpl
	c.fallbackTpl = fallbackTpl
	c.tplVanity = vanity
	c.tplMu.Unlock()

	c.publishBytes()
	log.Printf("[claim %s] claim template derived from final vanity", vanity)
}

func (c *Claimer) SignalAvailable() {
	select {
	case c.available <- time.Now():
	default:
	}
}

func (c *Claimer) Run() {
	defer close(c.done)
	c.ensureTemplate()
	// Guarantee the first availability signal has wire-ready bytes even if the
	// background publisher has not been scheduled yet (cold start).
	c.publishBytes()
	c.startPoller()
	c.claimLoop()
}

// claimLoop is the availability→claim loop. It is split out of Run so a test
// can drive the exact production loop without also starting the network
// poller.
func (c *Claimer) claimLoop() {
	for {
		select {
		case t0 := <-c.available:
			c.safeTryClaim(t0)
		case <-c.stop:
			return
		}
	}
}

// safeTryClaim contains panics inside the claim episode: tryClaim →
// firstClaim/reclaim → runBurst runs on the claim loop goroutine, and a panic
// reaching its root would kill the whole process — ending a 6-hour
// unattended Actions-hosted session over one malformed response. Recovered,
// the loop keeps consuming availability signals; the failed episode counts as
// an error.
func (c *Claimer) safeTryClaim(t0 time.Time) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[claim %s] recovered from panic in claim path: %v\n%s",
				c.target.Vanity, r, debug.Stack())
			c.stats.AddError()
		}
	}()
	c.tryClaim(t0)
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
	// A terminal `lost` state is also a fresh opportunity: the guard exhausted
	// its cap earlier, but this signal means the vanity is free (or held by
	// someone else) AGAIN — give up permanently and we could lose a code that
	// sits free forever after that. Reset the episode and take a fresh shot.
	if lost {
		c.target.mu.Lock()
		c.target.lost = false
		c.target.reclaimAttempts = 0
		c.target.mu.Unlock()
		log.Printf("[guard %s] vanity free again after a lost episode — taking a fresh claim", c.target.Vanity)
		c.firstClaim()
		return
	}

	if !c.guardEnabled || !guardArmed {
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

	// Background publish (startBackgroundPublish) keeps bytes fresh in a 1s
	// ticker. In steady state, the bytes are already published and we fire
	// immediately — no GetHeader, no WaitForToken, no publishBytes on the
	// critical path.
	//
	// Cold-start fallback: if the background goroutine hasn't produced bytes
	// yet (pre-solver not done, or first tick hasn't fired), do the old
	// synchronous GetHeader + WaitForToken + publishBytesWithName flow.
	if c.currentBytes.Load() == nil {
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
			log.Printf("[claim %s] no MFA token available — trying without MFA header (guild may not require MFA)", c.target.Vanity)
			if c.publishBytesWithName("", "") {
				log.Printf("[claim %s] published no-MFA claim bytes", c.target.Vanity)
			} else {
				log.Printf("[claim %s] ❌ could not build claim bytes — skipping (will retry on next signal)", c.target.Vanity)
				return
			}
		} else {
			log.Printf("[claim %s] synchronous MFA token, publishing bytes", c.target.Vanity)
			if !c.publishBytesWithName(mfaName, mfaValue) {
				log.Printf("[claim %s] ❌ could not build claim bytes — skipping (will retry on next signal)", c.target.Vanity)
				return
			}
		}
	}

	c.runBurst()
}

// runBurst fires all sentries and drains exactly one result per sentry. Returns
// true if any worker reported a 200. Shared by firstClaim and reclaim. The first
// 200 fires the success handler inside runOnce (via fireFirstSuccess) so the
// operator is notified before the remaining sentries drain.
func (c *Claimer) runBurst() bool {
	c.fire()
	success := false
	for i := 0; i < c.burstCount; i++ {
		select {
		case result := <-c.resultCh:
			if result == 1 {
				success = true
			}
		case <-c.stop:
			return success
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
			runGuarded("quarantine", c.target.Vanity, c.stats, c.guard.Quarantine)
		}
	} else {
		log.Printf("[guard %s] reclaim attempt %d/%d", c.target.Vanity, attemptNum+1, c.reclaimMax)
	}

	c.claimStart = time.Now()
	c.resetSuccessGate(true)

	for attempt := 0; attempt < c.reclaimMax; attempt++ {
		// Background publish keeps bytes fresh. If they're ready, fire
		// immediately. Cold-start fallback: synchronous publish if not.
		if c.currentBytes.Load() == nil {
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
			if !c.publishBytesWithName(mfaName, mfaValue) {
				log.Printf("[guard %s] could not build claim bytes, skipping attempt %d", c.target.Vanity, attempt+1)
				continue
			}
		}

		c.target.mu.Lock()
		c.target.reclaimAttempts = attempt + 1
		c.target.mu.Unlock()

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
// the latency breakdown sample (T0→T1→T2→T3) from the episode scratch fields and
// the winning sentry's own T2/T3 timestamps, then records it in the stats
// tracker for the dashboard p50/p99.
func (c *Claimer) fireFirstSuccess(success bool, t2, t3 time.Time) {
	if !success {
		return
	}
	c.firstSuccessOnce.Do(func() {
		if c.epT0 != (time.Time{}) && !t3.IsZero() {
			sample := latSample{
				dispatch: c.epT1.Sub(c.epT0), // gateway decode → fire publish
				local:    t2.Sub(c.epT1),     // fire close → conn.Write return
				rtt:      t3.Sub(t2),         // Write return → first 200 read
				total:    t3.Sub(c.epT0),     // frame arrival → claim landed
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
	// Single-flight per ticket: a burst of N sentries can all get 429s carrying
	// the same challenge ticket, and each concurrent solve would either race
	// duplicate network solves or (with backup codes) burn several limited
	// codes on one challenge. The first goroutine solves; the rest return
	// immediately since the result is already published via SetToken/publish.
	c.solveMu.Lock()
	if ticket != "" && ticket == c.lastSolvedTicket {
		c.solveMu.Unlock()
		return
	}
	defer c.solveMu.Unlock()

	// Try TOTP first (primary method for accounts with TOTP enabled)
	if c.mfa.totpSecret != "" {
		log.Printf("[mfa %s] solving ticket via totp", c.target.Vanity)
		token, expiresIn, err := c.mfa.solveTOTP(ticket)
		if err == nil && token != "" {
			c.mfa.SetToken(token, expiresIn)
			// Re-publish bytes with the fresh token so any in-flight or next
			// burst reads the new token via atomic load.
			c.lastSolvedTicket = ticket
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
			c.lastSolvedTicket = ticket
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
			c.lastSolvedTicket = ticket
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
	// The poller and sentries select on c.stop and will exit on their own;
	// waiting on them here could deadlock if a sentry is mid-Write. The done
	// channel (closed by Run on stop) is the join point the orchestrator waits on.
	<-c.done
}

// runGuarded launches fn in its own goroutine with panic containment. A panic
// in a fire-and-forget goroutine (the guard quarantine, the MFA pre-solve spur)
// would otherwise take down the whole process — on an unattended Actions-hosted
// session that ends the 340-minute window over one bad response. The panic is
// logged with its stack, counted as an error, and forgotten.
func runGuarded(label, vanity string, stats *Stats, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[%s %s] recovered from panic: %v\n%s", label, vanity, r, debug.Stack())
				if stats != nil {
					stats.AddError()
				}
			}
		}()
		fn()
	}()
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

// connectionClose returns true if the HTTP response explicitly sets
// "Connection: close", meaning the server will close the TCP conn after
// this response. HTTP/1.1 defaults to keepalive, so absence of the header
// means the conn is reusable.
func connectionClose(resp []byte) bool {
	headerEnd := bytes.Index(resp, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return true // incomplete response — be safe and assume close
	}
	headerBlock := resp[:headerEnd]
	return bytes.Contains(headerBlock, []byte("Connection: close")) ||
		bytes.Contains(headerBlock, []byte("connection: close"))
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
	body := bytes.TrimSpace(respBody(resp))
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
