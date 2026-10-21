package sniper

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type GatewayState struct {
	SessionID string
	ResumeURL string
	Sequence  int
}

// gatewayDialer has explicit timeouts so a stalled network cannot hang the
// gateway goroutine indefinitely.
var gatewayDialer = &websocket.Dialer{
	HandshakeTimeout: 10 * time.Second,
	NetDialContext: (&net.Dialer{
		Timeout: 10 * time.Second,
	}).DialContext,
	TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
}

type Gateway struct {
	target    *Target
	token     string
	sessionID string
	state     *GatewayState
	mu        sync.Mutex
	conn      *websocket.Conn
	available chan time.Time
	stop      chan struct{}
	done      chan struct{}
	sessions  *SessionStore
	key       string
	stats     *Stats // nil in tests that do not inspect observation counts

	// seqPending holds the latest dispatch sequence seen on the receive path.
	// The hot path stores to it lock-free (atomic) instead of calling
	// sessions.UpdateSequence on every frame — that call took the shared
	// SessionStore write lock (one mutex for ALL targets) per frame, serializing
	// every gateway's receive loop and churning the dirty flag. A background
	// flusher (runSeqFlusher, spawned in listen) coalesces the atomic into a
	// single UpdateSequence call every seqFlushInterval, and a final flush runs
	// on listen() exit so resume picks up the latest seq after a disconnect.
	//
	// lastFlushedSeq is the high-water mark of what the flusher has already
	// persisted. It's an atomic (not a plain int) because READY — which can
	// reset the sequence numbering back to a small value on a fresh IDENTIFY —
	// runs on the receive goroutine while the flusher goroutine reads it. The
	// flusher writes to the store only when seqPending has ADVANCED past
	// lastFlushedSeq; on READY we reset BOTH to 0 atomically so the fresh
	// session's small seq values are correctly flushed (and we don't get stuck
	// skipping flushes because lastFlushedSeq held a stale large value).
	seqPending     atomic.Int64
	lastFlushedSeq atomic.Int64

	// resumeAttempts is owned by noteFrame/nextResumeAttempt/resetResumeAttempts.
	// It lives on the Gateway (not in listen's stack) so both the raw fast path
	// and the normal decode path update the same counter. Guarded by mu.
	resumeAttempts int

	// guildIDNeedle/guildIDRaw are the target guild id in the two forms the
	// GUILD_UPDATE fast path checks. Precomputed so the hot path does not
	// concatenate or allocate a new string for every frame.
	guildIDNeedle []byte
	guildIDRaw    []byte

	// guildUpdateNeedle matches the dispatch type in a compact gateway frame, so
	// listen() can take the raw-frame path before decoding the envelope.
	guildUpdateNeedle []byte
}

// seqFlushInterval is how often runSeqFlusher persists the latest seen sequence
// to the SessionStore. Tuned to coalesce the ~10-50 frames/sec a busy gateway
// receives into one store write, while keeping resume's checkpoint recent enough
// that a crash loses at most this much replay progress (Discard handles gaps).
const seqFlushInterval = 2 * time.Second

// runSeqFlusher periodically flushes the lock-free seqPending value into the
// SessionStore. Spawned once per listen() call; stopped via close(stop) on
// listen exit, after which the caller runs a final flushSeq(). The done WG is
// signalled on exit so the caller can wait before the final flush (avoids a
// race between the periodic tick and the final write).
func (g *Gateway) runSeqFlusher(stop <-chan struct{}, done *sync.WaitGroup) {
	defer done.Done()
	t := time.NewTicker(seqFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			g.flushSeq()
		}
	}
}

// flushSeq writes the latest seen sequence to the SessionStore if it advanced
// since the last flush. The compare is on the atomics so it stays correct when
// READY resets the bookkeeping from the receive goroutine while the flusher
// concurrently reads it: a reset sets both to 0, so a subsequent flush with a
// fresh-session seq value (>0) writes correctly.
func (g *Gateway) flushSeq() {
	cur := g.seqPending.Load()
	last := g.lastFlushedSeq.Load()
	if cur <= last {
		return
	}
	g.sessions.UpdateSequence(g.key, int(cur))
	// Only advance lastFlushedSeq if it hasn't been reset to 0 under us by a
	// concurrent READY (in which case the store already holds 0 from Set() and
	// we want a fresh-session flush to win on the next tick). CAS-from-`last`
	// makes us the loser of that race cleanly.
	g.lastFlushedSeq.CompareAndSwap(last, cur)
}

func NewGateway(t *Target, available chan time.Time, sessions *SessionStore) *Gateway {
	key := t.GuildID + ":" + t.Vanity
	g := &Gateway{
		target:            t,
		token:             t.Token,
		guildIDNeedle:     []byte(`"id":"` + t.GuildID + `"`),
		guildIDRaw:        []byte(t.GuildID),
		guildUpdateNeedle: []byte(`"t":"GUILD_UPDATE"`),
		state:             &GatewayState{},
		available:         available,
		stop:              make(chan struct{}),
		done:              make(chan struct{}),
		sessions:          sessions,
		key:               key,
	}

	// Restore session from store
	if ts := sessions.Get(key); ts != nil {
		g.state.SessionID = ts.SessionID
		g.state.ResumeURL = ts.ResumeURL
		g.state.Sequence = ts.Sequence
		if g.state.SessionID != "" {
			log.Printf("[gateway %s] restored session %s (seq %d)",
				g.target.Vanity, shortID(g.state.SessionID), g.state.Sequence)
		}
	}

	return g
}

// noteFrame is the single owner of envelope sequence and resume-attempt state.
// Both the raw GUILD_UPDATE path and the normal decode path call it before they
// can signal a claim, so those two bookkeeping values cannot drift between
// routes. seq > 0 advances the gateway state and the coalesced flusher;
// dispatch clears the invalid-session counter.
func (g *Gateway) noteFrame(seq int, dispatch bool) {
	g.mu.Lock()
	if dispatch {
		g.resumeAttempts = 0
	}
	if seq > 0 {
		g.state.Sequence = seq
	}
	g.mu.Unlock()
	if seq > 0 {
		g.seqPending.Store(int64(seq))
	}
}

// noteInvalidSession records one invalid-session reply and reports whether the
// gateway must fall back to a fresh IDENTIFY. The counter resets when fallback
// happens, so a later episode starts from zero. A non-resumable reply falls
// back immediately.
func (g *Gateway) noteInvalidSession(resumable bool) (attempts int, fallback bool) {
	g.mu.Lock()
	g.resumeAttempts++
	attempts = g.resumeAttempts
	fallback = !resumable || attempts >= 3
	if fallback {
		g.resumeAttempts = 0
	}
	g.mu.Unlock()
	return attempts, fallback
}

// observeVanity is the gateway's single observation point. Every route that
// parses a vanity code calls this, so the check counter and the free/not-free
// decision cannot drift across READY, GUILD_CREATE, the GUILD_UPDATE fast path
// and fallback, or the RESUMED REST check.
func (g *Gateway) observeVanity(code string, valid bool) (string, bool) {
	current := g.target.currentVanity()
	return current, observeVanity(g.stats, current, code, valid)
}

// shortID returns the first 8 characters of an id, or the whole thing if shorter.
// Guards against a panic if a stored session id is unexpectedly short.
func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func (g *Gateway) Run() {
	defer close(g.done)

	retryDelay := 1 * time.Second
	const maxRetryDelay = 30 * time.Second

	for {
		select {
		case <-g.stop:
			return
		default:
		}

		err := g.connect()
		if err != nil {
			// Dial failures are transient (network). Back off and retry. The
			// sleep must be interruptible: Stop() closes g.done via a blocked
			// Run, so a plain time.Sleep could stall shutdown up to 30s.
			log.Printf("[gateway %s] connect error: %v", g.target.Vanity, err)
			select {
			case <-g.stop:
				return
			case <-time.After(retryDelay):
			}
			if retryDelay < maxRetryDelay {
				retryDelay *= 2
			}
			continue
		}

		err = g.listen()
		if err != nil {
			// 4004 = Authentication failed — the token is permanently invalid.
			// No amount of retrying will fix this; log a clear message and
			// stop the gateway loop so we don't spam reconnects.
			if strings.Contains(err.Error(), "4004") {
				log.Printf("[gateway %s] ❌ authentication failed (4004) — token is invalid or revoked, stopping gateway", g.target.Vanity)
				return
			}
			log.Printf("[gateway %s] listen error: %v", g.target.Vanity, err)
		}

		// Successful session (or clean reconnect). Reset retry backoff.
		retryDelay = 1 * time.Second
	}
}

func (g *Gateway) connect() error {
	g.mu.Lock()
	resumeID := g.state.SessionID
	resumeSeq := g.state.Sequence
	resumeURL := g.state.ResumeURL
	g.mu.Unlock()

	var u string
	if resumeURL != "" {
		u = resumeURL + "/?v=10&encoding=json"
	} else {
		u = "wss://gateway.discord.gg/?v=10&encoding=json"
	}

	conn, _, err := gatewayDialer.Dial(u, http.Header{})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	g.mu.Lock()
	if g.conn != nil {
		g.conn.Close()
	}
	g.conn = conn
	g.mu.Unlock()

	if resumeID != "" {
		return g.resume(resumeID, resumeSeq)
	}
	return g.identify()
}

func (g *Gateway) identify() error {
	props := map[string]string{
		"os":      "Windows",
		"browser": "Chrome",
		"device":  "",
	}

	payload := map[string]interface{}{
		"op": 2,
		"d": map[string]interface{}{
			"token":        g.token,
			"capabilities": 16381,
			"intents":      1, // GUILDS intent: needed for GUILD_CREATE/GUILD_UPDATE/GUILD_DELETE
			"properties":   props,
			"presence": map[string]interface{}{
				"status":     "online",
				"since":      0,
				"activities": []interface{}{},
				"afk":        false,
			},
		},
	}

	return g.conn.WriteJSON(payload)
}

func (g *Gateway) resume(sessionID string, seq int) error {
	payload := map[string]interface{}{
		"op": 6,
		"d": map[string]interface{}{
			"token":      g.token,
			"session_id": sessionID,
			"seq":        seq,
		},
	}

	return g.conn.WriteJSON(payload)
}

func (g *Gateway) listen() error {
	// Capture the conn ONCE for this listen session. The reader goroutine must
	// never read the g.conn field directly: Stop()/connect() replace or close
	// it under g.mu, and an unsynchronized read from the reader goroutine is a
	// data race on the field. connect() stored the dial result under the same
	// mutex before listen() was called, so this value is the live conn.
	conn := g.conn

	// Read on a dedicated goroutine and pump messages into a channel. This lets
	// the main loop select on g.stop and close g.conn to unblock the read when
	// shutting down — otherwise ReadMessage blocks forever on a quiet conn and
	// Stop() deadlocks on <-g.done.
	type readResult struct {
		msg []byte
		err error
	}
	readCh := make(chan readResult, 1)

	reader := func() {
		_, msg, err := conn.ReadMessage()
		select {
		case readCh <- readResult{msg: msg, err: err}:
		case <-g.stop:
		}
	}
	go reader()

	// Spawn the coalesced sequence flusher. It batches per-frame seq updates
	// (written lock-free to seqPending) into a single SessionStore write every
	// seqFlushInterval, removing the shared SessionStore mutex from the
	// receive hot path. Stopped on listen() exit; the deferred flushSeq below
	// guarantees the final value is persisted for resume.
	seqFlushStop := make(chan struct{})
	var seqFlushDone sync.WaitGroup
	seqFlushDone.Add(1)
	go g.runSeqFlusher(seqFlushStop, &seqFlushDone)
	defer func() {
		close(seqFlushStop)
		seqFlushDone.Wait()
		g.flushSeq() // final persist so resume picks up the latest seq
	}()

	// Heartbeat ACK tracking: if Discord stops acknowledging heartbeats, the
	// connection is dead (zombie). Force a reconnect instead of going deaf.
	var (
		heartbeatInterval time.Duration = 41 * time.Second
		lastACK                         = time.Now()
		pendingACK        bool
	)
	heartbeat := func() {
		g.mu.Lock()
		if g.conn != nil {
			g.conn.WriteJSON(map[string]interface{}{
				"op": 1,
				"d":  g.state.Sequence,
			})
		}
		g.mu.Unlock()
		pendingACK = true
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-g.stop:
			g.mu.Lock()
			if g.conn != nil {
				g.conn.Close()
			}
			g.mu.Unlock()
			return nil

		case res := <-readCh:
			if res.err != nil {
				return fmt.Errorf("read: %w", res.err)
			}

			var packet struct {
				Op   int             `json:"op"`
				Seq  int             `json:"s,omitempty"`
				Type string          `json:"t,omitempty"`
				Data json.RawMessage `json:"d,omitempty"`
			}

			// T0 is the moment the frame is available to this process, before the
			// envelope decode. Capturing it here makes the claimer's latency
			// breakdown include decode/dispatch instead of hiding it.
			frameT0 := time.Now()

			// GUILD_UPDATE fast path: Discord sends compact JSON. When the frame is
			// a dispatch for this event, handle it with byte scans and skip the
			// envelope + payload decode entirely (json decode is 10–15µs on a full
			// guild object; the scans are <1µs). Anything unexpected falls through
			// to the normal decode below.
			if bytes.Contains(res.msg, g.guildUpdateNeedle) {
				if handled := g.handleRawGuildUpdateFrame(res.msg, frameT0); handled {
					go reader()
					continue
				}
			}

			if err := json.Unmarshal(res.msg, &packet); err != nil {
				// Re-arm the reader for the next message.
				go reader()
				continue
			}

			// Both routes call the same owner before they can signal a claim.
			// The raw path already noted its envelope inside
			// handleRawGuildUpdateFrame; this covers the JSON path (and a raw
			// fallback, where the same value is noted again harmlessly).
			g.noteFrame(packet.Seq, packet.Op == 0)

			switch packet.Op {
			case 0: // Dispatch
				g.handleDispatch(packet.Type, packet.Data, frameT0)

			case 7: // Reconnect
				g.conn.Close()
				return nil

			case 9: // Invalid Session
				g.conn.Close()

				// For op 9, packet.Data is the bare bool `d` field directly
				// (true = resumable, false = must re-identify). Unmarshaling
				// into a struct silently fails, so unmarshal the raw bool.
				var resumeable bool
				if err := json.Unmarshal(packet.Data, &resumeable); err != nil {
					resumeable = false
				}

				attempts, fallback := g.noteInvalidSession(resumeable)
				if fallback {
					g.mu.Lock()
					g.state.SessionID = ""
					g.state.ResumeURL = ""
					g.state.Sequence = 0
					g.mu.Unlock()
					g.sessions.Clear(g.key)
					// Reset flusher bookkeeping to match the cleared store + the
					// fresh re-IDENTIFY that follows: the next session's seq
					// numbering restarts from a small value, and we don't want
					// a stale large lastFlushedSeq to suppress those flushes.
					g.seqPending.Store(0)
					g.lastFlushedSeq.Store(0)
					if !resumeable {
						log.Printf("[gateway %s] session invalidated, will re-identify", g.target.Vanity)
					} else {
						log.Printf("[gateway %s] resume exhausted after %d attempts, re-identifying", g.target.Vanity, attempts)
					}
				}

				return fmt.Errorf("invalid session")

			case 10: // Hello
				var hello struct {
					HeartbeatInterval int `json:"heartbeat_interval"`
				}
				json.Unmarshal(packet.Data, &hello)
				if hello.HeartbeatInterval > 0 {
					heartbeatInterval = time.Duration(hello.HeartbeatInterval) * time.Millisecond
					lastACK = time.Now()
					pendingACK = false
					heartbeat()
				}

			case 11: // Heartbeat ACK
				lastACK = time.Now()
				pendingACK = false
			}

			// Re-arm the reader for the next message.
			go reader()

		case <-ticker.C:
			// Heartbeat cadence.
			if time.Since(lastACK) >= heartbeatInterval && !pendingACK {
				heartbeat()
			}

			// Zombie detection: if we sent a heartbeat and never got an ACK
			// within 1.5x the interval, the connection is dead.
			if pendingACK && time.Since(lastACK) > heartbeatInterval*3/2 {
				log.Printf("[gateway %s] no heartbeat ACK, reconnecting", g.target.Vanity)
				g.mu.Lock()
				if g.conn != nil {
					g.conn.Close()
				}
				g.mu.Unlock()
				return fmt.Errorf("heartbeat timeout")
			}
		}
	}
}

// handleRawGuildUpdateFrame handles a complete GUILD_UPDATE gateway frame
// without decoding the JSON envelope or payload. It returns true when the
// frame was fully handled (including updates for other guilds). False means the
// frame is not in the compact shape this path understands and the caller must
// fall back to the normal decode.
func (g *Gateway) handleRawGuildUpdateFrame(frame []byte, frameT0 time.Time) bool {
	if op, ok := scanJSONIntField(frame, "op"); !ok || op != 0 {
		return false // not a dispatch (or unexpected shape)
	}

	if !bytes.Contains(frame, []byte(`"vanity_url_code"`)) {
		// Cannot affect the vanity, but the frame is still fully handled here.
		seq, _ := scanJSONIntField(frame, "s")
		g.noteFrame(seq, true)
		return true
	}

	// Decide whether the byte-scan route can handle this frame before noting
	// anything. A fallback must leave bookkeeping untouched so the JSON route
	// is the only one that notes this frame.
	res, handled := g.scanGuildUpdateFast(frame)
	if !handled {
		return false
	}
	seq, _ := scanJSONIntField(frame, "s")
	g.noteFrame(seq, true)
	g.applyGuildUpdateFast(res, frameT0)
	return true
}

// guildUpdateFastResult is the byte-scan decision for one GUILD_UPDATE. It is
// split from applyGuildUpdateFast so the raw route can note the envelope only
// after it knows this route will handle the frame, never on a JSON fallback.
type guildUpdateFastResult struct {
	code          string
	currentVanity string
	free          bool
}

// scanGuildUpdateFast classifies a GUILD_UPDATE without unmarshalling the
// payload. handled=false means the caller must fall back to JSON; handled=true
// with free=false means the frame is safely ignored (another guild or our
// vanity is still set).
func (g *Gateway) scanGuildUpdateFast(data []byte) (guildUpdateFastResult, bool) {
	if !bytes.Contains(data, g.guildIDNeedle) {
		if bytes.Contains(data, g.guildIDRaw) {
			return guildUpdateFastResult{}, false // our guild, but not in the compact shape
		}
		return guildUpdateFastResult{}, true // another guild's update; nothing to do
	}

	code, ok := scanJSONStringField(data, "vanity_url_code")
	if !ok {
		return guildUpdateFastResult{}, false // unexpected shape; let the JSON path handle
	}
	currentVanity, free := g.observeVanity(code, true)
	return guildUpdateFastResult{code: code, currentVanity: currentVanity, free: free}, true
}

// applyGuildUpdateFast publishes the signal for a frame already classified by
// scanGuildUpdateFast. The signal is published before the log line so logging
// never sits between the frame and the claimer's wake.
func (g *Gateway) applyGuildUpdateFast(res guildUpdateFastResult, frameT0 time.Time) {
	if !res.free {
		return
	}
	select {
	case g.available <- frameT0:
	default:
	}
	log.Printf("[gateway %s] vanity changed to %q -> available", res.currentVanity, res.code)
}

// handleGuildUpdateFast handles a GUILD_UPDATE for the target guild without
// unmarshalling the payload. It returns true when the frame was fully handled
// (including "not our guild"); false tells the caller to fall back to JSON.
func (g *Gateway) handleGuildUpdateFast(data []byte, frameT0 time.Time) bool {
	res, handled := g.scanGuildUpdateFast(data)
	if !handled {
		return false
	}
	g.applyGuildUpdateFast(res, frameT0)
	return true
}

// scanJSONStringField returns the value of the first `"field": ...` occurrence
// in data. A JSON null is reported as ("", true). Vanity codes and numeric ids
// are quote-free, so a byte scan is sufficient and avoids an allocation-heavy
// json.Unmarshal on the detection path.
// scanJSONIntField returns the first positive-or-zero integer value of
// `"field": <digits>` in data. Missing fields and non-numeric values return
// (0, false). Used for the sequence number on the raw-frame path, where a full
// JSON decode would defeat the point.
func scanJSONIntField(data []byte, field string) (int, bool) {
	key := []byte(`"` + field + `"`)
	idx := bytes.Index(data, key)
	if idx < 0 {
		return 0, false
	}
	i := idx + len(key)
	for i < len(data) && (data[i] == ' ' || data[i] == ':' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
		i++
	}
	start := i
	n := 0
	for i < len(data) && data[i] >= '0' && data[i] <= '9' {
		n = n*10 + int(data[i]-'0')
		i++
	}
	if i == start {
		return 0, false
	}
	return n, true
}

// parseJSONCode turns a raw vanity_url_code value into (code, valid). A JSON
// null is a valid empty code (no vanity set, therefore free). A missing field,
// a non-string value, or a partial raw value is invalid and must never be
// treated as free.
func parseJSONCode(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", false
	}
	if bytes.Equal(raw, []byte("null")) {
		return "", true
	}
	if raw[0] != '"' {
		return "", false
	}
	var code string
	if err := json.Unmarshal(raw, &code); err != nil {
		return "", false
	}
	return code, true
}

func scanJSONStringField(data []byte, field string) (string, bool) {
	key := []byte(`"` + field + `"`)
	idx := bytes.Index(data, key)
	if idx < 0 {
		return "", false
	}
	i := idx + len(key)
	for i < len(data) && (data[i] == ' ' || data[i] == ':' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
		i++
	}
	if i >= len(data) {
		return "", false
	}
	if i+4 <= len(data) && bytes.Equal(data[i:i+4], []byte("null")) {
		return "", jsonObjectValueEnds(data, i+4)
	}
	if data[i] != '"' {
		return "", false
	}
	i++
	end := bytes.IndexByte(data[i:], '"')
	if end < 0 {
		return "", false
	}
	if !jsonObjectValueEnds(data, i+end+1) {
		return "", false
	}
	return string(data[i : i+end]), true
}

// jsonObjectValueEnds reports whether the value just scanned is followed by a
// comma or the object's closing brace. A truncated frame that happens to
// contain a complete-looking string is therefore not mistaken for a parse
// success; the caller falls back to the full JSON decoder.
func jsonObjectValueEnds(data []byte, i int) bool {
	for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
		i++
	}
	return i < len(data) && (data[i] == ',' || data[i] == '}')
}

func (g *Gateway) handleDispatch(t string, data json.RawMessage, frameT0 time.Time) {
	switch t {
	case "READY":
		var ready struct {
			SessionID string `json:"session_id"`
			ResumeURL string `json:"resume_gateway_url"`
			User      struct {
				ID       string `json:"id"`
				Username string `json:"username"`
			} `json:"user"`
			Guilds []struct {
				ID            string          `json:"id"`
				VanityURLCode json.RawMessage `json:"vanity_url_code"`
			} `json:"guilds"`
		}
		if err := json.Unmarshal(data, &ready); err != nil {
			log.Printf("[gateway %s] READY parse failed — not signaling", g.target.currentVanity())
			return
		}
		g.mu.Lock()
		g.state.SessionID = ready.SessionID
		g.state.ResumeURL = ready.ResumeURL
		g.mu.Unlock()

		// Capture the token owner's user id so the Vanity Guard can whitelist
		// them — a legitimate vanity change made by the operator's own account
		// must never trigger a self-kick/self-ban. Stored on Target under its
		// mutex; the guard reads it under the same lock.
		if ready.User.ID != "" {
			g.target.mu.Lock()
			g.target.ownerID = ready.User.ID
			g.target.mu.Unlock()
		}

		g.sessions.Set(g.key, &TargetSession{
			SessionID: ready.SessionID,
			ResumeURL: ready.ResumeURL,
			Sequence:  0,
		})
		// A fresh IDENTIFY starts sequence numbering over from a small value.
		// Reset the flusher bookkeeping so a fresh-session seq (>0) flushes
		// correctly instead of being skipped because lastFlushedSeq held a
		// stale large value from the previous (resumed) session. Both atomics
		// reset together: seqPending→0 so the next frame's seq is "new", and
		// lastFlushedSeq→0 so flushSeq's cur>last test passes for that frame.
		g.seqPending.Store(0)
		g.lastFlushedSeq.Store(0)
		currentVanity := g.target.currentVanity()
		log.Printf("[gateway %s] ready as %s (%s) session=%s",
			currentVanity, ready.User.Username, ready.User.ID, shortID(ready.SessionID))
		log.Printf("[gateway %s] READY in %s from process start", currentVanity, time.Since(processStartTime))

		for _, guild := range ready.Guilds {
			if guild.ID == g.target.GuildID {
				code, ok := parseJSONCode(guild.VanityURLCode)
				currentVanity, free := g.observeVanity(code, ok)
				if !ok {
					log.Printf("[gateway %s] READY vanity code unparseable — not signaling", currentVanity)
				} else if free {
					log.Printf("[gateway %s] guild has vanity=%q, target=%s → available",
						currentVanity, code, currentVanity)
					select {
					case g.available <- frameT0:
					default:
					}
				} else {
					log.Printf("[gateway %s] guild matches target vanity=%q — waiting",
						currentVanity, code)
				}
				break
			}
		}

	case "RESUMED":
		log.Printf("[gateway %s] resumed session", g.target.currentVanity())
		go g.checkVanityREST()

	case "GUILD_UPDATE":
		// Fast-path filter: the vast majority of GUILD_UPDATE events change an
		// unrelated field (name, description, features, icon...). Only when the
		// vanity could have changed do we care — skip the json.Unmarshal +
		// availability signal entirely otherwise. A substring scan is ~μs and
		// avoids waking the claimer (and spurious claim attempts) for every
		// unrelated guild edit.
		if !bytes.Contains(data, []byte("vanity_url_code")) {
			return
		}

		// Most target-guild updates are fully handled by byte scans: no map or
		// struct allocation, no full-frame decode. Fall back to JSON only when
		// the payload is not in the expected shape.
		if g.handleGuildUpdateFast(data, frameT0) {
			return
		}

		var guild struct {
			ID            string          `json:"id"`
			VanityURLCode json.RawMessage `json:"vanity_url_code"`
		}
		if err := json.Unmarshal(data, &guild); err != nil || guild.ID != g.target.GuildID {
			return
		}

		code, ok := parseJSONCode(guild.VanityURLCode)
		currentVanity, free := g.observeVanity(code, ok)
		if free {
			select {
			case g.available <- frameT0:
			default:
			}
			log.Printf("[gateway %s] vanity changed to %q -> available", currentVanity, code)
		} else if !ok {
			log.Printf("[gateway %s] vanity code unparseable — not signaling", currentVanity)
		}

	case "GUILD_CREATE":
		var guild struct {
			ID            string          `json:"id"`
			VanityURLCode json.RawMessage `json:"vanity_url_code"`
		}
		if err := json.Unmarshal(data, &guild); err != nil {
			return
		}
		if g.target == nil || guild.ID != g.target.GuildID {
			return
		}

		code, ok := parseJSONCode(guild.VanityURLCode)
		currentVanity, free := g.observeVanity(code, ok)
		log.Printf("[gateway %s] GUILD_CREATE vanity=%q (parseOK=%v)", currentVanity, code, ok)
		if !ok {
			log.Printf("[gateway %s] GUILD_CREATE vanity code unparseable — not signaling", currentVanity)
		} else if free {
			log.Printf("[gateway %s] guild ready, vanity_code=%q → available",
				currentVanity, code)
			select {
			case g.available <- frameT0:
			default:
			}
		} else {
			log.Printf("[gateway %s] guild ready, vanity_code=%q matches — waiting",
				currentVanity, code)
		}

	case "GUILD_DELETE":
		var guild struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(data, &guild); err != nil {
			return
		}
		if guild.ID == g.target.GuildID {
			log.Printf("[gateway %s] guild deleted, signaling available", g.target.currentVanity())
			select {
			case g.available <- frameT0:
			default:
			}
		}
	}
}

func (g *Gateway) checkVanityREST() {
	conn, err := discordDialConn(5 * time.Second)
	if err != nil {
		log.Printf("[gateway %s] REST check: dial error: %v", g.target.currentVanity(), err)
		return
	}
	defer conn.Close()

	// A stalled response must not hang the RESUMED path; the REST check is a
	// backup, not the primary trigger.
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := fmt.Sprintf(
		"GET /api/v9/guilds/%s/vanity-url HTTP/1.1\r\nHost: discord.com\r\nAuthorization: %s\r\nConnection: close\r\n\r\n",
		g.target.GuildID, g.token,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		log.Printf("[gateway %s] REST check: write error: %v", g.target.currentVanity(), err)
		return
	}

	resp, complete := readCompleteResponse(conn, make([]byte, 2048))
	g.evaluateVanityREST(resp, complete)
}

// evaluateVanityREST is the REST route's decision point, separated from the
// socket so malformed and truncated responses are testable without a live
// Discord connection. Only a complete 200 with a parseable code may reach
// vanityFree; a partial or unparseable body never signals.
func (g *Gateway) evaluateVanityREST(resp []byte, complete bool) {
	currentVanity := g.target.currentVanity()
	statusLine := extractStatusLine(resp)
	body := extractBody(resp)
	log.Printf("[gateway %s] REST check — status: %s body: %s", currentVanity, statusLine, body)

	if !complete {
		log.Printf("[gateway %s] REST check: incomplete response, waiting for gateway event", currentVanity)
		return
	}
	if !isStatusOK(resp) {
		log.Printf("[gateway %s] REST check: non-200 (%s), waiting for gateway event", currentVanity, statusLine)
		return
	}

	code, ok := parseVanityCode(resp)
	currentVanity, free := g.observeVanity(code, ok)
	if !free {
		if !ok {
			log.Printf("[gateway %s] REST check: unparseable body — not signaling", currentVanity)
		} else {
			log.Printf("[gateway %s] REST check: vanity already set, waiting for change", currentVanity)
		}
		return
	}

	select {
	case g.available <- time.Now():
	default:
	}
	log.Printf("[gateway %s] REST check: vanity not set or different, signaling available", currentVanity)
}

func (g *Gateway) IsConnected() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.conn != nil
}

func (g *Gateway) Stop() {
	// Close the conn first so a blocked ReadMessage (running in the reader
	// goroutine) returns immediately and listen()'s main loop can observe stop.
	g.mu.Lock()
	if g.conn != nil {
		g.conn.Close()
	}
	g.mu.Unlock()

	close(g.stop)
	<-g.done
}
