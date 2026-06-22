package main

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
		target:    t,
		token:     t.Token,
		state:     &GatewayState{},
		available: available,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		sessions:  sessions,
		key:       key,
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
			// Dial failures are transient (network). Back off and retry.
			log.Printf("[gateway %s] connect error: %v", g.target.Vanity, err)
			time.Sleep(retryDelay)
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
		_, msg, err := g.conn.ReadMessage()
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

	resumeAttempts := 0

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

			if err := json.Unmarshal(res.msg, &packet); err != nil {
				// Re-arm the reader for the next message.
				go reader()
				continue
			}

			// T0: frame-arrival baseline for the latency breakdown. Captured once
			// per frame (right after the Op/Seq/Type decode) and threaded through
			// every available-signal path so the claimer can measure dispatch→wire.
			frameT0 := time.Now()

			if packet.Seq > 0 {
				g.mu.Lock()
				g.state.Sequence = packet.Seq
				g.mu.Unlock()
				// Persist the sequence lock-free for the coalesced flusher to
				// pick up. The OLD code called sessions.UpdateSequence here,
				// which took the shared SessionStore write lock (one mutex for
				// every target) on every single WS frame — serializing all
				// gateways' receive loops and churning the dirty/AutoSave flag.
				// Resume only needs an approximately-recent seq (Discord replays
				// gaps), so a 2s coalesce window is correct and far cheaper.
				g.seqPending.Store(int64(packet.Seq))
			}

			switch packet.Op {
			case 0: // Dispatch
				resumeAttempts = 0
				g.handleDispatch(packet.Type, packet.Data, frameT0)

			case 7: // Reconnect
				g.conn.Close()
				return nil

			case 9: // Invalid Session
				resumeAttempts++
				g.conn.Close()

				// For op 9, packet.Data is the bare bool `d` field directly
				// (true = resumable, false = must re-identify). Unmarshaling
				// into a struct silently fails, so unmarshal the raw bool.
				var resumeable bool
				if err := json.Unmarshal(packet.Data, &resumeable); err != nil {
					resumeable = false
				}

				if !resumeable || resumeAttempts >= 3 {
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
					resumeAttempts = 0
					if !resumeable {
						log.Printf("[gateway %s] session invalidated, will re-identify", g.target.Vanity)
					} else {
						log.Printf("[gateway %s] resume exhausted after %d attempts, re-identifying", g.target.Vanity, 3)
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
				ID            string `json:"id"`
				VanityURLCode string `json:"vanity_url_code"`
			} `json:"guilds"`
		}
		json.Unmarshal(data, &ready)
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
			log.Printf("[gateway %s] ready as %s (%s) session=%s",
				g.target.Vanity, ready.User.Username, ready.User.ID, shortID(ready.SessionID))
			log.Printf("[gateway %s] READY in %s from process start", g.target.Vanity, time.Since(processStartTime))

		for _, guild := range ready.Guilds {
			if guild.ID == g.target.GuildID {
				g.mu.Lock()
				currentVanity := g.target.Vanity
				g.mu.Unlock()
					if guild.VanityURLCode == "" || guild.VanityURLCode != currentVanity {
						log.Printf("[gateway %s] guild has vanity=%q, target=%s → available",
							currentVanity, guild.VanityURLCode, currentVanity)
						select {
						case g.available <- frameT0:
						default:
						}
					} else {
					log.Printf("[gateway %s] guild matches target vanity=%q — waiting",
						currentVanity, guild.VanityURLCode)
				}
				break
			}
		}

	case "RESUMED":
		log.Printf("[gateway %s] resumed session", g.target.Vanity)
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

		var guild struct {
			ID            string `json:"id"`
			VanityURLCode string `json:"vanity_url_code"`
		}
		json.Unmarshal(data, &guild)
		if guild.ID == g.target.GuildID {
			g.mu.Lock()
			currentVanity := g.target.Vanity
			g.mu.Unlock()

			if guild.VanityURLCode == "" || guild.VanityURLCode != currentVanity {
				log.Printf("[gateway %s] vanity changed '%s' -> '%s'", currentVanity, guild.VanityURLCode, currentVanity)
				select {
				case g.available <- frameT0:
				default:
				}
			}
		}

	case "GUILD_CREATE":
		var guild struct {
			ID            string `json:"id"`
			VanityURLCode string `json:"vanity_url_code"`
		}
		json.Unmarshal(data, &guild)
		if g.target != nil && guild.ID == g.target.GuildID {
			log.Printf("[gateway %s] GUILD_CREATE vanity=%q", g.target.Vanity, guild.VanityURLCode)
			g.mu.Lock()
			currentVanity := g.target.Vanity
			g.mu.Unlock()
			if guild.VanityURLCode == "" || guild.VanityURLCode != currentVanity {
				log.Printf("[gateway %s] guild ready, vanity_code=%q → available",
					currentVanity, guild.VanityURLCode)
				select {
				case g.available <- frameT0:
				default:
				}
			} else {
				log.Printf("[gateway %s] guild ready, vanity_code=%q matches — waiting",
					currentVanity, guild.VanityURLCode)
			}
		}

	case "GUILD_DELETE":
		var guild struct {
			ID string `json:"id"`
		}
		json.Unmarshal(data, &guild)
		if guild.ID == g.target.GuildID {
			log.Printf("[gateway %s] guild deleted, signaling available", g.target.Vanity)
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
		log.Printf("[gateway %s] REST check: dial error: %v", g.target.Vanity, err)
		return
	}
	defer conn.Close()

	req := fmt.Sprintf(
		"GET /api/v9/guilds/%s/vanity-url HTTP/1.1\r\nHost: discord.com\r\nAuthorization: %s\r\nConnection: close\r\n\r\n",
		g.target.GuildID, g.token,
	)
	conn.Write([]byte(req))

	resp := make([]byte, 2048)
	n, _ := conn.Read(resp)

	statusLine := extractStatusLine(resp[:n])
	body := extractBody(resp[:n])
	log.Printf("[gateway %s] REST check — status: %s body: %s", g.target.Vanity, statusLine, body)

	// If not a 200, don't signal available — wait for gateway event
	if !isStatusOK(resp[:n]) {
		log.Printf("[gateway %s] REST check: non-200 (%s), waiting for gateway event", g.target.Vanity, statusLine)
		return
	}

	// Response 200 with {"code":"vanity"} means vanity is set
	if bytes.Contains(resp[:n], []byte(`"code":"`+g.target.Vanity+`"`)) {
		log.Printf("[gateway %s] REST check: vanity already set, waiting for change", g.target.Vanity)
		return
	}

	log.Printf("[gateway %s] REST check: vanity not set or different, signaling available", g.target.Vanity)
	select {
	case g.available <- time.Now():
	default:
	}
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
