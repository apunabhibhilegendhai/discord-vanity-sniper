package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

type TargetRunner struct {
	target  *Target
	gateway *Gateway
	claimer *Claimer
	pools   []*ConnPool // one per proxy entry; pools[0] is the direct pool
	mfa     *MFAHandler
	guard   *Guard
	mfaCancel chan struct{}
}

type Orchestrator struct {
	cfg      *Conf
	runners  []*TargetRunner
	stats    *Stats
	webhook  *WebhookSender
	rateLim  *RateLimiter
	sessions *SessionStore
	cliMode  bool // set true when interactive CLI is active (disables dashboard)
}

func NewOrchestrator(cfg *Conf) *Orchestrator {
	stats := &Stats{StartTime: time.Now(), lat: newLatencyTracker()}
	rl := NewRateLimiter()
	wh := NewWebhookSender(cfg.WebhookURL)
	sessions := NewSessionStore(cfg.SessionPath)
	sessions.Load()

	o := &Orchestrator{
		cfg:      cfg,
		stats:    stats,
		webhook:  wh,
		rateLim:  rl,
		sessions: sessions,
	}

	orchStart := time.Now()
	for i := range cfg.Targets {
			t := &cfg.Targets[i]

			mfa := NewMFAHandler(t, sessions, cfg.Password, cfg.TOTPSecret, cfg.BackupCodes, &cfg.Fingerprint)

			// Prime MFA token synchronously before pools/gateway start, so the
			// first availability signal has a warm token to read. Without this,
			// the background pre-solver (StartRefresh) races the gateway connect
			// and the claim hot path falls back to a synchronous solve, delaying
			// the burst by ~10s. This matches how S-pectral and other snipers
			// solve MFA once upfront.
			if !mfa.EnsureValid() {
				log.Printf("[target %s] WARNING: MFA prime failed — hot path may need fallback solve", t.Vanity)
			}

		// Build one warm pool per proxy entry. t.Proxies is guaranteed non-empty
		// by config.LoadConfig (it defaults to [""] when omitted), and "" is the
		// direct (no-proxy) entry — always at the front so pools[0] is the
		// direct pool. Each pool runs its own rewarmer so a burst that drains it
		// doesn't force a synchronous dial on the next burst's hot path.
		//
		// Pools are warmed CONCURRENTLY across proxies (warmPoolsParallel) rather
		// than one-after-another. This is safe because each proxy dials from a
		// different source IP, so they don't share Cloudflare's per-IP new-TLS-
		// session rate window; the 200ms-per-dial cadence INSIDE each pool (see
		// NewConnPool) is what keeps a single IP under that limit, and that
		// cadence is preserved per-pool. With P proxies this collapses a cold
		// start from P×~3.5s to ~3.5s.
			pools := warmPoolsParallel(t, cfg.WarmConns)
			log.Printf("[target %s] %d pool(s) warmed in %s", t.Vanity, len(pools), time.Since(orchStart))
			for _, pool := range pools {
			pool.StartRewarmer()
		}

		// Vanity Guard: construct even when guard_mode is off so reclaim() can
		// be wired through the claimer without a nil check churn; the guard's
		// Quarantine() is only invoked when the claimer's reclaim path runs,
		// which itself is gated on guardEnabled. The protected set always
		// includes the token owner (captured from READY into target.ownerID) —
		// NewGuard also folds in any configured guard_protected_user_ids.
		var guard *Guard
		if cfg.GuardMode {
			guard = NewGuard(t, mfa, stats, wh, pools[0], cfg.GuardAction, cfg.GuardProtectedUserIDs)
		}

		claimer := NewClaimer(t, cfg, pools, mfa, stats, wh, rl, cfg.BurstCount, cfg.GuardMode, cfg.GuardReclaimMax, cfg.GuardReclaimBackoffMS, guard)
		gateway := NewGateway(t, claimer.available, sessions)

		mfaCancel := &chanCancel{ch: make(chan struct{})}

		runner := &TargetRunner{
			target:    t,
			gateway:   gateway,
			claimer:   claimer,
			pools:     pools,
			mfa:       mfa,
			guard:     guard,
			mfaCancel: mfaCancel.ch,
		}
		o.runners = append(o.runners, runner)

		go claimer.Run()
		go gateway.Run()
		go mfa.StartRefresh(mfaCancel)

		proxyCount := len(pools)
		if proxyCount > 1 {
			log.Printf("[target %s] armed ✅ (%d pools: direct + %d proxy)", t.Vanity, proxyCount, proxyCount-1)
		} else {
			log.Printf("[target %s] armed ✅ (1 direct pool — add proxies for multi-IP burst)", t.Vanity)
		}
			if cfg.GuardMode {
				log.Printf("[target %s] guard: action=%s", t.Vanity, cfg.GuardAction)
			}
		}

	log.Printf("[startup] orchestrator ready in %s (%d target(s))", time.Since(orchStart), len(o.runners))
	return o
}

func (o *Orchestrator) Run() {
	log.Println("=== Discord Vanity Sniper ===")
	log.Printf("Targets: %d", len(o.cfg.Targets))
	log.Printf("Burst: %d | Warm conns: %d", o.cfg.BurstCount, o.cfg.WarmConns)
	if o.cfg.GuardMode {
		log.Printf("Guard: ON (reclaim_max=%d, backoff=%dms)", o.cfg.GuardReclaimMax, o.cfg.GuardReclaimBackoffMS)
	} else {
		log.Printf("Guard: off (enable guard_mode to re-claim if a vanity is lost)")
	}
	log.Printf("Sessions: %s", o.cfg.SessionPath)
	log.Println()

	go o.sessions.AutoSave()

	if o.webhook != nil {
		o.webhook.Send("🚀 Sniper Started", 0x00FFFF, map[string]string{
			"Targets": fmt.Sprintf("%d", len(o.cfg.Targets)),
			"Time":    time.Now().Format(time.RFC3339),
		})
	}

	if !o.cliMode {
		o.dashboard()
	}
}

func (o *Orchestrator) dashboard() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
			checks, claims, errors := o.stats.Snapshot()
			elapsed := time.Since(o.stats.StartTime)
			cps := float64(checks) / elapsed.Seconds()

			latLine := ""
			if p50, p99, ok := o.stats.LatencyPercentiles(); ok {
				latLine = fmt.Sprintf(" | latency p50: %.1f/%.1f/%.1f/%.1fms p99: %.1f/%.1f/%.1f/%.1fms",
					p50.dispatch.Seconds()*1000, p50.local.Seconds()*1000, p50.rtt.Seconds()*1000, p50.total.Seconds()*1000,
					p99.dispatch.Seconds()*1000, p99.local.Seconds()*1000, p99.rtt.Seconds()*1000, p99.total.Seconds()*1000)
			}

			fmt.Printf("\r[stats] checks: %d | claims: %d | errors: %d | speed: %.1f/s | uptime: %s%s   ",
				checks, claims, errors, cps, elapsed.Round(time.Second), latLine)
		}
}

// warmPoolsParallel builds one warm ConnPool per proxy entry concurrently,
// preserving the input order in the returned slice (so pools[0] is the direct
// pool, matching what the claimer and guard expect). Each pool's internal
// warm-up (NewConnPool) dials its conns sequentially with a 200ms cadence to
// stay under Cloudflare's per-IP new-TLS-session rate window — that per-pool
// cadence is preserved; we only parallelize ACROSS pools, which is safe because
// distinct proxies dial from distinct source IPs and therefore don't share that
// rate window.
//
// On a partial failure (one proxy unreachable) we fall back to an empty
// on-demand-dial pool for that entry rather than failing the whole target, so a
// single bad proxy can't disarm a target that has working alternates.
func warmPoolsParallel(t *Target, warmConns int) []*ConnPool {
	proxies := t.Proxies
	pools := make([]*ConnPool, len(proxies))
	var wg sync.WaitGroup
	for i, proxy := range proxies {
		wg.Add(1)
		go func(idx int, p string) {
			defer wg.Done()
			pool, err := NewConnPool(p, warmConns)
			if err != nil {
				log.Printf("[target %s] warm pool for %q failed: %v (falling back to on-demand dial)", t.Vanity, proxyLabel(p), err)
				pool = &ConnPool{addr: "discord.com:443", proxy: p}
			}
			pools[idx] = pool
		}(i, proxy)
	}
	wg.Wait()
	return pools
}

// proxyLabel returns a human-readable label for a proxy entry. "" (direct) maps
// to "direct"; a URL is truncated to "host:port" so secrets aren't logged.
func proxyLabel(proxy string) string {	if proxy == "" {
		return "direct"
	}
	// Strip scheme and auth for the log line: "http://user:pass@1.2.3.4:8080"
	// → "1.2.3.4:8080". Not security-critical (operator's own config) but
	// keeps logs tidy.
	if idx := strings.LastIndex(proxy, "@"); idx >= 0 {
		proxy = proxy[idx+1:]
	}
	if idx := strings.Index(proxy, "://"); idx >= 0 {
		proxy = proxy[idx+3:]
	}
	return proxy
}

func (o *Orchestrator) Shutdown() {
	log.Println("\nshutting down...")

		// Stop the claimers and gateways FIRST so they stop producing session
		// updates. Stopping the session store before the runners would drop any
		// final MFA token / sequence write (e.g. from a claim that lands during
		// shutdown) on the floor.
		for _, r := range o.runners {
			close(r.mfaCancel)
			r.gateway.Stop()
			r.claimer.Stop()
			for _, pool := range r.pools {
				pool.StopRewarmer()
				pool.Close()
			}
		}

	// Now that writers are quiesced, flush & stop the session store.
	o.sessions.Stop()

	var claimed []string
	for _, r := range o.runners {
		r.target.mu.Lock()
		isClaimed := r.target.claimed
		r.target.mu.Unlock()
		if isClaimed {
			claimed = append(claimed, r.target.Vanity)
		}
	}

	if o.webhook != nil {
		title := "🛑 Sniper Shutdown"
		fields := map[string]string{
			"Uptime": time.Since(o.stats.StartTime).Round(time.Second).String(),
		}
		if len(claimed) > 0 {
			var claimedStr string
			for _, v := range claimed {
				claimedStr += "discord.gg/" + v + " "
			}
			fields["Claimed"] = claimedStr
		}
		// Include guard counters when guard was active this session so the
		// operator can see recovery activity at a glance. Quarantines/fails only
		// appear when guard_action is kick/ban and an offender was actually
		// detected.
		if o.cfg.GuardMode {
			reclaims, losses, quarantines, qFails := o.stats.GuardSnapshot()
			if reclaims > 0 || losses > 0 {
				fields["Reclaims"] = fmt.Sprintf("%d", reclaims)
				fields["Losses"] = fmt.Sprintf("%d", losses)
			}
			if quarantines > 0 || qFails > 0 {
				fields["Quarantines"] = fmt.Sprintf("%d", quarantines)
				fields["QuarantineFails"] = fmt.Sprintf("%d", qFails)
			}
		}
			o.webhook.Send(title, 0xFF00FF, fields)
		}

		// Wait for all in-flight webhook Sends (including any success embed
		// spawned moments before Ctrl-C) to finish. Replaces the old
		// time.Sleep(500ms) which was too short for a fresh dial+TLS on slow
		// networks and didn't guarantee delivery at all.
		if o.webhook != nil {
			o.webhook.Flush()
		}

	log.Println("goodbye")
}
