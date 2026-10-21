package sniper

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

type TargetRunner struct {
	target    *Target
	gateway   *Gateway
	claimer   *Claimer
	pools     []*ConnPool // one per proxy entry; pools[0] is the direct pool
	mfa       *MFAHandler
	guard     *Guard
	mfaCancel chan struct{}

	// startMu guards started, armedAt and armWarnings. Start is idempotent and
	// safe to call from the orchestrator's single StartAll entry point;
	// Shutdown reads IsStarted() rather than touching the field directly.
	startMu     sync.Mutex
	started     bool
	armedAt     time.Time
	armWarnings []string
}

// IsStarted reports whether Start has launched this runner's gateway + claimer.
func (r *TargetRunner) IsStarted() bool {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	return r.started
}

// ArmedAt is when this lane finished priming MFA and warming its pools. It is
// set before the runner is visible to StartAll, so reading it after
// NewOrchestrator returns is safe.
func (r *TargetRunner) ArmedAt() time.Time {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	return r.armedAt
}

// ArmWarnings returns a copy of the non-fatal problems encountered while
// arming this lane (for example a failed MFA prime or an unwarmable proxy).
// The lane still starts; these are the degraded-but-usable states.
func (r *TargetRunner) ArmWarnings() []string {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	return append([]string(nil), r.armWarnings...)
}

func (r *TargetRunner) setArmed(warnings []string) {
	r.startMu.Lock()
	r.armedAt = time.Now()
	r.armWarnings = append([]string(nil), warnings...)
	r.startMu.Unlock()
}

// ArmFailure identifies a target that could not be armed. Failed lanes are
// deliberately not added to Orchestrator.runners: StartAll skips them instead
// of starting a half-built lane, and the failure remains queryable here.
type ArmFailure struct {
	Index   int
	GuildID string
	Vanity  string
	Err     error
	At      time.Time
}

func (f ArmFailure) Error() string {
	return fmt.Sprintf("target %s (guild %s): %v", f.Vanity, f.GuildID, f.Err)
}

type Orchestrator struct {
	cfg      *Conf
	runners  []*TargetRunner
	stats    *Stats
	webhook  *WebhookSender
	rateLim  *RateLimiter
	sessions *SessionStore

	// startOnce makes StartAll the single owner of run state across every
	// target: however many times it is called (and from whichever goroutine),
	// each runner is launched exactly once, concurrently with the others.
	startOnce sync.Once
	stopOnce  sync.Once
	stopCh    chan struct{}

	// startHook is a test seam. When nil (production), StartAll calls the real
	// runner Start. Tests set it to observe that every configured target is
	// launched without opening Discord connections.
	startHook func(*TargetRunner)

	// warmPools is the per-target pool-warming function. Production uses
	// warmPoolsParallelReport; tests can inject a fake dialer. It never changes
	// what a pool does after it is armed.
	warmPools func(*Target, int) ([]*ConnPool, []string)

	// armMu guards armFailures, which is populated during NewOrchestrator's
	// parallel arm phase and read by ArmFailures/StartAll.
	armMu       sync.Mutex
	armFailures []ArmFailure
}

type armLaneFunc func(*Target) (*TargetRunner, []string, error)
type warmPoolsFunc func(*Target, int) ([]*ConnPool, []string)

type armResult struct {
	idx      int
	runner   *TargetRunner
	warnings []string
	err      error
	started  time.Time
	finished time.Time
}

// armLaneTimeout bounds the whole arm phase. A lane that hangs (a stalled
// handshake, a proxy that accepts TCP but never completes TLS, or a bug in a
// test hook) is marked failed and the other lanes still start. This is a code
// constant by design: it is a safety bound, not an operator-tunable speed knob.
const armLaneTimeout = 30 * time.Second

// ArmFailures returns the lanes that could not arm. The slice is ordered by
// target index, so it is stable regardless of goroutine completion order.
func (o *Orchestrator) ArmFailures() []ArmFailure {
	o.armMu.Lock()
	defer o.armMu.Unlock()
	return append([]ArmFailure(nil), o.armFailures...)
}

func NewOrchestrator(cfg *Conf) *Orchestrator {
	return newOrchestratorWithTimeout(cfg, nil, nil, armLaneTimeout)
}

// newOrchestrator is the testable constructor. armLane and warmPools are
// optional seams; nil selects the production implementation. Arming is a
// parallel phase with a single completion barrier: every lane is primed and
// warm, or has a visible ArmFailure, before this function returns. No runner
// is added to o.runners until the barrier closes, so StartAll can never see a
// half-armed lane.
func newOrchestrator(cfg *Conf, armLane armLaneFunc, warmPools warmPoolsFunc) *Orchestrator {
	return newOrchestratorWithTimeout(cfg, armLane, warmPools, armLaneTimeout)
}

func newOrchestratorWithTimeout(cfg *Conf, armLane armLaneFunc, warmPools warmPoolsFunc, timeout time.Duration) *Orchestrator {
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
		stopCh:   make(chan struct{}),
	}
	if warmPools == nil {
		warmPools = warmPoolsParallelReport
	}
	o.warmPools = warmPools
	if armLane == nil {
		armLane = o.armTarget
	}

	orchStart := time.Now()

	results := make(chan armResult, len(cfg.Targets))
	for i := range cfg.Targets {
		go func(idx int, t *Target) {
			started := time.Now()
			runner, warnings, err := safeArmLane(armLane, t)
			results <- armResult{
				idx:      idx,
				runner:   runner,
				warnings: warnings,
				err:      err,
				started:  started,
				finished: time.Now(),
			}
		}(i, &cfg.Targets[i])
	}

	runners := make([]*TargetRunner, len(cfg.Targets))
	warnings := make([][]string, len(cfg.Targets))
	failures := make([]ArmFailure, len(cfg.Targets))
	failed := make([]bool, len(cfg.Targets))
	pending := make([]bool, len(cfg.Targets))
	for i := range pending {
		pending[i] = true
	}
	remaining := len(cfg.Targets)
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for remaining > 0 {
		select {
		case res := <-results:
			if !pending[res.idx] {
				continue
			}
			pending[res.idx] = false
			remaining--
			if res.err == nil && res.runner == nil {
				res.err = fmt.Errorf("arm lane produced no runner")
			}
			if res.err != nil {
				failed[res.idx] = true
				failures[res.idx] = ArmFailure{
					Index:   res.idx,
					GuildID: cfg.Targets[res.idx].GuildID,
					Vanity:  cfg.Targets[res.idx].Vanity,
					Err:     res.err,
					At:      res.finished,
				}
				log.Printf("[arm] target %s failed: %v", cfg.Targets[res.idx].Vanity, res.err)
				continue
			}
			runners[res.idx] = res.runner
			warnings[res.idx] = res.warnings
			log.Printf("[arm] target %s ready in %s", cfg.Targets[res.idx].Vanity, res.finished.Sub(res.started))

		case <-timer.C:
			late := 0
			for i := range pending {
				if !pending[i] {
					continue
				}
				pending[i] = false
				late++
				failed[i] = true
				failures[i] = ArmFailure{
					Index:   i,
					GuildID: cfg.Targets[i].GuildID,
					Vanity:  cfg.Targets[i].Vanity,
					Err:     fmt.Errorf("arm timeout after %s", timeout),
					At:      time.Now(),
				}
				log.Printf("[arm] target %s timed out after %s", cfg.Targets[i].Vanity, timeout)
			}
			remaining = 0
			if late > 0 {
				// The timed-out goroutines still hold their result slot. Drain it
				// in the background so a late success is cleaned up rather than
				// leaking its claimer and pool goroutines.
				go drainArmResults(results, late)
			}
		}
	}

	for i, runner := range runners {
		if runner == nil {
			continue
		}
		if runner.ArmedAt().IsZero() {
			runner.setArmed(warnings[i])
		}
		o.runners = append(o.runners, runner)
		if runner.mfa != nil && runner.mfaCancel != nil {
			go runner.mfa.StartRefresh(&chanCancel{ch: runner.mfaCancel})
		}
	}

	for i := range cfg.Targets {
		if failed[i] {
			o.armFailures = append(o.armFailures, failures[i])
		}
	}

	log.Printf("[startup] arm phase complete in %s: %d/%d target(s) armed, %d failed",
		time.Since(orchStart), len(o.runners), len(cfg.Targets), len(o.armFailures))
	return o
}

func safeArmLane(armLane armLaneFunc, t *Target) (runner *TargetRunner, warnings []string, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic while arming: %v\n%s", p, debug.Stack())
		}
	}()
	return armLane(t)
}

// drainArmResults collects results that arrive after the arm barrier timed out
// and tears down any runner they produced. It must be started only after the
// barrier has stopped waiting; the channel is buffered to len(targets), so the
// late goroutines never block on the send.
func drainArmResults(results <-chan armResult, n int) {
	for i := 0; i < n; i++ {
		res := <-results
		cleanupArmedRunner(res.runner)
	}
}

// cleanupArmedRunner releases a runner that was built after its lane was
// already marked failed by the timeout. It deliberately does not call
// Claimer.Stop (which waits for Run's done channel); the claimer was never
// started, so closing stop is enough to release its sentries and publisher.
func cleanupArmedRunner(r *TargetRunner) {
	if r == nil {
		return
	}
	if r.mfaCancel != nil {
		close(r.mfaCancel)
	}
	if r.claimer != nil {
		if r.claimer.stop != nil {
			close(r.claimer.stop)
		}
		r.claimer.sentryWG.Wait()
	}
	for _, p := range r.pools {
		p.StopRewarmer()
		p.Close()
	}
}

// armTarget primes one lane: MFA token, warm pools, guard, claimer and
// gateway. It is safe to call concurrently for distinct targets; the shared
// stats/webhook/rate-limiter/session store are concurrency-safe. A non-nil
// error means this lane must not start (for example, no usable token).
func (o *Orchestrator) armTarget(t *Target) (*TargetRunner, []string, error) {
	if t.Token == "" {
		return nil, nil, fmt.Errorf("no usable token (mint failed or token missing)")
	}

	var warnings []string
	mfa := NewMFAHandler(t, o.sessions, o.cfg.Password, o.cfg.TOTPSecret, o.cfg.BackupCodes, &o.cfg.Fingerprint)

	// Prime MFA token synchronously before pools/gateway start, so the first
	// availability signal has a warm token to read. Without this, the background
	// pre-solver (StartRefresh) races the gateway connect and the claim hot path
	// falls back to a synchronous solve, delaying the burst by ~10s. A failed
	// prime is degraded, not fatal: the claimer has a synchronous fallback, and
	// the warning is attached to the runner so the state is visible.
	if !mfa.EnsureValid() {
		warnings = append(warnings, "MFA prime failed — hot path may need fallback solve")
		log.Printf("[target %s] WARNING: MFA prime failed — hot path may need fallback solve", t.Vanity)
	}

	warm := o.warmPools
	if warm == nil {
		warm = warmPoolsParallelReport
	}
	poolStart := time.Now()
	pools, poolWarnings := warm(t, o.cfg.WarmConns)
	warnings = append(warnings, poolWarnings...)
	if len(pools) == 0 {
		pools = []*ConnPool{{addr: "discord.com:443"}}
		warnings = append(warnings, "no warm pool available — using on-demand dialing")
	}
	log.Printf("[target %s] %d pool(s) warmed in %s", t.Vanity, len(pools), time.Since(poolStart))
	for _, pool := range pools {
		pool.StartRewarmer()
	}

	// Vanity Guard: construct even when guard_mode is off so reclaim() can be
	// wired through the claimer without a nil check churn; the guard's
	// Quarantine() is only invoked when the claimer's reclaim path runs, which
	// itself is gated on guardEnabled. The protected set always includes the
	// token owner (captured from READY into target.ownerID) — NewGuard also
	// folds in any configured guard_protected_user_ids.
	var guard *Guard
	if o.cfg.GuardMode {
		guard = NewGuard(t, mfa, o.stats, o.webhook, pools[0], o.cfg.GuardAction, o.cfg.GuardProtectedUserIDs)
	}

	claimer := NewClaimer(t, o.cfg, pools, mfa, o.stats, o.webhook, o.rateLim, o.cfg.BurstCount, o.cfg.GuardMode, o.cfg.GuardReclaimMax, o.cfg.GuardReclaimBackoffMS, guard)
	gateway := NewGateway(t, claimer.available, o.sessions)
	gateway.stats = o.stats

	runner := &TargetRunner{
		target:    t,
		gateway:   gateway,
		claimer:   claimer,
		pools:     pools,
		mfa:       mfa,
		guard:     guard,
		mfaCancel: make(chan struct{}),
	}
	runner.setArmed(warnings)

	proxyCount := len(pools)
	if proxyCount > 1 {
		log.Printf("[target %s] armed ✅ (%d pools: direct + %d proxy)", t.Vanity, proxyCount, proxyCount-1)
	} else {
		log.Printf("[target %s] armed ✅ (1 direct pool — add proxies for multi-IP burst)", t.Vanity)
	}
	if o.cfg.GuardMode {
		log.Printf("[target %s] guard: action=%s", t.Vanity, o.cfg.GuardAction)
	}
	return runner, warnings, nil
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

	o.StartAll()
	o.dashboard()
}

func (o *Orchestrator) dashboard() {
	// On an interactive terminal the stats line repaints a single in-place
	// line (\r) every 5s. On redirected output — Actions log streams, files,
	// pipes — \r has no cursor semantics: each repaint renders as a new line,
	// which would flood a 5h45m session's logs with ~4,100 near-identical
	// entries. Non-TTY output logs a compact checkpoint every 5 minutes
	// instead.
	isTTY := stdoutIsTTY()
	period := 5 * time.Second
	repaint := "\r[stats] %s   "
	if !isTTY {
		period = 5 * time.Minute
		repaint = "[stats] %s\n"
	}

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-o.stopCh:
			return
		case <-ticker.C:
		}
		checks, claims, errors := o.stats.Snapshot()
		elapsed := time.Since(o.stats.StartTime)
		cps := float64(checks) / elapsed.Seconds()

		latLine := ""
		if p50, p99, ok := o.stats.LatencyPercentiles(); ok {
			latLine = fmt.Sprintf(" | latency p50: %.1f/%.1f/%.1f/%.1fms p99: %.1f/%.1f/%.1f/%.1fms",
				p50.dispatch.Seconds()*1000, p50.local.Seconds()*1000, p50.rtt.Seconds()*1000, p50.total.Seconds()*1000,
				p99.dispatch.Seconds()*1000, p99.local.Seconds()*1000, p99.rtt.Seconds()*1000, p99.total.Seconds()*1000)
		}

		body := fmt.Sprintf("checks: %d | claims: %d | errors: %d | speed: %.1f/s | uptime: %s%s",
			checks, claims, errors, cps, elapsed.Round(time.Second), latLine)
		fmt.Printf(repaint, body)
	}
}

// stdoutIsTTY reports whether stdout is an interactive terminal. Files and
// pipes (including CI log capture) are char-device-less → false.
func stdoutIsTTY() bool {
	st, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
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
	pools, _ := warmPoolsParallelReport(t, warmConns)
	return pools
}

// warmPoolsParallelReport is warmPoolsParallel plus the per-proxy degradation
// messages. A failed proxy still yields an on-demand-dial fallback pool, so it
// degrades the lane rather than disarming it; the message is surfaced through
// TargetRunner.ArmWarnings().
func warmPoolsParallelReport(t *Target, warmConns int) ([]*ConnPool, []string) {
	proxies := t.Proxies
	pools := make([]*ConnPool, len(proxies))
	warnings := make([][]string, len(proxies))
	var wg sync.WaitGroup
	for i, proxy := range proxies {
		wg.Add(1)
		go func(idx int, p string) {
			defer wg.Done()
			pool, err := NewConnPool(p, warmConns)
			if err != nil {
				msg := fmt.Sprintf("warm pool for %q failed: %v (falling back to on-demand dial)", proxyLabel(p), err)
				log.Printf("[target %s] %s", t.Vanity, msg)
				warnings[idx] = append(warnings[idx], msg)
				pool = &ConnPool{addr: "discord.com:443", proxy: p}
			}
			pools[idx] = pool
		}(i, proxy)
	}
	wg.Wait()

	var out []string
	for _, ws := range warnings {
		out = append(out, ws...)
	}
	return pools, out
}

// proxyLabel returns a human-readable label for a proxy entry. "" (direct) maps
// to "direct"; a URL is truncated to "host:port" so secrets aren't logged.
func proxyLabel(proxy string) string {
	if proxy == "" {
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

// Start launches this runner's claimer and gateway. Idempotent: the
// orchestrator's StartAll may be called more than once without arming a target
// twice, and Shutdown uses IsStarted to decide what to stop.
func (r *TargetRunner) Start() {
	r.startMu.Lock()
	if r.started {
		r.startMu.Unlock()
		return
	}
	r.started = true
	r.startMu.Unlock()

	go r.claimer.Run()
	go r.gateway.Run()
}

// StartAll is the single entry point for run state across targets. It launches
// every configured runner exactly once, so an N-target config monitors all N
// vanities concurrently from one command. The startHook seam is only used by
// tests; production always calls the real runner Start.
func (o *Orchestrator) StartAll() {
	o.startOnce.Do(func() {
		if failures := o.ArmFailures(); len(failures) > 0 {
			log.Printf("[run] %d target(s) failed to arm and will not start", len(failures))
			for _, f := range failures {
				log.Printf("[run] skipped target %s: %v", f.Vanity, f.Err)
			}
		}
		for i, r := range o.runners {
			// A signal that arrives during startup must not launch runners after
			// Shutdown has already begun tearing them down.
			select {
			case <-o.stopCh:
				return
			default:
			}
			if o.startHook != nil {
				o.startHook(r)
			} else {
				r.Start()
			}
			log.Printf("[run] target %d/%d started: discord.gg/%s (guild %s)",
				i+1, len(o.runners), r.target.Vanity, r.target.GuildID)
		}
	})
}

func (o *Orchestrator) Shutdown() {
	log.Println("\nshutting down...")

	o.stopOnce.Do(func() { close(o.stopCh) })

	// Stop the claimers and gateways FIRST so they stop producing session
	// updates. Stopping the session store before the runners would drop any
	// final MFA token / sequence write (e.g. from a claim that lands during
	// shutdown) on the floor.
	for _, r := range o.runners {
		if r.mfaCancel != nil {
			close(r.mfaCancel)
		}
		if r.IsStarted() {
			r.gateway.Stop()
			r.claimer.Stop()
		}
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
