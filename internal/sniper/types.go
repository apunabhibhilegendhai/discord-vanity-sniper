package sniper

import (
	"sync"
	"time"
)

// currentVanity reads the target vanity under the lock that owns it. Every
// detection route must use this rather than reading target.Vanity directly.
func (t *Target) currentVanity() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.Vanity
}

// vanityFree is the single owner of the "is the vanity free?" decision.
// current is the target's vanity, observed is the code parsed by a route, and
// valid is that route's parse result. An unparseable or partial payload is
// never free. A valid empty code (JSON null / no vanity set) is free.
func vanityFree(current, observed string, valid bool) bool {
	if !valid {
		return false
	}
	return observed == "" || observed != current
}

// observeVanity is the counter-aware entry point shared by both detection
// triggers. A valid parsed code is one observation/check; malformed payloads
// never count and never resolve to free. Keeping the increment here prevents
// each gateway route and the poller from growing its own counter.
func observeVanity(stats *Stats, current, observed string, valid bool) bool {
	if valid && stats != nil {
		stats.AddChecks(1)
	}
	return vanityFree(current, observed, valid)
}

type Target struct {
	GuildID  string   `json:"guild_id"`
	Vanity   string   `json:"vanity"`
	Token    string   `json:"token"`
	Password string   `json:"password,omitempty"`
	Proxies  []string `json:"proxies"`

	mu sync.Mutex
	// claimed is set true after the first successful claim. Without Vanity
	// Guard it also doubles as the "stop listening" flag (claimer drops every
	// later availability signal). With Guard enabled, guardArmed gates whether
	// a later loss signal triggers re-claim.
	claimed    bool
	proxyIndex int

	// ownerID is the Discord user id of the token holder, captured from the
	// gateway READY event. The Vanity Guard uses it to whitelist the token
	// owner so a legitimate change made by the operator's own account is never
	// punished by kick/ban quarantine. Always implicitly protected.
	ownerID string

	// Vanity Guard state — all guarded by mu.
	// guardArmed: set true after the first claim when guard_mode is on; later
	//   loss signals are acted on only while this is set.
	// reclaimAttempts: attempts in the current loss episode; reset to 0 on a
	//   successful re-claim so the cap applies per-episode, not per-session.
	// lost: terminal — set when the reclaim cap is exhausted without recovery.
	//   Further loss signals are dropped to avoid webhook spam and rate-limit
	//   burnout.
	guardArmed      bool
	reclaimAttempts int
	lost            bool
}

type Conf struct {
	WebhookURL  string   `json:"webhook_url"`
	TOTPSecret  string   `json:"totp_secret"`
	Password    string   `json:"password,omitempty"`
	Email       string   `json:"email,omitempty"`
	BackupCodes []string `json:"backup_codes,omitempty"`
	BurstCount  int      `json:"burst_count"`
	WarmConns   int      `json:"warm_connections"`
	SessionPath string   `json:"session_path"`

	// Vanity Guard (FR-08): after a successful claim, keep defending the target
	// vanity. If a GUILD_UPDATE arrives showing the guild's vanity is no longer
	// ours, fire a re-claim burst, retrying up to ReclaimMax times with
	// ReclaimBackoffMS between attempts. Defaults to off — guard adds claim
	// pressure and can compound an active rate-limit lockout, so it's opt-in.
	GuardMode             bool `json:"guard_mode"`
	GuardReclaimMax       int  `json:"guard_reclaim_max"`
	GuardReclaimBackoffMS int  `json:"guard_reclaim_backoff_ms"`

	// GuardAction selects what the guard does to the offender (the audit-log
	// actor who changed the vanity) after detecting an unauthorized change.
	//   "reclaim_only" (default): only revert the vanity; no punishment.
	//   "kick": DELETE /guilds/{g}/members/{uid} the offender.
	//   "ban":   PUT /guilds/{g}/bans/{uid} the offender (degrades to kick on
	//            a 403 role-hierarchy block).
	// In all modes the reclaim burst still fires (the revert is the core
	// defense). Punishment requires KICK_MEMBERS/BAN_MEMBERS + a top role
	// above the offender; a 403 is logged and the revert is relied on.
	GuardAction string `json:"guard_action"`

	// GuardProtectedUserIDs are user ids that must NEVER be punished by the
	// guard, even if the audit log names them as the offender. The token
	// owner's id is always implicitly protected (captured from READY).
	GuardProtectedUserIDs []string `json:"guard_protected_user_ids"`

	Browser     string      `json:"browser"` // "chrome" (default) or "firefox" — single source of truth for TLS+UA+super-props
	Targets     []Target    `json:"targets"`
	Fingerprint Fingerprint `json:"fingerprint"`
}

type Fingerprint struct {
	DcfDuid       string `json:"dcfduid"`
	SdcfDuid      string `json:"sdcfduid"`
	SuperPropsB64 string `json:"super_properties_b64"`
	UserAgent     string `json:"user_agent"`
}

type RateBucket struct {
	mu             sync.Mutex
	remaining      int
	limit          int
	resetAt        time.Time
	backoff        time.Time
	scope          string
	lastRetryAfter string
}

type ProxyScore struct {
	addr    string
	latency time.Duration
	alive   bool
	mu      sync.Mutex
	fails   int
}

type Stats struct {
	mu        sync.Mutex
	Checks    int64
	Claims    int64
	Errors    int64
	StartTime time.Time

	// Latency breakdown (per-claim episode): frame-arrival→fire→wire-write→RTT.
	// One shared tracker across all targets — the values are small (latSample)
	// and the dashboard reads p50/p99 globally. record() runs only on the
	// post-success path (firstSuccessOnce), never on the wake→wire hot path.
	lat *latencyTracker

	// Vanity Guard counters: reclaims (successful re-claims after a loss) and
	// losses (episodes where the reclaim cap was exhausted without recovery).
	Reclaims int64
	Losses   int64

	// Quarantine counters (Vanity Guard offender punishment): quarantines
	// (kick/ban landed) and quarantineFails (403 role-hierarchy block or other
	// failure; revert was relied on instead).
	Quarantines     int64
	QuarantineFails int64
}

func (s *Stats) AddChecks(n int) {
	s.mu.Lock()
	s.Checks += int64(n)
	s.mu.Unlock()
}

func (s *Stats) AddClaim() {
	s.mu.Lock()
	s.Claims++
	s.mu.Unlock()
}

func (s *Stats) AddError() {
	s.mu.Lock()
	s.Errors++
	s.mu.Unlock()
}

func (s *Stats) AddReclaim() {
	s.mu.Lock()
	s.Reclaims++
	s.mu.Unlock()
}

func (s *Stats) AddLoss() {
	s.mu.Lock()
	s.Losses++
	s.mu.Unlock()
}

func (s *Stats) AddQuarantine() {
	s.mu.Lock()
	s.Quarantines++
	s.mu.Unlock()
}

func (s *Stats) AddQuarantineFail() {
	s.mu.Lock()
	s.QuarantineFails++
	s.mu.Unlock()
}

func (s *Stats) Snapshot() (checks, claims, errors int64) {
	s.mu.Lock()
	checks = s.Checks
	claims = s.Claims
	errors = s.Errors
	s.mu.Unlock()
	return
}

// RecordLatency appends a claim-episode latency sample (frame→wire breakdown).
// Safe to call with a zero-value Stats (lat nil) — it's a no-op then.
func (s *Stats) RecordLatency(sample latSample) {
	if s == nil || s.lat == nil {
		return
	}
	s.lat.record(sample)
}

// LatencyPercentiles returns p50/p99 latency samples across recorded claims,
// for the dashboard. ok=false before any claim has landed.
func (s *Stats) LatencyPercentiles() (p50, p99 latSample, ok bool) {
	if s == nil || s.lat == nil {
		return
	}
	return s.lat.Percentiles()
}

// LatencyCount returns how many latency samples are in the ring.
func (s *Stats) LatencyCount() int {
	if s == nil || s.lat == nil {
		return 0
	}
	return s.lat.Count()
}

// GuardSnapshot returns the Vanity Guard counters for the shutdown webhook and
// dashboard. Returns reclaims, losses, quarantines, quarantineFails.
func (s *Stats) GuardSnapshot() (reclaims, losses, quarantines, quarantineFails int64) {
	s.mu.Lock()
	reclaims = s.Reclaims
	losses = s.Losses
	quarantines = s.Quarantines
	quarantineFails = s.QuarantineFails
	s.mu.Unlock()
	return
}

var respBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 2048) },
}
