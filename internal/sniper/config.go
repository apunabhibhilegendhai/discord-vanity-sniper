package sniper

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/pquerna/otp/totp"
)

func LoadConfig(path string) (*Conf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Conf
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("no targets in config")
	}

	if cfg.BurstCount <= 0 {
		cfg.BurstCount = 5
	}
	// Only default WarmConns when it was omitted entirely (< 0 sentinel via a
	// missing/zero value). A value of 0 is a legitimate "disable pooling"
	// setting, so distinguish "unset" (0) from "explicitly none" via < 0 is not
	// possible with the int field — instead we treat <= 0 as "use default" but
	// document that warm pooling can't be disabled this way. To truly disable,
	// set warm_connections to 1 (one fresh conn per attempt, no idle pool).
	if cfg.WarmConns <= 0 {
		cfg.WarmConns = 2
	}

	// Speed guarantee: the claim burst spawns BurstCount workers, each calling
	// pool.Get(). If the pool has fewer warm conns than workers, the shortfall
	// is served by a synchronous TLS handshake (1 RTT; measured 68.5ms p50 on
	// this host) — the exact latency the PRD says to eliminate. Forcing warm
	// >= burst means
	// every burst worker grabs a pre-warmed conn and zero handshakes happen on
	// the hot path. Set warm_connections to 1 (or BurstCount to 1) to opt out
	// of the auto-raise; that deliberately signals "I know what I'm doing".
	if cfg.BurstCount > 1 && cfg.WarmConns > 1 && cfg.WarmConns < cfg.BurstCount {
		log.Printf("[config] raising warm_connections %d -> %d to cover burst_count (avoids TLS handshakes on the claim hot path)",
			cfg.WarmConns, cfg.BurstCount)
		cfg.WarmConns = cfg.BurstCount
	}
	if cfg.SessionPath == "" {
		cfg.SessionPath = "session_state.json"
	}

	// Vanity Guard defaults. GuardMode intentionally stays false when unset so
	// the feature is opt-in (it adds claim pressure that can compound an active
	// rate-limit lockout). When enabled, cap the reclaims per loss episode and
	// pace them with a short backoff if the operator didn't configure values.
	if cfg.GuardMode {
		if cfg.GuardReclaimMax <= 0 {
			cfg.GuardReclaimMax = 5
		}
		if cfg.GuardReclaimBackoffMS <= 0 {
			cfg.GuardReclaimBackoffMS = 500
		}
	}

	// GuardAction defaults to "reclaim_only" so enabling guard_mode alone never
	// silently turns on punishment — the operator must opt into kick/ban
	// explicitly. Validate the value up front so a typo fails at startup rather
	// than no-op'ing silently during an attack.
	if cfg.GuardAction == "" {
		cfg.GuardAction = "reclaim_only"
	}
	switch cfg.GuardAction {
	case "reclaim_only", "kick", "ban":
		// ok
	default:
		return nil, fmt.Errorf("invalid guard_action %q (want reclaim_only|kick|ban)", cfg.GuardAction)
	}

	// Validate the TOTP secret early (if provided) so a malformed secret fails
	// at startup instead of mid-claim. totp.GenerateCode will surface the same
	// error later; this just front-loads it.
	if cfg.TOTPSecret != "" {
		if _, err := totp.GenerateCode(cfg.TOTPSecret, time.Now()); err != nil {
			return nil, fmt.Errorf("invalid totp_secret: %w", err)
		}
	}

	// Resolve the browser fingerprint from the single "browser" field (or infer
	// from user_agent, or default to chrome). This sets cfg.Fingerprint's
	// UserAgent and SuperPropsB64 to a self-consistent set that matches the TLS
	// JA3 used by tlsdial.go. See fingerprint.go for the profile presets.
	ResolveFingerprint(&cfg)

	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if t.GuildID == "" {
			return nil, fmt.Errorf("target %d: guild_id required", i)
		}
		if t.Vanity == "" {
			return nil, fmt.Errorf("target %d: vanity required", i)
		}
		// Token is required to actually claim, but if it's empty AND we have
		// email+password configured, the auto-login step in main.go will mint a
		// fresh one at startup. Only hard-fail when there's no way to get a token
		// at all.
		if t.Token == "" && cfg.Email == "" && cfg.Password == "" && t.Password == "" {
			return nil, fmt.Errorf("target %d: token required (or set email+password for auto-login)", i)
		}
		if len(t.Proxies) == 0 {
			t.Proxies = []string{""}
		}
		if t.Password == "" {
			t.Password = cfg.Password
		}
		// Legacy grace_end keys are intentionally ignored: the grace burst was
		// never implemented, and removing the field keeps old configs loading
		// (encoding/json ignores unknown object keys).
	}

	return &cfg, nil
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
