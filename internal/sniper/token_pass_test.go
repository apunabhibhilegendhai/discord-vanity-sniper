package sniper

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func tokenTestConf(t *testing.T, tokens ...string) *Conf {
	t.Helper()
	targets := make([]Target, len(tokens))
	for i, tok := range tokens {
		targets[i] = Target{
			GuildID: fmt.Sprintf("%018d", i+1),
			Vanity:  fmt.Sprintf("token-lane-%d", i),
			Token:   tok,
		}
	}
	return &Conf{
		Targets: targets,
		Fingerprint: Fingerprint{
			UserAgent:     "test-ua",
			SuperPropsB64: "test-super-props",
		},
	}
}

// TestEnsureTokensValidatesConcurrently measures the token-validation pass:
// three valid tokens should be checked in roughly one delay, not three.
func TestEnsureTokensValidatesConcurrently(t *testing.T) {
	const lanes = 3
	const delay = 100 * time.Millisecond

	cfg := tokenTestConf(t, "token-0", "token-1", "token-2")
	var calls atomic.Int32
	validate := func(string, string, string, string) bool {
		calls.Add(1)
		time.Sleep(delay)
		return true
	}
	mint := func(string, string, string, string, string) (string, error) {
		t.Error("mint called for already-valid tokens")
		return "", errors.New("unexpected mint")
	}

	start := time.Now()
	err := ensureTokensWith(cfg, filepath.Join(t.TempDir(), "config.json"), validate, mint)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ensureTokensWith: %v", err)
	}
	if got := calls.Load(); got != lanes {
		t.Fatalf("validate calls = %d, want %d", got, lanes)
	}
	if elapsed >= 2*delay {
		t.Fatalf("token validation took %s for %d lanes; expected concurrent (~%s)", elapsed, lanes, delay)
	}
	t.Logf("token validation: lanes=%d wall=%s (serial would be ~%s)",
		lanes, elapsed.Round(time.Millisecond), lanes*delay)
}

// TestEnsureTokensCoalescesSameAccountMint proves targets sharing credentials
// wait on one login instead of racing duplicate mints.
func TestEnsureTokensCoalescesSameAccountMint(t *testing.T) {
	cfg := tokenTestConf(t, "", "")
	cfg.Email = "operator@example.test"
	cfg.Password = "hunter2"
	cfg.TOTPSecret = "JBSWY3DPEHPK3PXP"

	var mints atomic.Int32
	validate := func(string, string, string, string) bool { return false }
	mint := func(string, string, string, string, string) (string, error) {
		mints.Add(1)
		time.Sleep(30 * time.Millisecond)
		return "fresh-token", nil
	}

	err := ensureTokensWith(cfg, filepath.Join(t.TempDir(), "config.json"), validate, mint)
	if err != nil {
		t.Fatalf("ensureTokensWith: %v", err)
	}
	if got := mints.Load(); got != 1 {
		t.Fatalf("mint calls = %d, want 1 (same account must be coalesced)", got)
	}
	for i := range cfg.Targets {
		if cfg.Targets[i].Token != "fresh-token" {
			t.Errorf("target %d token = %q, want fresh-token", i, cfg.Targets[i].Token)
		}
	}
}

// TestEnsureTokensMintFailureIsPerLane proves one lane's mint failure does not
// abort the others; the failed lane keeps an empty token and is skipped later.
func TestEnsureTokensMintFailureIsPerLane(t *testing.T) {
	cfg := tokenTestConf(t, "", "")
	cfg.Email = "operator@example.test"
	cfg.Targets[0].Password = "bad-password"
	cfg.Targets[1].Password = "good-password"

	validate := func(string, string, string, string) bool { return false }
	mint := func(email, password, totp, sp, ua string) (string, error) {
		if password == "bad-password" {
			return "", errors.New("invalid credentials")
		}
		return "fresh-token", nil
	}

	err := ensureTokensWith(cfg, filepath.Join(t.TempDir(), "config.json"), validate, mint)
	if err != nil {
		t.Fatalf("ensureTokensWith returned a global error for one lane: %v", err)
	}
	if cfg.Targets[0].Token != "" {
		t.Errorf("failed lane token = %q, want empty", cfg.Targets[0].Token)
	}
	if cfg.Targets[1].Token != "fresh-token" {
		t.Errorf("healthy lane token = %q, want fresh-token", cfg.Targets[1].Token)
	}
}
