//go:build manual

package sniper

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestManualMFAFlow runs one real email/password → TOTP ticket solve → token
// mint against Discord, then validates the minted token. Credentials come from
// env vars so nothing secret is committed:
//
//	go test -tags=manual -run TestManualMFAFlow -v .
//	   (set MFA_TEST_EMAIL / MFA_TEST_PASSWORD / MFA_TEST_TOTP first)
func TestManualMFAFlow(t *testing.T) {
	email := strings.TrimSpace(envOr("MFA_TEST_EMAIL", ""))
	password := envOr("MFA_TEST_PASSWORD", "")
	totpSecret := strings.ToUpper(strings.TrimSpace(envOr("MFA_TEST_TOTP", "")))
	if email == "" || password == "" || totpSecret == "" {
		t.Skip("set MFA_TEST_EMAIL, MFA_TEST_PASSWORD, MFA_TEST_TOTP to run")
	}

	// Resolve the browser fingerprint the same way LoadConfig would.
	cfg := &Conf{Browser: "chrome"}
	ResolveFingerprint(cfg)
	sp, ua := cfg.Fingerprint.SuperPropsB64, cfg.Fingerprint.UserAgent

	started := time.Now()
	token, err := MintToken(email, password, totpSecret, sp, ua)
	if err != nil {
		t.Fatalf("MintToken failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
	}
	t.Logf("MintToken OK in %s (token: %s, %d chars)",
		time.Since(started).Round(time.Millisecond), maskToken(token), len(token))

	// Step 2: the minted token must pass GET /users/@me.
	if !ValidateToken(token, sp, ua, "") {
		t.Fatal("ValidateToken rejected the freshly minted token")
	}
	t.Logf("ValidateToken: 2xx — token is live ✅")

	// Step 3: second solve round-trip (an already-logged account) to exercise
	// the repeated-flow path.
	started2 := time.Now()
	token2, err := MintToken(email, password, totpSecret, sp, ua)
	if err != nil {
		t.Fatalf("second MintToken failed after %s: %v", time.Since(started2).Round(time.Millisecond), err)
	}
	same := ""
	if token2 == token {
		same = " (identical token)"
	}
	t.Logf("second MintToken OK in %s%s — %s",
		time.Since(started2).Round(time.Millisecond), same, maskToken(token2))
}

// maskToken keeps a couple of leading chars visible for diffing and hides the
// rest, so live logs never carry a full credential.
func maskToken(tok string) string {
	if len(tok) <= 8 {
		return strings.Repeat("*", len(tok))
	}
	return tok[:5] + "…" + strings.Repeat("*", 12)
}

func envOr(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}
