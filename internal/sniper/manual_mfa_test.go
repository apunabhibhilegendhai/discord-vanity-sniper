//go:build manual

package sniper

import (
	"fmt"
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

// TestManualMFAClaimPath exercises the CLAIM-TIME MFA flow the burst actually
// uses: ticket capture (PATCH vanity-url), TOTP solve → MFA JWT, header
// assembly — driven by a pre-grabbed user token, so the email/password login
// (and thus the datacenter-IP hCaptcha gate) is never involved. The ticket
// trigger is a throwaway guild this account owns, created purely for the
// probe: the PATCH issued for the ticket does not change anything by itself
// (Discord answers 60003 MFA-challenge), and the guild is deleted on cleanup,
// so no real server's vanity is ever touched — nothing is sniped.
//
//	go test -tags=manual -run TestManualMFAClaimPath -v ./internal/sniper
//	   (set MFA_TEST_TOKEN and MFA_TEST_TOTP first)
func TestManualMFAClaimPath(t *testing.T) {
	token := strings.TrimSpace(envOr("MFA_TEST_TOKEN", ""))
	totpSecret := strings.ToUpper(strings.TrimSpace(envOr("MFA_TEST_TOTP", "")))
	if token == "" || totpSecret == "" {
		t.Skip("set MFA_TEST_TOKEN, MFA_TEST_TOTP to run")
	}

	// Resolve the browser fingerprint the same way LoadConfig would.
	cfg := &Conf{Browser: "chrome"}
	ResolveFingerprint(cfg)
	sp, ua := cfg.Fingerprint.SuperPropsB64, cfg.Fingerprint.UserAgent

	// Step 1: the pasted token must be live.
	if !ValidateToken(token, sp, ua, "") {
		t.Fatal("supplied token failed GET /users/@me — invalid or expired")
	}
	t.Logf("token live ✅ (%s)", maskToken(token))

	// Step 2: throwaway guild (owned by this account) as the ticket trigger.
	gid := createThrowawayGuild(t, token, ua)
	t.Cleanup(func() {
		resp := sendLoginRequest(buildGuildDelete(token, gid, ua))
		t.Logf("cleanup: DELETE guild %s -> %s", maskID(gid), extractStatusLine(resp))
	})

	// Step 3: ticket capture against the throwaway guild. A 60003 challenge
	// response is EXPECTED and fully benign (the request is rejected pending
	// MFA, nothing on the guild changes).
	m := NewMFAHandler(&Target{
		GuildID: gid,
		Vanity:  "zsnp0mfa",
		Token:   token,
	}, NewSessionStore(""), "", totpSecret, nil, &cfg.Fingerprint)

	ticketStart := time.Now()
	ticket, err := m.getTicket()
	if err != nil {
		t.Fatalf("getTicket: %v", err)
	}
	if len(ticket) > 8 {
		ticket = ticket[:8]
	}
	t.Logf("ticket captured in %s (%s…, %d chars)",
		time.Since(ticketStart).Round(time.Millisecond), maskID(ticket), len(ticket))

	// Step 4: TOTP solve → MFA JWT. THE decisive assertion: if this fails
	// with 60008, MFA_TEST_TOTP does not match the account's enrolled key.
	solveStart := time.Now()
	jwt, expiresIn, err := m.solveTOTP(ticket)
	if err != nil {
		if strings.Contains(err.Error(), "60008") {
			t.Fatalf("TOTP solve rejected with 60008 (invalid two-factor code) — MFA_TEST_TOTP does not match the account's enrolled key")
		}
		t.Fatalf("solveTOTP: %v", err)
	}
	t.Logf("MFA JWT solved in %s — valid ~%ds (%s)",
		time.Since(solveStart).Round(time.Millisecond), expiresIn, maskID(jwt))

	// Step 5: the exact header the claim burst splices into the PATCH.
	name, val := m.GetHeader()
	if name == "" || val == "" {
		t.Fatal("GetHeader returned an empty MFA header after a successful solve")
	}
	t.Logf("claim header %s: %s (%d chars)", name, maskID(val), len(val))
}

// createThrowawayGuild POSTs a minimal guild owned by the probed account and
// returns its snowflake, so the ticket PATCH has a scope we can discard.
func createThrowawayGuild(t *testing.T, token, ua string) string {
	t.Helper()
	body := `{"name":"sniper-mfa-probe"}`
	req := fmt.Sprintf("POST /api/v9/guilds HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"X-Discord-Locale: en-US\r\n"+
		"User-Agent: %s\r\n"+
		"Accept: */*\r\n"+
		"Connection: close\r\n\r\n%s", token, len(body), ua, body)
	resp := sendLoginRequest(req)
	if parseStatusCode(resp)/100 != 2 {
		t.Fatalf("throwaway guild create failed: %s (%s)", extractStatusLine(resp), extractBody(resp))
	}
	gid := extractJSONStringField(string(extractRawBody(resp)), "id")
	if gid == "" {
		t.Fatalf("guild create returned no id: %s", extractBody(resp))
	}
	return gid
}

func buildGuildDelete(token, gid, ua string) string {
	return fmt.Sprintf("DELETE /api/v9/guilds/%s HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"User-Agent: %s\r\n"+
		"Accept: */*\r\n"+
		"Connection: close\r\n\r\n", gid, token, ua)
}

// maskID keeps only the shape of an id/ticket/jwt in test logs.
func maskID(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:6] + "…"
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
