//go:build manual

package sniper

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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

	// Optional build-number probe (MFA_TEST_BUILD, optionally MFA_TEST_CHROME
	// like "150.0.0.0"). Discord answers
	// `You need to update your app to perform this action.` for requests with
	// a stale client_build_number; the override lets us hunt the current one.
	if b := envOr("MFA_TEST_BUILD", ""); b != "" {
		n, _ := strconv.Atoi(b)
		ver := envOr("MFA_TEST_CHROME", "150.0.0.0")
		sp = buildChromeSuperPropsVersioned(n, ver)
		ua = fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", ver)
		t.Logf("probing with client_build_number=%d (Chrome %s)", n, ver)
	}

	// MFA_TEST_PROBE_ONLY=1: run just the username self-set probe and report
	// the verdict, skipping the guild ladder and the solve.
	probeOnly := envOr("MFA_TEST_PROBE_ONLY", "") == "1"

	// Step 1: the pasted token must be live.
	if !ValidateToken(token, sp, ua, "") {
		t.Fatal("supplied token failed GET /users/@me — invalid or expired")
	}
	t.Logf("token live ✅ (%s)", maskToken(token))

	// Step 2: capture a ticket with the no-damage trigger ladder, most benign
	// first:
	//   Path 0 — PATCH /users/@me re-setting the CURRENT username: an exact
	//   no-op if granted, a standard 60003 MFA challenge (ticket) otherwise.
	//   No guild is involved anywhere.
	//   Path A — a guild where the token holds MANAGE_GUILD with an existing
	//   vanity; the probe re-sends the EXACT current code (guaranteed no-op).
	//   Path B — fallback: a throwaway guild created and deleted by the probe.
	ticket, source := captureTicket(t, token, ua, sp)
	if probeOnly {
		if ticket == "" {
			t.Skip("username probe: no ticket (see logs above) — probe-only mode stops here")
		}
		t.Logf("username probe: TICKET captured, would proceed to solve — probe-only mode stops here")
		t.Skip("ticket working; re-run without MFA_TEST_PROBE_ONLY to solve")
	}
	if ticket == "" {
		t.Fatal("no MFA challenge could be interposed by any no-damage trigger")
	}
	t.Logf("ticket captured via %s (%s, %d chars)", source, maskID(ticket), len(ticket))

	// Step 3: TOTP solve → MFA JWT. THE decisive assertion: if this fails
	// with 60008, MFA_TEST_TOTP does not match the account's enrolled key.
	m := NewMFAHandler(&Target{
		Vanity: fmt.Sprintf("probe:%s", source),
		Token:  token,
	}, NewSessionStore(""), "", totpSecret, nil, &cfg.Fingerprint)

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
	m.SetToken(jwt, expiresIn)

	// Step 4: the exact header the claim burst splices into the PATCH.
	name, val := m.GetHeader()
	if name == "" || val == "" {
		t.Fatal("GetHeader returned an empty MFA header after a successful solve")
	}
	t.Logf("claim header %s: %s (%d chars)", name, maskID(val), len(val))
}

// guildLite / vanityResp parse just the fields the trigger ladder needs.
type guildLite struct {
	ID          string `json:"id"`
	Owner       bool   `json:"owner"`
	Permissions string `json:"permissions"` // decimal bitset string
}

// hasManageGuild reports the MANAGE_GUILD (1<<5 = 0x20) bit of the token's
// permissions in a guild, per the /users/@me/guilds list.
func (g guildLite) hasManageGuild() bool {
	if g.Owner {
		return true
	}
	perms, err := strconv.ParseInt(g.Permissions, 10, 64)
	if err != nil {
		return false
	}
	return perms&0x20 != 0
}

type vanityResp struct {
	Code *string `json:"code"`
}

// captureTicket interposes an MFA challenge (60003 ticket) using the most
// benign, guaranteed-no-op trigger available, and returns the ticket + label.
//
// Path 0 (username self-set): PATCH /users/@me with the exact current
// username. If granted, Discord accepts the no-change write; if challenged,
// the request is rejected pending MFA with a ticket. The account state is
// identical after either answer.
//
// Path A (same-code vanity re-set): a guild where the token holds
// MANAGE_GUILD with an existing vanity; the probe re-sends that exact code.
//
// Path B (throwaway): a fresh guild created purely as the probe scope and
// deleted on cleanup.
func captureTicket(t *testing.T, token, ua, sp string) (string, string) {
	// Path 0.
	ub := sendLoginRequest(rawGuildReq("GET", "/api/v9/users/@me", token, "", ua, sp))
	username := extractJSONStringField(string(extractRawBody(ub)), "username")
	if username != "" {
		probe := sendLoginRequest(rawGuildReq("PATCH", "/api/v9/users/@me", token,
			fmt.Sprintf(`{"username":"%s"}`, username), ua, sp))
		if ticket, err := extractTicket(probe); err == nil {
			t.Logf("trigger: same-username self-set interposed the challenge (%s)", extractStatusLine(probe))
			return ticket, "username-self-set"
		}
		status := parseStatusCode(probe)
		if status/100 == 2 {
			t.Logf("username self-set granted challenge-free (%s) — falling to the guild ladder", extractStatusLine(probe))
		} else if strings.Contains(string(respBody(probe)), "captcha") {
			t.Logf("username probe captcha'd (build gate?): %s — %s",
				extractStatusLine(probe), string(extractBody(probe)))
		} else {
			t.Logf("username self-set answered without a ticket: %s (%s)", extractStatusLine(probe), extractBody(probe))
		}
	}

	// Path A.
	resp := sendLoginRequest(rawGuildReq("GET", "/api/v9/users/@me/guilds", token, "", ua, sp))
	var guilds []guildLite
	if err := json.Unmarshal([]byte(extractRawBody(resp)), &guilds); err == nil {
		for _, g := range guilds {
			if g.ID == "" || !g.hasManageGuild() {
				continue
			}
			vresp := sendLoginRequest(rawGuildReq("GET", "/api/v9/guilds/"+g.ID+"/vanity-url", token, "", ua, sp))
			var vr vanityResp
			if json.Unmarshal([]byte(extractRawBody(vresp)), &vr) == nil && vr.Code != nil && *vr.Code != "" {
				probe := sendLoginRequest(rawGuildReqPatchVanity(g.ID, *vr.Code, token, ua, sp))
				if ticket, err := extractTicket(probe); err == nil {
					t.Logf("trigger: guild %s (its current vanity re-set — a guaranteed no-op)", maskID(g.ID))
					return ticket, "guild-same-code"
				}
				t.Logf("guild %s PATCH gave no ticket (%s) — trying the next guild", maskID(g.ID), extractStatusLine(probe))
			} else {
				t.Logf("guild %s: no existing vanity (skipping — a granted PATCH would set one)", maskID(g.ID))
			}
		}
	} else {
		t.Logf("guild list unavailable (%s: %v)", extractStatusLine(resp), err)
	}

	// Path B.
	ticket, source := throwawayTicket(t, token, ua, sp)
	return ticket, source
}

// throwawayTicket creates the probe guild, PATCHes an invisible-of-consequence
// vanity at it, extracts the ticket, and registers the guild's DELETE as
// cleanup. Nothing snipable ever exists on the throwaway.
func throwawayTicket(t *testing.T, token, ua, sp string) (string, string) {
	tgid := createThrowawayTrigger(t, token, ua, sp)
	t.Cleanup(func() {
		resp := sendLoginRequest(buildGuildDelete(token, tgid, ua))
		t.Logf("cleanup: DELETE guild %s -> %s", maskID(tgid), extractStatusLine(resp))
	})
	probe := sendLoginRequest(rawGuildReqPatchVanity(tgid, "zsnp0mfa", token, ua, sp))
	ticket, err := extractTicket(probe)
	if err != nil {
		t.Fatalf("throwaway PATCH gave no ticket: %s (%s)", extractStatusLine(probe), extractBody(probe))
	}
	return ticket, fmt.Sprintf("throwaway:%s", maskID(tgid))
}

// createThrowawayTrigger POSTs a minimal guild owned by the probed account so
// the ticket PATCH has a scope we can discard.
func createThrowawayTrigger(t *testing.T, token, ua, sp string) string {
	t.Helper()
	resp := sendLoginRequest(rawGuildReq("POST", "/api/v9/guilds", token, `{"name":"sniper-mfa-probe"}`, ua, sp))
	if parseStatusCode(resp)/100 != 2 {
		t.Fatalf("throwaway guild create failed: %s (%s)", extractStatusLine(resp), extractBody(resp))
	}
	gid := extractJSONStringField(string(extractRawBody(resp)), "id")
	if gid == "" {
		t.Fatalf("guild create returned no id: %s", extractBody(resp))
	}
	t.Logf("throwaway guild created: %s (removed on cleanup)", maskID(gid))
	return gid
}

// rawGuildReq builds a JSON request to discord.com with the PROVEN MINIMAL
// header set (the one that works for the claim PATCH in production):
// request-line, Host, Authorization, Content-* , X-Super-Properties, UA.
//
// Deliberately EXCLUDING browser-like headers (Origin, Referer, Sec-Fetch-*,
// X-Context-Properties): this repo's own claims history found they TRIGGER the
// 403/10008 "Unknown Message" rather than prevent it — a raw TLS socket that
// claims to be a browser page load is more suspicious than one that openly
// speaks the API dialect (ValidateToken's bare GET /users/@me also passes).
func rawGuildReq(method, path, token, body, ua, sp string) string {
	sb := new(strings.Builder)
	fmt.Fprintf(sb, "%s %s HTTP/1.1\r\n", method, path)
	sb.WriteString("Host: discord.com\r\n")
	if token != "" {
		fmt.Fprintf(sb, "Authorization: %s\r\n", token)
	}
	if body != "" {
		sb.WriteString("Content-Type: application/json\r\n")
		fmt.Fprintf(sb, "Content-Length: %d\r\n", len(body))
	}
	if sp != "" {
		fmt.Fprintf(sb, "X-Super-Properties: %s\r\n", sp)
	}
	if ua != "" {
		fmt.Fprintf(sb, "User-Agent: %s\r\n", ua)
	}
	sb.WriteString("Accept: */*\r\n")
	sb.WriteString("Connection: close\r\n\r\n")
	sb.WriteString(body)
	return sb.String()
}

// rawGuildReqPatchVanity identifies the PATCH specifically: same header set as
// the trigger probe, with the vanity body.
func rawGuildReqPatchVanity(gid, code, token, ua, sp string) string {
	body := fmt.Sprintf(`{"code":"%s"}`, code)
	return rawGuildReq("PATCH", "/api/v9/guilds/"+gid+"/vanity-url", token, body, ua, sp)
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
