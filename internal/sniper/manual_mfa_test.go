//go:build manual

package sniper

import (
	"encoding/json"
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

	// Step 2: pick a SAFE ticket trigger, in a no-damage ladder:
	//   Path A — a guild the account owns that ALREADY carries a vanity. The
	//   probe re-PATCHes the EXACT current code, so even a granted
	//   (challenge-free) request is an exact no-op on a real server.
	//   Path B — no such guild exists, or PATCH answers without a challenge:
	//   create a throwaway guild (nothing snipable on it) and delete it in
	//   cleanup.
	gid, targetCode, throwaway := pickTicketTrigger(t, token, ua, sp)
	if throwaway {
		t.Cleanup(func() {
			resp := sendLoginRequest(buildGuildDelete(token, gid, ua))
			t.Logf("cleanup: DELETE guild %s -> %s", maskID(gid), extractStatusLine(resp))
		})
	}

	// Step 3: ticket capture against the chosen trigger. A 60003 challenge
	// response is EXPECTED and fully benign (the request is rejected pending
	// MFA — nothing on the guild changes).
	m := NewMFAHandler(&Target{
		GuildID: gid,
		Vanity:  targetCode,
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

// guildLite / vanityResp parse just the fields the trigger ladder needs.
type guildLite struct {
	ID    string `json:"id"`
	Owner bool   `json:"owner"`
}

type vanityResp struct {
	Code *string `json:"code"`
}

// pickTicketTrigger resolves (guild id, vanity code) for the MFA ticket PATCH
// and reports whether that guild is a throwaway (delete-on-cleanup).
//
// Path A (real guild): owned guild that already has a vanity; the PATCH
// re-sends that exact code, so any granted request is an identity no-op. This
// never creates or deletes anything on the account.
//
// Path B (throwaway): no owned+vanity guild exists, or the same-code PATCH was
// granted without a challenge — a fresh guild is created purely as the probe
// scope and removed by the returned cleanup.
func pickTicketTrigger(t *testing.T, token, ua, sp string) (gid string, code string, throwaway bool) {
	// Path A.
	resp := sendLoginRequest(rawGuildReq("GET", "/api/v9/users/@me/guilds", token, "", ua, sp))
	var guilds []guildLite
	if err := json.Unmarshal([]byte(extractRawBody(resp)), &guilds); err == nil {
		for _, g := range guilds {
			if !g.Owner || g.ID == "" {
				continue
			}
			vresp := sendLoginRequest(rawGuildReq("GET", "/api/v9/guilds/"+g.ID+"/vanity-url", token, "", ua, sp))
			var vr vanityResp
			if json.Unmarshal([]byte(extractRawBody(vresp)), &vr) == nil && vr.Code != nil && *vr.Code != "" {
				// Confirm the PATCH actually interposes an MFA challenge; a
				// granted same-code request (recent-solve grace) cannot act
				// as a ticket trigger.
				probe := sendLoginRequest(rawGuildReqPatchVanity(g.ID, *vr.Code, token, ua, sp))
				if parseStatusCode(probe)/100 != 2 && strings.Contains(string(respBody(probe)), "ticket") {
					t.Logf("trigger: owned guild %s (vanity re-set of its current code — a guaranteed no-op)", maskID(g.ID))
					return g.ID, *vr.Code, false
				}
				t.Logf("guild %s PATCH did not interpose a challenge (%s) — trying the next guild", maskID(g.ID), extractStatusLine(probe))
			}
		}
	} else {
		t.Logf("guild list unavailable (%s: %v)", extractStatusLine(resp), err)
	}

	// Path B.
	tgid := createThrowawayTrigger(t, token, ua, sp)
	return tgid, "zsnp0mfa", true
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

// rawGuildReq builds a JSON request to discord.com with a browser-credible
// header set. The set mirrors minimal browser traffic: X-Super-Properties,
// origin context, Sec-Fetch-*, Accept-Language — the bare header set (api-raw
// style) gets treated as scripted traffic on some endpoints.
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
	sb.WriteString("X-Discord-Locale: en-US\r\n")
	sb.WriteString("X-Context-Properties: eyJsb2NhdGlvbiI6IkdpbGQgU2V0dGluZ3MifQ==\r\n") // {"location":"Guild Settings"}
	sb.WriteString("Origin: https://discord.com\r\n")
	sb.WriteString("Referer: https://discord.com/channels/@me\r\n")
	sb.WriteString("Accept: */*\r\n")
	sb.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	sb.WriteString("Sec-Fetch-Site: same-origin\r\n")
	sb.WriteString("Sec-Fetch-Mode: cors\r\n")
	sb.WriteString("Sec-Fetch-Dest: empty\r\n")
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
