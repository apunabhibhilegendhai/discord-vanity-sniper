//go:build live

// live_claim_test.go exercises the REAL production claim path end-to-end:
//
//   SessionStore → MFAHandler.EnsureValid (getTicket + solveTOTP)
//                → ConnPool (utls Chrome JA3)
//                → Claimer.firstClaim (burst hot path → doClaim)
//                → WebhookSender (success embed)
//
// It does NOT reimplement the HTTP path (unlike the stale diag_*.go tools,
// which use /api/v9 and raw crypto/tls). Every call here is the same function
// the live sniper runs, so the latency numbers are representative.
//
// It is gated behind the `live` build tag so it never compiles into a normal
// build, `go vet`, or `go test` run. Invoke explicitly:
//
//	go test -tags=live -run=TestLiveClaim -v -timeout=120s
//
// This makes real Discord API calls with the configured token and mutates the
// guild's vanity (it claims the configured target vanity, which is a no-op 200
// if the guild already holds it). It also posts real webhook embeds.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestLiveClaim drives the production claim stack against the live config.
func TestLiveClaim(t *testing.T) {
	cfg, err := LoadConfig("config.json")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Targets) == 0 {
		t.Fatal("no targets in config")
	}
	target := &cfg.Targets[0]
	t.Logf("target guild=%s vanity=%q", target.GuildID, target.Vanity)

	// ---- 0. Webhook connectivity check (independent of the claim) ----------
	// A direct POST lets us read the HTTP status back, which WebhookSender
	// (fire-and-forget) can't. Confirms the webhook URL accepts embeds before we
	// blame a missing success embed on the claim path.
	webhookStatus := postWebhook(t, cfg.WebhookURL, "🧪 Webhook Connectivity Test", 0x00FFFF, map[string]string{
		"Guild":  target.GuildID,
		"Vanity": target.Vanity,
		"Note":   "live_claim_test probe — ignore",
	})
	t.Logf("connectivity webhook POST status: %s (204 = delivered)", webhookStatus)

	// Give Discord a beat to render the embed in the channel before the claim
	// embed lands on top of it, so the two are visually distinguishable.
	time.Sleep(2 * time.Second)

	// ---- 1. Build the production stack -------------------------------------
	sessions := NewSessionStore(cfg.SessionPath)
	sessions.Load()
	defer sessions.Save() // flush the MFA token so the next run reads a warm one

	mfa := NewMFAHandler(target, sessions, cfg.Password, cfg.TOTPSecret, cfg.BackupCodes, &cfg.Fingerprint)
	t.Logf("MFA method: %s", mfa.Method())

	// Use a small warm pool for the test so it doesn't pay the full
	// cfg.WarmConns (10×200ms) warm-up. burst_count conns covers the burst.
	// Start the rewarmer so the pool refills between the clear and the claim.
	warm := cfg.BurstCount
	if warm < 1 {
		warm = 3
	}
	pool, err := NewConnPool("", warm)
	if err != nil {
		t.Fatalf("NewConnPool: %v", err)
	}
	defer pool.StopRewarmer()
	defer pool.Close()
	pool.StartRewarmer()

	stats := &Stats{StartTime: time.Now()}
	rl := NewRateLimiter()
	wh := NewWebhookSender(cfg.WebhookURL)

	claimer := NewClaimer(target, cfg, []*ConnPool{pool}, mfa, stats, wh, rl,
		cfg.BurstCount, cfg.GuardMode, cfg.GuardReclaimMax, cfg.GuardReclaimBackoffMS, nil)

	// ---- 2. Warm the MFA token (measure solve latency) --------------------
	// EnsureValid returns instantly if a cached token exists in session_state;
	// otherwise it blocks on getTicket + /mfa/finish. In production the
	// background pre-solver keeps this warm, so a fast return here is the
	// realistic hot-path precondition.
	mfaT0 := time.Now()
	ok := mfa.EnsureValid()
	mfaLatency := time.Since(mfaT0)
	if !ok {
		t.Fatalf("MFA EnsureValid failed (method=%s) — cannot claim without a token", mfa.Method())
	}
	t.Logf("MFA EnsureValid: ok=%v latency=%dms", ok, mfaLatency.Milliseconds())

	// ---- 3. Fire the claim hot path ---------------------------------------
	// firstClaim is the exact entry point the gateway signal triggers in
	// production. claimSuccess fires from INSIDE the winning burst worker the
	// instant a 200 lands (before the remaining workers drain), setting
	// target.claimed = true. We measure time-to-first-200 by polling that flag
	// instead of waiting for firstClaim to return (which drains all workers and
	// measures the SLOWEST, not the first).
	//
	// If the guild already holds the target vanity (e.g. from a prior run), every
	// burst worker would 400 "already taken" and the claim would be reported as
	// failed — a false negative that says nothing about the hot path. So if the
	// guild currently holds it, clear it first via a raw PATCH {code:""} using
	// the warm MFA token, making the subsequent claim a genuine fresh claim.
	if guildHoldsVanity(t, target) {
		t.Log("guild already holds target vanity — clearing first for a fresh claim")
		clearVanity(t, target, mfa)
		time.Sleep(1500 * time.Millisecond) // let the clear propagate
	}

	// Fire the burst in the background so we can poll for the first 200.
	claimDone := make(chan struct{})
	go func() {
		claimer.firstClaim()
		close(claimDone)
	}()

	// Poll target.claimed until the first worker confirms a 200 (or timeout).
	// This measures the TRUE claim latency: signal → PATCH → 200, not the
	// burst drain time which is dominated by the slowest tail worker.
	claimT0 := time.Now()
	claimed := false
	for {
		target.mu.Lock()
		claimed = target.claimed
		target.mu.Unlock()
		if claimed {
			break
		}
		// Also bail if firstClaim already returned (burst drained without success).
		select {
		case <-claimDone:
			// Burst done — check claimed one last time.
			target.mu.Lock()
			claimed = target.claimed
			target.mu.Unlock()
			goto done
		default:
		}
		if time.Since(claimT0) > 10*time.Second {
			t.Log("timeout waiting for claim")
			break
		}
		time.Sleep(time.Millisecond)
	}
done:

	claimLatency := time.Since(claimT0)
	// Wait for the background firstClaim to fully drain so we don't race
	// with webhook.Send (now synchronous) on pool/webhook resources.
	<-claimDone

	_, claims, errs := stats.Snapshot()
	t.Logf("stats: claims=%d errors=%d", claims, errs)

	t.Logf("CLAIM: claimed=%v latency=%dms (burst=%d)", claimed, claimLatency.Milliseconds(), cfg.BurstCount)

	// WebhookSender.Send is now synchronous (blocks until delivered or all
	// retries exhaust), so no sleep is needed — the embed was already written
	// (or logged as failed) by the time we get here.

	if !claimed {
		t.Errorf("claim did not succeed — check logs above for the PATCH response (400 = vanity taken/invalid, 401/60003 = MFA, 429 = rate limit)")
	}
}

// postWebhook POSTs a Discord embed payload to the webhook URL and returns the
// HTTP status string. Discord responds 204 No Content on successful execution,
// so a "204" return means the embed was accepted and will render in the
// channel. Used for the standalone connectivity check (the production
// WebhookSender ignores its own response).
func postWebhook(t *testing.T, url, title string, color int, fields map[string]string) string {
	t.Helper()
	if url == "" {
		return "(no webhook_url configured)"
	}

	embedFields := make([]map[string]interface{}, 0, len(fields))
	for k, v := range fields {
		embedFields = append(embedFields, map[string]interface{}{
			"name": k, "value": v, "inline": true,
		})
	}
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{{
			"title":     title,
			"color":     color,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"fields":    embedFields,
		}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "marshal: " + err.Error()
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return "build request: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "do: " + err.Error()
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	status := resp.Status
	if resp.StatusCode >= 300 {
		// Discord returns a JSON error body on failure; surface it.
		status += " body=" + strings.TrimSpace(string(respBody))
	}
	return status
}

// guildHoldsVanity does a GET /guilds/{id}/vanity-url to check whether the
// guild currently has the target code set. Used to decide whether a clear is
// needed before the claim so the claim is a genuine fresh claim (not a 400
// "already taken").
func guildHoldsVanity(t *testing.T, target *Target) bool {
	t.Helper()
	url := "https://discord.com/api/v9/guilds/" + target.GuildID + "/vanity-url"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", target.Token)
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	// Body shape: {"code":"xkq7test9","uses":0}  (or {"code":null,...} if unset)
	return strings.Contains(string(body), `"code":"`+target.Vanity+`"`)
}

// clearVanity clears the guild's vanity via a raw PATCH {code:""} carrying the
// warm MFA token, mirroring the production claim PATCH header set. Uses
// discordDialConn (the same utls Chrome path the pool uses) so the request is
// fingerprint-identical to a production solve.
func clearVanity(t *testing.T, target *Target, mfa *MFAHandler) {
	t.Helper()
	mfaName, mfaValue := mfa.GetHeader()
	if mfaValue == "" {
		t.Fatal("no warm MFA token available to clear vanity")
	}

	sp, ua, _, _, _ := mfa.getFingerprintHeaders()
	body := `{"code":""}`
	var sb strings.Builder
	fmt.Fprintf(&sb, "PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n", target.GuildID)
	sb.WriteString("Host: discord.com\r\n")
	fmt.Fprintf(&sb, "Authorization: %s\r\n", target.Token)
	if sp != "" {
		fmt.Fprintf(&sb, "X-Super-Properties: %s\r\n", sp)
	}
	fmt.Fprintf(&sb, "%s: %s\r\n", mfaName, mfaValue)
	fmt.Fprintf(&sb, "Content-Type: application/json\r\n")
	fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	if ua != "" {
		fmt.Fprintf(&sb, "User-Agent: %s\r\n", ua)
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)

	conn, err := discordDialConn(10 * time.Second)
	if err != nil {
		t.Fatalf("clearVanity dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		t.Fatalf("clearVanity write: %v", err)
	}
	buf := make([]byte, 4096)
	var resp []byte
	for {
		n, rerr := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	t.Logf("clearVanity response status: %s", extractStatusLine(resp))
}
