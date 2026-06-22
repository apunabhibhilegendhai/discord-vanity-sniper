package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// GuardAction selects the Vanity Guard's response to an unauthorized vanity
// change. See Conf.GuardAction docs for the semantics of each value.
type GuardAction int

const (
	// ActionReclaimOnly reverts the vanity but does not touch the offender. The
	// default — opt-in to punishment explicitly.
	ActionReclaimOnly GuardAction = iota
	// ActionKick removes the offender from the guild (reversible re-invite).
	ActionKick
	// ActionBan bans the offender; on a 403 (role hierarchy/owner) it degrades
	// to ActionKick, and on a second 403 it degrades to revert-only.
	ActionBan
)

// Guard defends an already-claimed vanity. When the gateway reports the guild's
// vanity is no longer ours, the Guard runs the reclaim burst (see Claimer) AND,
// in parallel, identifies the offender via the audit log and punishes them
// (kick/ban) so a competitor can't immediately re-steal the vanity after a
// successful revert. Quarantine is best-effort: a 403 (the offender outranks
// the sniper account, or is the owner) is logged and the revert is relied on.
//
// The audit-log fetch and the reclaim PATCH race are independent — Quarantine
// runs in its own goroutine so it never delays the snipe.
type Guard struct {
	target    *Target
	mfa       *MFAHandler
	stats     *Stats
	webhook   *WebhookSender
	action    GuardAction
	protected map[string]bool

	// pool dials fresh conns for the audit-log GET and the kick/ban requests.
	// These run off the snipe hot path (only when guard is armed and a loss is
	// detected), so a fresh dial per quarantine is acceptable — there's no
	// <150ms budget to protect here, and reusing a claim conn would leak
	// MFA-bearing state into an audit-log GET.
	pool *ConnPool
}

// NewGuard constructs a Guard. protectedIDs is the set of user ids that must
// never be punished; the caller (orchestrator) must include the token owner's
// id (captured from READY, stored on Target.ownerID) plus any
// guard_protected_user_ids from config. actionStr is validated against
// "reclaim_only"|"kick"|"ban" by config.LoadConfig, so an unknown value falls
// back to ActionReclaimOnly.
func NewGuard(t *Target, mfa *MFAHandler, stats *Stats, wh *WebhookSender, pool *ConnPool, actionStr string, protectedIDs []string) *Guard {
	var action GuardAction
	switch actionStr {
	case "kick":
		action = ActionKick
	case "ban":
		action = ActionBan
	default:
		action = ActionReclaimOnly
	}

	protected := make(map[string]bool, len(protectedIDs))
	for _, id := range protectedIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			protected[id] = true
		}
	}

	return &Guard{
		target:    t,
		mfa:       mfa,
		stats:     stats,
		webhook:   wh,
		action:    action,
		protected: protected,
		pool:      pool,
	}
}

// Quarantine identifies and punishes the offender who changed the vanity. It is
// intended to be called from claimer.reclaim() in a separate goroutine so the
// reclaim PATCH race is unaffected. It does NOT reclaim the vanity itself — the
// reclaim burst in Claimer.reclaim handles that; this is purely the offender
// response. Safe to call concurrently with the reclaim burst.
//
// If the configured action is ActionReclaimOnly, or the offender is protected,
// this is a no-op (the reclaim burst alone defends the vanity).
func (g *Guard) Quarantine() {
	if g.action == ActionReclaimOnly {
		return
	}

	offender, err := g.findOffender()
	if err != nil {
		log.Printf("[guard %s] couldn't identify offender: %v — relying on revert only", g.target.Vanity, err)
		return
	}
	if offender == "" {
		log.Printf("[guard %s] no offender in audit log — relying on revert only", g.target.Vanity)
		return
	}

	// Whitelist: the token owner and any configured protected ids are never
	// punished. A legitimate change made by the operator's own account (or a
	// trusted admin) must not trigger a self-ban.
	if g.isProtected(offender) {
		log.Printf("[guard %s] offender %s is protected — skipping punishment, revert only", g.target.Vanity, offender)
		return
	}

	g.punish(offender)
}

// findOffender queries the guild audit log for the most recent GUILD_UPDATE
// (action type 1) entry that changed vanity_url_code, and returns that entry's
// user_id. Returns "" if no such entry exists (the change may be older than the
// audit-log window, or the sniper account lacks VIEW_AUDIT_LOG).
//
// Uses the raw-HTTP path (like getTicket/claim) with the full browser header
// set so Cloudflare/Discord treat it as a continuation of the same session.
func (g *Guard) findOffender() (string, error) {
	sp, ua, dcfDuid, sdcfDuid, ticketCookies := g.mfa.getFingerprintHeaders()

	// action type 1 = GUILD_UPDATE. limit=5: the vanity change is almost always
	// the most recent GUILD_UPDATE, but a small window catches a tie with a
	// concurrent unrelated guild edit.
	path := fmt.Sprintf("/api/v9/guilds/%s/audit-logs?action_type=1&limit=5", g.target.GuildID)

	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\n", path)
	sb.WriteString("Host: discord.com\r\n")
	fmt.Fprintf(&sb, "Authorization: %s\r\n", g.target.Token)
	if sp != "" {
		fmt.Fprintf(&sb, "X-Super-Properties: %s\r\n", sp)
	}
	cookie := buildCookieHeader(dcfDuid, sdcfDuid, ticketCookies)
	if cookie != "" {
		fmt.Fprintf(&sb, "Cookie: %s\r\n", cookie)
	}
	if ua != "" {
		fmt.Fprintf(&sb, "User-Agent: %s\r\n", ua)
	}
	sb.WriteString("Origin: https://discord.com\r\n")
	sb.WriteString("Referer: https://discord.com/channels/@me\r\n")
	sb.WriteString("X-Discord-Locale: en-US\r\n")
	sb.WriteString("Accept: application/json\r\n")
	sb.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	sb.WriteString("\r\n")

	resp, err := g.rawHTTP(sb.String())
	if err != nil {
		return "", fmt.Errorf("audit-log GET: %w", err)
	}

	statusCode := parseStatusCode(resp)
	if statusCode != 200 {
		return "", fmt.Errorf("audit-log GET status %d (%s)", statusCode, extractStatusLine(resp))
	}

	return parseOffenderFromAuditLog(resp), nil
}

// parseOffenderFromAuditLog scans the audit-log JSON for the first
// GUILD_UPDATE entry whose changes include a vanity_url_code key, and returns
// that entry's user_id. A targeted struct unmarshal (not a full map[string]interface{})
// keeps allocations bounded. Returns "" if no matching entry is present.
func parseOffenderFromAuditLog(resp []byte) string {
	body := resp
	if idx := bytes.Index(resp, []byte("\r\n\r\n")); idx >= 0 {
		body = resp[idx+4:]
	}

	// The audit log body is JSON; trim a chunked-encoding "0\r\n" tail if the
	// transfer was chunked, and any trailing CRLF, before unmarshaling.
	body = bytes.TrimSpace(body)

	var log struct {
		Entries []struct {
			UserID    string `json:"user_id"`
			ActionType int   `json:"action_type"`
			Changes   []struct {
				Key   string `json:"key"`
				New   string `json:"new_value"`
				Old   string `json:"old_value"`
			} `json:"changes"`
		} `json:"audit_log_entries"`
	}
	if err := json.Unmarshal(body, &log); err != nil {
		return ""
	}

	for _, e := range log.Entries {
		// action_type 1 == GUILD_UPDATE. Belt-and-suspenders: the query filters
		// on action_type=1 already, but a stray entry type shouldn't match.
		if e.ActionType != 1 {
			continue
		}
		for _, ch := range e.Changes {
			if ch.Key == "vanity_url_code" {
				return e.UserID
			}
		}
	}
	return ""
}

// isProtected reports whether uid is the token owner or a configured protected
// id. Reads ownerID under the target mutex.
func (g *Guard) isProtected(uid string) bool {
	if uid == "" {
		return false
	}
	if g.protected[uid] {
		return true
	}
	g.target.mu.Lock()
	owner := g.target.ownerID
	g.target.mu.Unlock()
	return uid == owner
}

// punish executes the configured quarantine action against the offender,
// degrading on a 403 (role hierarchy / owner block):
//
//	ActionBan   -> PUT /bans/{uid}; on 403 fall through to ActionKick
//	ActionKick  -> DELETE /members/{uid}; on 403 log + rely on revert
//
// Each landed action fires a webhook and bumps the quarantine stat. A 403 bumps
// quarantineFail so the operator sees the guard couldn't neutralize the
// offender. Non-403 errors are logged but not retried (this is best-effort
// defense; the reclaim burst is the authoritative revert).
func (g *Guard) punish(uid string) {
	if g.action == ActionBan {
		if g.ban(uid) {
			return
		}
		// 403 or error — degrade to kick.
	}

	if g.action >= ActionKick {
		if g.kick(uid) {
			return
		}
	}
}

// ban PUTs /guilds/{g}/bans/{uid} with delete_message_days=0 (don't scrub
// history — keeps the action proportionate and avoids a slow bulk-delete).
// Returns true on success, false on any failure (including 403 hierarchy).
func (g *Guard) ban(uid string) bool {
	body := `{"delete_message_days":0}`
	path := fmt.Sprintf("/api/v9/guilds/%s/bans/%s", g.target.GuildID, uid)

	resp, err := g.sendGuildAction("PUT", path, body)
	if err != nil {
		log.Printf("[guard %s] ban %s error: %v", g.target.Vanity, uid, err)
		g.stats.AddQuarantineFail()
		g.webhook.Send("⛔ Ban Failed", 0x8B0000, map[string]string{
			"Vanity": "discord.gg/" + g.target.Vanity,
			"User":   uid,
			"Error":  err.Error(),
		})
		return false
	}

	status := parseStatusCode(resp)
	if status == 204 || (status >= 200 && status < 300) {
		log.Printf("[guard %s] 🔨 banned offender %s", g.target.Vanity, uid)
		g.stats.AddQuarantine()
		g.webhook.Send("🔨 Offender Banned", 0xFF0044, map[string]string{
			"Vanity": "discord.gg/" + g.target.Vanity,
			"User":   uid,
			"Action": "ban",
		})
		return true
	}

	log.Printf("[guard %s] ban %s failed: %s body: %s", g.target.Vanity, uid, extractStatusLine(resp), extractBody(resp))
	g.stats.AddQuarantineFail()
	if status == 403 {
		log.Printf("[guard %s] ban 403 (hierarchy/owner) — degrading to kick", g.target.Vanity)
		return false
	}
	// Non-403 failure: report but still degrade so the offender at least gets
	// kicked if the ban endpoint is the problem.
	return false
}

// kick DELETEs /guilds/{g}/members/{uid}. Returns true on success, false on any
// failure. A 403 here is terminal (we've already degraded from ban); the revert
// is relied on and the operator is notified.
func (g *Guard) kick(uid string) bool {
	path := fmt.Sprintf("/api/v9/guilds/%s/members/%s", g.target.GuildID, uid)

	resp, err := g.sendGuildAction("DELETE", path, "")
	if err != nil {
		log.Printf("[guard %s] kick %s error: %v", g.target.Vanity, uid, err)
		g.stats.AddQuarantineFail()
		g.webhook.Send("⛔ Kick Failed", 0x8B0000, map[string]string{
			"Vanity": "discord.gg/" + g.target.Vanity,
			"User":   uid,
			"Error":  err.Error(),
		})
		return false
	}

	status := parseStatusCode(resp)
	if status == 204 || (status >= 200 && status < 300) {
		log.Printf("[guard %s] 👢 kicked offender %s", g.target.Vanity, uid)
		g.stats.AddQuarantine()
		g.webhook.Send("👢 Offender Kicked", 0xFF8800, map[string]string{
			"Vanity": "discord.gg/" + g.target.Vanity,
			"User":   uid,
			"Action": "kick",
		})
		return true
	}

	log.Printf("[guard %s] kick %s failed: %s body: %s", g.target.Vanity, uid, extractStatusLine(resp), extractBody(resp))
	g.stats.AddQuarantineFail()
	if status == 403 {
		g.webhook.Send("🚫 Couldn't Quarantine", 0xFFA500, map[string]string{
			"Vanity": "discord.gg/" + g.target.Vanity,
			"User":   uid,
			"Reason": "403 — offender outranks the sniper account (insufficient role hierarchy or is the owner). Vanity reverted; offender NOT removed.",
		})
	} else {
		g.webhook.Send("⛔ Quarantine Failed", 0x8B0000, map[string]string{
			"Vanity": "discord.gg/" + g.target.Vanity,
			"User":   uid,
			"Status": fmt.Sprintf("%d", status),
			"Body":   extractBody(resp),
		})
	}
	return false
}

// sendGuildAction issues a kick/ban request with the full browser header set so
// Cloudflare/Discord treat it as a continuation of the same session as the
// claim. method/path/body describe the request; body may be "".
func (g *Guard) sendGuildAction(method, path, body string) ([]byte, error) {
	sp, ua, dcfDuid, sdcfDuid, ticketCookies := g.mfa.getFingerprintHeaders()

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", method, path)
	sb.WriteString("Host: discord.com\r\n")
	fmt.Fprintf(&sb, "Authorization: %s\r\n", g.target.Token)
	if sp != "" {
		fmt.Fprintf(&sb, "X-Super-Properties: %s\r\n", sp)
	}
	if body != "" {
		fmt.Fprintf(&sb, "Content-Type: application/json\r\n")
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}
	cookie := buildCookieHeader(dcfDuid, sdcfDuid, ticketCookies)
	if cookie != "" {
		fmt.Fprintf(&sb, "Cookie: %s\r\n", cookie)
	}
	if ua != "" {
		fmt.Fprintf(&sb, "User-Agent: %s\r\n", ua)
	}
	sb.WriteString("Origin: https://discord.com\r\n")
	sb.WriteString("Referer: https://discord.com/channels/@me\r\n")
	sb.WriteString("X-Discord-Locale: en-US\r\n")
	sb.WriteString("X-Context-Properties: eyJsb2NhdGlvbiI6Ikd1aWxkU2V0dGluZ3MifQ==\r\n")
	sb.WriteString("Accept: */*\r\n")
	sb.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	return g.rawHTTP(sb.String())
}

// rawHTTP borrows a conn from the guard pool, writes the request, reads the
// full response, and closes the conn (guard requests are one-shot — never
// recycled, same discipline as the claim path). Returns the raw response bytes
// (status line + headers + body).
func (g *Guard) rawHTTP(req string) ([]byte, error) {
	conn, err := g.pool.Get()
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write: %w", err)
	}

	var resp []byte
	readBuf := respBufPool.Get().([]byte)
	defer respBufPool.Put(readBuf)
	bodyLen := -1
	for {
		n, rerr := conn.Read(readBuf)
		if n > 0 {
			resp = append(resp, readBuf[:n]...)
		}
		if rerr != nil {
			break
		}
		if bodyLen < 0 {
			bodyLen = contentLength(resp)
		}
		headerEnd := bytes.Index(resp, []byte("\r\n\r\n"))
		if headerEnd < 0 {
			continue
		}
		if bytes.Contains(resp, []byte("Transfer-Encoding: chunked")) {
			if bytes.Contains(resp, []byte("\r\n0\r\n")) {
				break
			}
		} else if bodyLen >= 0 {
			if len(resp)-headerEnd-4 >= bodyLen {
				break
			}
		} else {
			break
		}
	}
	conn.Close()

	if len(resp) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	return resp, nil
}
