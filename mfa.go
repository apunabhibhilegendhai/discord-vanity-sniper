package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
)

type MFAHandler struct {
	mu          sync.Mutex
	totpSecret  string
	password    string
	backupCodes []string
	backupIndex int
	autoSolve   bool
	target      *Target
	session     *SessionStore
	key         string

	token     string
	expiresAt time.Time
	lastTOTP  string
	totpGenAt time.Time

	superProps    string
	dcfDuid       string
	sdcfDuid      string
	userAgent     string
	ticketCookies string // cookies extracted from the last getTicket response

	// tokenReady is closed once the first MFA token is cached (by SetToken or
	// the pre-solver). Claimers can select on it via WaitForToken to avoid
	// firing a burst with no MFA header on cold starts.
	tokenReady chan struct{}
}

func NewMFAHandler(target *Target, session *SessionStore, globalPassword, totpSecret string, backupCodes []string, fp *Fingerprint) *MFAHandler {
	password := target.Password
	if password == "" {
		password = globalPassword
	}

	h := &MFAHandler{
		target:      target,
		session:     session,
		key:         mfaCacheKey(target.Token),
		totpSecret:  totpSecret,
		backupCodes: backupCodes,
		autoSolve:   password != "",
		password:    password,
		superProps:  fp.SuperPropsB64,
		dcfDuid:     fp.DcfDuid,
		sdcfDuid:    fp.SdcfDuid,
		userAgent:   fp.UserAgent,
		tokenReady:  make(chan struct{}),
	}

	// Load cached MFA token from session store
	if ts := session.Get(h.key); ts != nil && ts.MFAToken != "" {
		h.token = ts.MFAToken
		h.expiresAt = time.Unix(ts.MFAExpiresAt, 0)
		if time.Now().After(h.expiresAt) {
			h.token = ""
		}
	}

	// If a token is already loaded from session cache, close tokenReady immediately
	// so WaitForToken returns without blocking.
	if h.token != "" {
		log.Printf("[mfa %s] loaded cached MFA token from session (valid for %s remaining)",
			target.Vanity, time.Until(h.expiresAt).Round(time.Second))
		close(h.tokenReady)
	}

	return h
}

// mfaCacheKey returns the session-store key under which an MFA token is cached.
//
// Discord's MFA JWT authorizes the ACCOUNT, not a specific guild or vanity — the
// same solved token works for any guild that account can PATCH. So the cache key
// must be derived from the account, NOT from guild:vanity. The previous key
// (target.GuildID + ":" + target.Vanity) meant that every vanity swap or guild
// change produced a cache MISS, forcing a fresh ~9s TOTP solve. On a cold start
// (no cached token) that solve delay also let the warm pool's held conns go
// stale before the claim burst fired, so the burst wrote to dead sockets and
// silently lost the snipe. Keying by account makes a token solved for one
// vanity reusable for every other vanity the same account targets.
//
// The Discord account id is the first segment of the auth token (a base64-
// encoded snowflake, e.g. "MTUxNzA0..." in "MTUxNzA0....<ts>.<hmac>"). We use
// "mfa:" + that segment as the key. Falls back to the raw token prefix if the
// segment isn't base64-parseable (defensive — never block caching on a parse
// error; the worst case is a sub-optimal key, still account-stable).
func mfaCacheKey(token string) string {
	if token == "" {
		return "mfa:anon"
	}
	dot := strings.IndexByte(token, '.')
	if dot <= 0 {
		return "mfa:" + token
	}
	return "mfa:" + token[:dot]
}

func (m *MFAHandler) Method() string {
	if m.totpSecret != "" {
		return "totp"
	}
	if m.autoSolve {
		return "password"
	}
	return "none"
}

func (m *MFAHandler) GetHeader() (name string, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Cached token from a previous ticket solve
	if m.token != "" && time.Now().Before(m.expiresAt) {
		return "X-Discord-MFA-Authorization", m.token
	}

	// Direct TOTP in header is no longer supported by Discord v10 gateway
	// Must use ticket → /mfa/finish → token flow instead
	return "", ""
}

func (m *MFAHandler) EnsureValid() bool {
	m.mu.Lock()
	token := m.token
	expired := time.Now().After(m.expiresAt)
	m.mu.Unlock()

	if token != "" && !expired {
		return true
	}

	// Try each MFA method until one succeeds.
	// Order: TOTP → password (if configured)
	if m.totpSecret != "" {
		if m.refreshTOTP() {
			return true
		}
		log.Printf("[mfa %s] TOTP refresh failed, trying password fallback", m.target.Vanity)
	}
	if m.autoSolve {
		if m.refresh() {
			return true
		}
	}
	return false
}

// refresh solves an MFA ticket using the account password and caches the token.
func (m *MFAHandler) refresh() bool {
	if !m.autoSolve {
		return false
	}

	log.Printf("[mfa %s] refreshing MFA token via password...", m.target.Vanity)

	ticket, err := m.getTicket()
	if err != nil {
		log.Printf("[mfa %s] get ticket: %v", m.target.Vanity, err)
		return false
	}

	token, expiresIn, err := m.solveTicket(ticket)
	if err != nil {
		log.Printf("[mfa %s] solve: %v", m.target.Vanity, err)
		return false
	}

	m.mu.Lock()
	m.token = token
	m.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	m.mu.Unlock()

	m.session.UpdateMFAToken(m.key, token, m.expiresAt.Unix())
	log.Printf("[mfa %s] token valid until %s", m.target.Vanity, m.expiresAt.Format(time.RFC3339))

	return true
}

// refreshTOTP solves an MFA ticket via TOTP and caches the resulting token.
// The ticket is fetched from the REAL target guild (via getTicket), not guild
// "0": the guild-0 trick occasionally returns 401 instead of 60003 on some
// accounts and the fallback path duplicated effort. Since StartRefresh runs this
// only ~once per token lifetime (never on the hot path), the extra PATCH on the
// real guild is cheap and reliably yields a ticket.
func (m *MFAHandler) refreshTOTP() bool {
	if m.totpSecret == "" {
		return false
	}

	log.Printf("[mfa %s] refreshing MFA token via TOTP...", m.target.Vanity)

	ticket, err := m.getTicket()
	if err != nil || ticket == "" {
		log.Printf("[mfa %s] get ticket: %v", m.target.Vanity, err)
		return false
	}

	token, expiresIn, err := m.solveTOTP(ticket)
	if err != nil {
		log.Printf("[mfa %s] solve TOTP: %v", m.target.Vanity, err)
		return false
	}

	m.mu.Lock()
	m.token = token
	m.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	m.mu.Unlock()

	m.session.UpdateMFAToken(m.key, token, m.expiresAt.Unix())
	log.Printf("[mfa %s] TOTP token valid until %s", m.target.Vanity, m.expiresAt.Format(time.RFC3339))

	return true
}

// getTicket sends a PATCH to the real target guild's vanity-url endpoint to
// trigger an MFA challenge and capture the resulting ticket. Discord responds
// 401 with body {"code":60003,"ticket":"..."} for MFA-enabled accounts. Also
// harvests Set-Cookie headers from the response (notably __Secure-recent_mfa
// and re-issued __dcfduid) so the subsequent /mfa/finish solve carries the same
// session identity.
//
// The Cookie header merges the configured device identity (__dcfduid/__sdcfduid)
// with any cookies previously captured from Cloudflare/Discord (_cfuvid,
// __Secure-recent_mfa, re-issued __dcfduid). Forwarding the full set across the
// getTicket → solve → claim chain is what makes the three requests look like a
// single continuous browser session rather than three cold connections —
// Cloudflare in particular keys its bot score on _cfuvid continuity.
func (m *MFAHandler) getTicket() (string, error) {
	m.mu.Lock()
	sp, ua := m.superProps, m.userAgent
	vanity := m.target.Vanity
	prevCookies := m.ticketCookies
	m.mu.Unlock()

	body := fmt.Sprintf(`{"code":"%s"}`, vanity)
	sb := new(strings.Builder)
	fmt.Fprintf(sb, "PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n", m.target.GuildID)
	fmt.Fprintf(sb, "Host: discord.com\r\n")
	fmt.Fprintf(sb, "Authorization: %s\r\n", m.target.Token)
	if sp != "" {
		fmt.Fprintf(sb, "X-Super-Properties: %s\r\n", sp)
	}
	fmt.Fprintf(sb, "Content-Type: application/json\r\n")
	fmt.Fprintf(sb, "Content-Length: %d\r\n", len(body))
	// Merge device cookies with any previously captured session cookies so the
	// device identity is always present even if a prior response re-issued only
	// _cfuvid without __dcfduid.
	cookie := mergeCookieStrings(
		fmt.Sprintf("__dcfduid=%s; __sdcfduid=%s", m.dcfDuid, m.sdcfDuid),
		prevCookies,
	)
	if cookie != "" {
		fmt.Fprintf(sb, "Cookie: %s\r\n", cookie)
	}
	if ua != "" {
		fmt.Fprintf(sb, "User-Agent: %s\r\n", ua)
	}
	sb.WriteString("Origin: https://discord.com\r\n")
	sb.WriteString("Referer: https://discord.com/channels/@me\r\n")
	sb.WriteString("X-Discord-Locale: en-US\r\n")
	sb.WriteString("X-Context-Properties: eyJsb2NhdGlvbiI6Ikd1aWxkU2V0dGluZ3MifQ==\r\n")
	sb.WriteString("X-Debug-Options: bugReporterEnabled\r\n")
	sb.WriteString("Accept: */*\r\n")
	sb.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	sb.WriteString("Sec-Fetch-Site: same-origin\r\n")
	sb.WriteString("Sec-Fetch-Mode: cors\r\n")
	sb.WriteString("Sec-Fetch-Dest: empty\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	req := sb.String()

	conn, err := discordDialConn(10 * time.Second)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	conn.Write([]byte(req))

	var resp []byte
	buf := make([]byte, 4096)
	for {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	// Merge any freshly issued cookies into the store so the solve + claim
	// inherit the updated device id / _cfuvid. setTicketCookies merges by name.
	m.setTicketCookies(extractSetCookies(resp))

	ticket, err := extractTicket(resp)
	if err != nil {
		// Log the actual response so we can see what Discord returned instead
		// of 60003 (e.g. 200 OK — guild doesn't require MFA, 403 — no
		// permission, 429 — rate limited, or an HTML error page from Cloudflare).
		respSnippet := extractBody(resp)
		if len(respSnippet) > 200 {
			respSnippet = respSnippet[:200]
		}
		log.Printf("[mfa %s] getTicket failed: %v (status=%d, body=%s)",
			m.target.Vanity, err, parseStatusCode(resp), respSnippet)
	}
	return ticket, err
}

func sendSolveRequest(req string) []byte {
	// Don't log req: it contains the account auth token and the MFA ticket.
	// Only log errors. The full request was previously dumped to stdout, which
	// leaked credentials into log files / terminal scrollback.
	conn, err := discordDialConn(10 * time.Second)
	if err != nil {
		log.Printf("[mfa] solve dial error: %v", err)
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(req)); err != nil {
		log.Printf("[mfa] solve write error: %v", err)
		return nil
	}

	var resp []byte
	buf := make([]byte, 4096)
	for {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return resp
}

func solveTicketTOTP(ticket, code, token string, superProps, userAgent, cookie string) (string, int, error) {
	payload := map[string]interface{}{
		"ticket":   ticket,
		"mfa_type": "totp",
		"data":     code,
	}
	body, _ := json.Marshal(payload)
	req := buildMFASolveRequest(token, string(body), superProps, userAgent, cookie)
	resp := sendSolveRequest(req)
	if resp == nil {
		return "", 0, fmt.Errorf("request failed")
	}
	return parseFinishResponse(resp)
}

func solveTicketTOTPWithCookies(ticket, code, token string, superProps, userAgent, cookie string) (string, int, string, error) {
	payload := map[string]interface{}{
		"ticket":   ticket,
		"mfa_type": "totp",
		"data":     code,
	}
	body, _ := json.Marshal(payload)
	req := buildMFASolveRequest(token, string(body), superProps, userAgent, cookie)
	resp := sendSolveRequest(req)
	if resp == nil {
		return "", 0, "", fmt.Errorf("request failed")
	}
	// NOTE: mfaToken is the solved MFA authorization token; it shadows the
	// `token` parameter (the account auth token) intentionally, since we want
	// to return the MFA token here, not the auth token. Named explicitly to
	// avoid confusion.
	mfaToken, expiresIn, err := parseFinishResponse(resp)
	if err != nil {
		return "", 0, "", err
	}
	cookies := extractSetCookies(resp)
	return mfaToken, expiresIn, cookies, nil
}

func solveTicketBackup(ticket, code, token string, superProps, userAgent, cookie string) (string, int, error) {
	payload := map[string]interface{}{
		"ticket":   ticket,
		"mfa_type": "backup",
		"data":     code,
	}
	body, _ := json.Marshal(payload)
	req := buildMFASolveRequest(token, string(body), superProps, userAgent, cookie)
	resp := sendSolveRequest(req)
	if resp == nil {
		return "", 0, fmt.Errorf("request failed")
	}
	return parseFinishResponse(resp)
}

func solveTicket(ticket, password, token string, superProps, userAgent, cookie string) (string, int, error) {
	payload := map[string]interface{}{
		"ticket":   ticket,
		"mfa_type": "password",
		"data":     password,
	}
	body, _ := json.Marshal(payload)
	req := buildMFASolveRequest(token, string(body), superProps, userAgent, cookie)
	resp := sendSolveRequest(req)
	if resp == nil {
		return "", 0, fmt.Errorf("request failed")
	}
	return parseFinishResponse(resp)
}

// getSolveHeaders returns the MFA solve header values in a thread-safe manner.
func (m *MFAHandler) getSolveHeaders() (superProps, userAgent, cookie string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.superProps, m.userAgent, m.ticketCookies
}

// getFingerprintHeaders returns the browser-fingerprint values the claim PATCH
// must send to avoid Discord's anti-abuse filter (403 / 10008). This is the
// same header set that getTicket already sends; the claim PATCH (buildMFARequest)
// must match it or the request is treated as a cookieless new device and
// rejected.
func (m *MFAHandler) getFingerprintHeaders() (superProps, userAgent, dcfDuid, sdcfDuid, ticketCookies string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.superProps, m.userAgent, m.dcfDuid, m.sdcfDuid, m.ticketCookies
}

func (m *MFAHandler) getTicketCookies() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ticketCookies
}

// setTicketCookies merges new cookies into the existing ticketCookies store
// by cookie NAME, keeping the latest value for each name. This preserves
// Cloudflare's _cfuvid (set by the getTicket response) across the subsequent
// /mfa/finish solve — without merging, a solve response that only re-issues
// __dcfduid would silently drop _cfuvid, breaking the cookie chain the claim
// PATCH needs to look like a continuation of the same session.
//
// The merge is name-based because cookies arrive as "name=value" pairs (the
// attributes are stripped by extractSetCookies), so we re-split on '=' and
// dedup into a map, then re-join in stable order for the wire.
func (m *MFAHandler) setTicketCookies(cookies string) {
	merged := mergeCookieStrings(m.ticketCookies, cookies)
	m.mu.Lock()
	m.ticketCookies = merged
	m.mu.Unlock()
}

// mergeCookieStrings merges two "a=1; b=2" cookie strings by name, with values
// from b taking precedence over a for duplicate names. Returns "" if both are
// empty. Output order is deterministic (sorted by name) for stable wire bytes
// and easier log diffing.
func mergeCookieStrings(a, b string) string {
	parsed := make(map[string]string)
	for _, s := range []string{a, b} {
		for _, part := range strings.Split(s, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			eq := strings.IndexByte(part, '=')
			if eq < 0 {
				continue
			}
			parsed[strings.TrimSpace(part[:eq])] = strings.TrimSpace(part[eq+1:])
		}
	}
	if len(parsed) == 0 {
		return ""
	}
	names := make([]string, 0, len(parsed))
	for n := range parsed {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for i, n := range names {
		if i > 0 {
			sb.WriteString("; ")
		}
		fmt.Fprintf(&sb, "%s=%s", n, parsed[n])
	}
	return sb.String()
}

func (m *MFAHandler) solveTicket(ticket string) (string, int, error) {
	sp, ua, ck := m.getSolveHeaders()
	return solveTicket(ticket, m.password, m.target.Token, sp, ua, ck)
}

func (m *MFAHandler) solveTOTP(ticket string) (string, int, error) {
	code, err := totp.GenerateCode(m.totpSecret, time.Now())
	if err != nil {
		return "", 0, err
	}
	sp, ua, ck := m.getSolveHeaders()
	token, expiresIn, cookies, err := solveTicketTOTPWithCookies(ticket, code, m.target.Token, sp, ua, ck)
	if err == nil && cookies != "" {
		m.setTicketCookies(cookies)
	}
	return token, expiresIn, err
}

func (m *MFAHandler) solveBackup(ticket string) (string, int, error) {
	m.mu.Lock()
	if m.backupIndex >= len(m.backupCodes) {
		m.mu.Unlock()
		return "", 0, fmt.Errorf("no backup codes left")
	}
	code := m.backupCodes[m.backupIndex]
	m.mu.Unlock()

	sp, ua, ck := m.getSolveHeaders()
	token, expiresIn, err := solveTicketBackup(ticket, code, m.target.Token, sp, ua, ck)

	// Only consume the backup code if the solve actually succeeded. Previously
	// the index was incremented before the network call, so a transient failure
	// (network error, wrong code) permanently burned a single-use code. Backup
	// codes are a limited resource; don't waste them on failures. Note: if
	// Discord rejects a code as already-used/invalid, retrying the same code is
	// pointless, but that case still returns a token="" with a non-nil err, so
	// we advance the index only on definitive success.
	if err == nil && token != "" {
		m.mu.Lock()
		m.backupIndex++
		m.mu.Unlock()
	}
	return token, expiresIn, err
}

func (m *MFAHandler) SetToken(token string, expiresIn int) {
	if token == "" {
		return
	}
	m.mu.Lock()
	m.token = token
	m.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	// Close tokenReady on first SetToken so any goroutine blocked in
	// WaitForToken wakes up immediately.
	select {
	case <-m.tokenReady:
		// Already closed — nothing to do.
	default:
		close(m.tokenReady)
	}
	m.mu.Unlock()
	m.session.UpdateMFAToken(m.key, token, m.expiresAt.Unix())
	log.Printf("[mfa %s] token cached, valid until %s", m.target.Vanity, m.expiresAt.Format(time.RFC3339))
}

// WaitForToken blocks until an MFA token is available or the timeout expires.
// Returns the header name and value if ready, or ("", "") on timeout. This
// bridges the cold-start gap: the gateway signals availability ~3s after
// launch, but the MFA pre-solver has a 5s delay before the first solve.
// Without this wait, the burst fires with no MFA header and silently bails.
func (m *MFAHandler) WaitForToken(timeout time.Duration) (string, string) {
	select {
	case <-m.tokenReady:
		return m.GetHeader()
	case <-time.After(timeout):
		return "", ""
	}
}

func (m *MFAHandler) ClearToken() {
	m.mu.Lock()
	m.token = ""
	m.expiresAt = time.Time{}
	m.mu.Unlock()
}

// StartRefresh runs an aggressive background pre-solve loop that keeps an MFA
// token warm so the claim hot path (firstClaim/reclaim → GetHeader) can read a
// fresh token without ever blocking on a synchronous solve.
//
// Cadence (tuned for "always-warm" with Discord's real 300s MFA JWT lifetime):
//   - tickInterval (90s): how often we re-check token health. Frequent enough
//     that a token expiring mid-window is re-solved well before the hot path
//     needs it, without burning ticket-fetch PATCHes on every tick (we only
//     solve when the threshold trips).
//   - refreshWithin (90s): re-solve whenever fewer than this many seconds
//     remain (or the token is missing). Discord's MFA JWTs live 300s; with a
//     30s safety margin (jwtExpiresIn) the usable window is ~270s. A 90s
//     threshold means we re-solve when ~180s remain — well before expiry and
//     with 2 ticker cycles of headroom.
//
// The threshold means we solve at most ~2× per token lifetime: a 300s token
// crosses the 90s-remaining line after ~210s, so the 90s ticker fires ~2-3
// times before the threshold trips, and only one of them actually solves.
//
// Both TOTP and password solves fetch the ticket from the REAL guild now (see
// refreshTOTP), not guild "0": that ticket-fetch PATCH runs ~once per token
// lifetime here, never on the hot path, so it never competes with the burst.
func (m *MFAHandler) StartRefresh(ctx CancelContext) {
	// Pick the refresh strategy once. An account is either TOTP-backed or
	// password-backed; if neither is configured there's nothing to pre-solve —
	// return and let the hot path fall back to a synchronous solve on demand
	// (the handleMFAChallenge 60003-retry path in claimer.go).
	var refresh func() bool
	switch {
	case m.totpSecret != "":
		refresh = m.refreshTOTP
	case m.autoSolve:
		refresh = m.refresh
	default:
		return
	}

		const (
			tickInterval  = 90 * time.Second
			refreshWithin = 90 * time.Second
		)

		log.Printf("[mfa %s] pre-solve active (interval=%s, refresh-within=%s)",
			m.target.Vanity, tickInterval, refreshWithin)

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			needsRefresh := m.token == "" || time.Now().Add(refreshWithin).After(m.expiresAt)
			m.mu.Unlock()
			if needsRefresh {
				refresh()
			}
		}
	}
}

type CancelContext interface {
	Done() <-chan struct{}
}

type chanCancel struct {
	ch chan struct{}
}

func (c *chanCancel) Done() <-chan struct{} {
	return c.ch
}

func extractTicket(resp []byte) (string, error) {
	idx := bytes.Index(resp, []byte(`"ticket":"`))
	if idx < 0 {
		return "", fmt.Errorf("no ticket in response")
	}
	idx += 10
	end := bytes.IndexByte(resp[idx:], '"')
	if end < 0 {
		return "", fmt.Errorf("malformed ticket")
	}
	return string(resp[idx : idx+end]), nil
}

func parseFinishResponse(resp []byte) (token string, expiresIn int, err error) {
	// Prefer a structured JSON parse so we can read both token and expires_in.
	headerEnd := bytes.Index(resp, []byte("\r\n\r\n"))
	var bodyBytes []byte
	if headerEnd >= 0 {
		bodyBytes = resp[headerEnd+4:]
	} else {
		bodyBytes = resp
	}

	type finishResp struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	var fr finishResp
	if jerr := json.Unmarshal(bodyBytes, &fr); jerr == nil && fr.Token != "" {
		// Trust the JWT's own exp claim over the response's expires_in or any
		// hardcoded default. Discord's MFA tokens are HS256 JWTs with exp set to
		// iat+300 (5 minutes). The response sometimes omits expires_in or
		// includes a different value; the JWT is always authoritative. We also
		// subtract 30s (10% of lifetime) as a safety margin so we never send a
		// token that expires mid-flight.
		if exp := jwtExpiresIn(fr.Token); exp > 0 {
			expiresIn = exp
		} else if fr.ExpiresIn > 0 {
			expiresIn = fr.ExpiresIn
		} else {
			expiresIn = 300 // observed Discord MFA JWT lifetime
		}
		return fr.Token, expiresIn, nil
	}

	// Fallback: manual substring scan if the body isn't clean JSON (e.g.
	// chunked/concatenated reads).
	idx := bytes.Index(resp, []byte(`"token":"`))
	if idx < 0 {
		// Surface the status line so a failed solve (e.g. 60008 wrong code) is
		// diagnosable without dumping the full response body on every attempt.
		return "", 0, fmt.Errorf("no token in response (%s)", extractStatusLine(resp))
	}
	idx += 9
	end := bytes.IndexByte(resp[idx:], '"')
	if end < 0 {
		return "", 0, fmt.Errorf("malformed token")
	}
	token = string(resp[idx : idx+end])
	if exp := jwtExpiresIn(token); exp > 0 {
		return token, exp, nil
	}
	return token, 300, nil
}

// jwtExpiresIn extracts the remaining seconds until the JWT's exp claim,
// minus a 30s safety margin (10% of the typical 300s Discord MFA lifetime).
// Returns 0 if the token isn't a parseable JWT or has no exp claim.
func jwtExpiresIn(token string) int {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return 0
	}
	if claims.Exp == 0 {
		return 0
	}
	remaining := claims.Exp - time.Now().Unix() - 30
	if remaining < 60 {
		return 60 // floor: always report at least 1 minute of usability
	}
	return int(remaining)
}

func totpCode(secret string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("no totp secret")
	}
	return totp.GenerateCode(secret, time.Now())
}

// buildMFASolveRequest builds a raw HTTP/1.1 POST request to /api/v9/mfa/finish.
// The header set matches a real browser session: Auth, Content-Type, User-Agent,
// X-Super-Properties, Cookie, plus the full browser fingerprint set (Origin,
// Referer, Locale, Context, Accept, Accept-Language) so the solve request is
// not flagged as a scripted client. Earlier experiments omitted these extra
// headers because they caused 60008 "Invalid two-factor code" on some account
// cohorts, but Discord's anti-abuse now requires them for most accounts.
func buildMFASolveRequest(token, jsonBody, superProps, userAgent, cookie string) string {
	sb := new(strings.Builder)
	fmt.Fprintf(sb, "POST /api/v9/mfa/finish HTTP/1.1\r\n")
	fmt.Fprintf(sb, "Host: discord.com\r\n")
	fmt.Fprintf(sb, "Authorization: %s\r\n", token)
	fmt.Fprintf(sb, "Content-Type: application/json\r\n")
	fmt.Fprintf(sb, "Content-Length: %d\r\n", len(jsonBody))
	if userAgent != "" {
		fmt.Fprintf(sb, "User-Agent: %s\r\n", userAgent)
	}
	if superProps != "" {
		fmt.Fprintf(sb, "X-Super-Properties: %s\r\n", superProps)
	}
	if cookie != "" {
		fmt.Fprintf(sb, "Cookie: %s\r\n", cookie)
	}
	sb.WriteString("Origin: https://discord.com\r\n")
	sb.WriteString("Referer: https://discord.com/channels/@me\r\n")
	sb.WriteString("X-Discord-Locale: en-US\r\n")
	sb.WriteString("X-Context-Properties: eyJsb2NhdGlvbiI6Ikd1aWxkU2V0dGluZ3MifQ==\r\n")
	sb.WriteString("X-Debug-Options: bugReporterEnabled\r\n")
	sb.WriteString("Accept: */*\r\n")
	sb.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	sb.WriteString("Sec-Fetch-Site: same-origin\r\n")
	sb.WriteString("Sec-Fetch-Mode: cors\r\n")
	sb.WriteString("Sec-Fetch-Dest: empty\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(jsonBody)
	return sb.String()
}

// extractSetCookies parses Set-Cookie headers from a raw HTTP response.
// Returns a semicolon-separated cookie string suitable for reuse.
func extractSetCookies(resp []byte) string {
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return ""
	}
	headerBlock := resp[:idx]
	lines := bytes.Split(headerBlock, []byte("\r\n"))

	var cookies []string
	for _, line := range lines {
		lower := bytes.ToLower(line)
		if bytes.HasPrefix(lower, []byte("set-cookie:")) {
			// Extract just the name=value part (before first semicolon)
			val := bytes.TrimSpace(line[11:])
			scIdx := bytes.IndexByte(val, ';')
			if scIdx >= 0 {
				val = val[:scIdx]
			}
			cookies = append(cookies, string(val))
		}
	}

	return strings.Join(cookies, "; ")
}
