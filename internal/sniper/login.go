package sniper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// login.go implements Discord account login + MFA solve to mint a fresh user
// token from email/password/TOTP. This lets the sniper recover automatically
// when a cached token dies (401) without a manual token-grab from DevTools.
//
// Flow:
//   1. POST /api/v9/auth/login {"login": email, "password": pwd, "undelete": false}
//      -> if MFA enabled: {"ticket": "...", "mfa": true, "sms": false, ...}
//   2. POST /api/v9/auth/mfa/totp {"ticket": ..., "code": "<totp>"}
//      -> {"token": "<USER TOKEN>"}
//
// We send the full browser-fingerprint header set (matching getTicket /
// buildMFARequest) so the login isn't flagged by anti-abuse.

// ValidateToken does a lightweight GET /users/@me to confirm a token still
// works. Returns true if Discord returns 2xx. Used to decide whether to mint.
func ValidateToken(token, superProps, userAgent, cookie string) bool {
	req := buildGetMeRequest(token, superProps, userAgent, cookie)
	resp := sendLoginRequest(req)
	return resp != nil && parseStatusCode(resp)/100 == 2
}

func buildGetMeRequest(token, superProps, userAgent, cookie string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET /api/v9/users/@me HTTP/1.1\r\n")
	fmt.Fprintf(&sb, "Host: discord.com\r\n")
	fmt.Fprintf(&sb, "Authorization: %s\r\n", token)
	if superProps != "" {
		fmt.Fprintf(&sb, "X-Super-Properties: %s\r\n", superProps)
	}
	if cookie != "" {
		fmt.Fprintf(&sb, "Cookie: %s\r\n", cookie)
	}
	if userAgent != "" {
		fmt.Fprintf(&sb, "User-Agent: %s\r\n", userAgent)
	}
	sb.WriteString("Accept: */*\r\n")
	sb.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	sb.WriteString("Connection: close\r\n\r\n")
	return sb.String()
}

// MintToken performs email/password login, solves the TOTP challenge, and
// returns a fresh user token. Returns (token, error).
func MintToken(email, password, totpSecret, superProps, userAgent string) (string, error) {
	if email == "" || password == "" {
		return "", fmt.Errorf("email and password required for auto-login")
	}
	if totpSecret == "" {
		return "", fmt.Errorf("totp_secret required for auto-login (account has MFA)")
	}

	cookie := "" // first request has no cookies

	// Step 1: POST /auth/login
	loginBody, _ := json.Marshal(map[string]interface{}{
		"login":     email,
		"password":  password,
		"undelete":  false,
		"login_src": "dash",
	})
	loginReq := buildAuthPostRequest("/api/v9/auth/login", string(loginBody), "", superProps, userAgent, cookie)
	loginResp := sendLoginRequest(loginReq)
	if loginResp == nil {
		return "", fmt.Errorf("login: no response from discord")
	}
	log.Printf("[login] /auth/login status: %s", extractStatusLine(loginResp))

	// Capture cookies for the follow-up MFA request (Discord may set device
	// cookies here that it expects on /auth/mfa/finish).
	cookie = extractSetCookies(loginResp)

	body := extractRawBody(loginResp)

	// Success path: some accounts (no MFA) get the token directly here.
	if tok := extractJSONStringField(body, "token"); tok != "" {
		log.Printf("[login] login returned token directly (no MFA)")
		return tok, nil
	}

	ticket := extractJSONStringField(body, "ticket")
	if ticket == "" {
		return "", fmt.Errorf("login: no ticket and no token in response: %s", truncate(body, 300))
	}
	loginInstanceID := extractJSONStringField(body, "login_instance_id")
	log.Printf("[login] MFA required, got ticket, solving via TOTP...")

	// Step 2: POST /auth/mfa/totp  (the "Verify MFA Login" endpoint for TOTP).
	// NOTE: this is DIFFERENT from /mfa/finish (used for action-elevation MFA).
	// Login MFA takes {"ticket", "code", "login_instance_id?"} and returns the
	// account auth token. See https://docs.discord.food/authentication.
	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		return "", fmt.Errorf("totp generate: %w", err)
	}
	finishPayload := map[string]interface{}{
		"ticket": ticket,
		"code":   code,
	}
	if loginInstanceID != "" {
		finishPayload["login_instance_id"] = loginInstanceID
	}
	finishBody, _ := json.Marshal(finishPayload)
	finishReq := buildAuthPostRequest("/api/v9/auth/mfa/totp", string(finishBody), "", superProps, userAgent, cookie)
	finishResp := sendLoginRequest(finishReq)
	if finishResp == nil {
		return "", fmt.Errorf("mfa/totp: no response")
	}
	log.Printf("[login] /auth/mfa/totp status: %s", extractStatusLine(finishResp))

	finishBodyStr := extractRawBody(finishResp)
	tok := extractJSONStringField(finishBodyStr, "token")
	if tok == "" {
		return "", fmt.Errorf("mfa/totp: no token in response: %s", truncate(finishBodyStr, 300))
	}
	return tok, nil
}

func buildAuthPostRequest(path, body, auth, superProps, userAgent, cookie string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "POST %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&sb, "Host: discord.com\r\n")
	if auth != "" {
		fmt.Fprintf(&sb, "Authorization: %s\r\n", auth)
	}
	fmt.Fprintf(&sb, "Content-Type: application/json\r\n")
	fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	if superProps != "" {
		fmt.Fprintf(&sb, "X-Super-Properties: %s\r\n", superProps)
	}
	if cookie != "" {
		fmt.Fprintf(&sb, "Cookie: %s\r\n", cookie)
	}
	if userAgent != "" {
		fmt.Fprintf(&sb, "User-Agent: %s\r\n", userAgent)
	}
	sb.WriteString("Origin: https://discord.com\r\n")
	sb.WriteString("Referer: https://discord.com/login\r\n")
	sb.WriteString("X-Discord-Locale: en-US\r\n")
	sb.WriteString("X-Context-Properties: eyJsb2NhdGlvbiI6IkxvZ2luIn0=\r\n") // {"location":"Login"}
	sb.WriteString("Accept: */*\r\n")
	sb.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	sb.WriteString("Connection: close\r\n\r\n")
	sb.WriteString(body)
	return sb.String()
}

func sendLoginRequest(req string) []byte {
	conn, err := discordDialConn(10 * time.Second)
	if err != nil {
		log.Printf("[login] dial error: %v", err)
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(req)); err != nil {
		log.Printf("[login] write error: %v", err)
		return nil
	}

	var resp []byte
	buf := make([]byte, 4096)
	for {
		conn.SetDeadline(time.Now().Add(8 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil {
			// Capture the terminal read error so an empty/aborted response
			// isn't a silent "status: unknown" — we need to know whether it's
			// EOF, a TLS alert, a reset, or a deadline.
			log.Printf("[login] read terminated after %d bytes: %v", len(resp), err)
			break
		}
	}
	// Diagnostic: if we got nothing (or something that doesn't look like
	// HTTP/1.1), dump the first bytes so we can see what Discord/Cloudflare
	// actually returned. extractStatusLine returns "unknown" when there's no
	// '\r' — i.e. empty or non-HTTP (TLS alert text, HTML challenge page, etc.).
	if len(resp) < 16 || !bytes.HasPrefix(resp, []byte("HTTP/")) {
		preview := resp
		if len(preview) > 256 {
			preview = preview[:256]
		}
		log.Printf("[login] non-HTTP response (%d bytes): %q", len(resp), string(preview))
	}
	return resp
}

// extractRawBody returns the HTTP body (everything after the header
// terminator), de-chunked when the response arrived with Transfer-Encoding:
// chunked. Discord's auth endpoints respond chunked; handing the raw wire form
// (with embedded hex chunk-size markers) to the JSON parsers corrupted
// extraction — and could embed size-marker bytes INSIDE a token the fallback
// scan pulled out of a chunk boundary.
func extractRawBody(resp []byte) string {
	return string(respBody(resp))
}

// extractJSONStringField pulls a top-level "field":"value" via a structured
// parse first, falling back to a tolerant substring scan for non-JSON (chunked,
// truncated) bodies. Used for token / ticket extraction.
func extractJSONStringField(body, field string) string {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err == nil {
		if v, ok := m[field].(string); ok {
			return v
		}
	}
	// Fallback scan: "field":"value"
	needle := []byte(`"` + field + `":"`)
	idx := bytes.Index([]byte(body), needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := bytes.IndexByte([]byte(body)[start:], '"')
	if end < 0 {
		return ""
	}
	return body[start : start+end]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
