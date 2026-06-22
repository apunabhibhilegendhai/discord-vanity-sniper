package main

import (
	"fmt"
	"strings"
	"sync"
)

// ClaimRequest is a pre-parsed PATCH template for vanity-url claims. The MFA
// header is spliced at publish time:
//
//	prefix + "X-Discord-MFA-Authorization: <token>\r\n" + mfaSuffix
//
// The template sends only the minimal header set matching the proven working JS
// sniper (main.js tryClaim): request-line, Host, Authorization,
// X-Super-Properties, X-Discord-MFA-Authorization, Content-Type, Content-Length,
// User-Agent. No Cookie, Origin, Referer, or other browser-like headers — those
// were found to trigger 403/10008 "Unknown Message" rather than prevent it.
type ClaimRequest struct {
	prefix    []byte
	mfaSuffix []byte // everything after the MFA placeholder line (headers + body)
	noMFA     []byte // pre-built request with no MFA header (triggers 60003 ticket)
}

var claimBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 2048) },
}

func getClaimBuf(min int) []byte {
	b := claimBufPool.Get().([]byte)
	if len(b) < min {
		b = make([]byte, min)
	}
	return b
}

func putClaimBuf(b []byte) {
	claimBufPool.Put(b)
}

// RenderClaimBytes produces a fresh wire-ready []byte for the claim PATCH given
// an MFA header name+value, mirroring ClaimRequest.BuildClaimMFA but callable
// without a pre-built ClaimRequest template. Used by the pre-armed sentry
// worker reload path.
//
// Returns nil if no usable token is available (caller must bail rather than send
// a bare PATCH, which Discord's anti-abuse filter rejects with 403/10008).
func RenderClaimBytes(t *Target, cfg *Conf, mfaName, mfaValue string) []byte {
	if mfaName == "" || mfaValue == "" {
		return nil
	}
	req := BuildClaimRequest(t, cfg)
	return req.BuildClaimMFA(mfaValue)
}

// RenderClaimBytesWith is the hot-path variant: it takes an already-built
// ClaimRequest template (which the caller caches for the claimer's lifetime)
// and renders the wire bytes by splicing the MFA token into the placeholder
// slot. The only work per call is buffer copies — no strings.Builder, no header
// re-render, no allocation of the prefix/suffix slices. The claimer publishes
// this result once per burst and every sentry reads it via atomic load.
//
// Returns nil if no usable token is available.
func RenderClaimBytesWith(tpl *ClaimRequest, mfaName, mfaValue string) []byte {
	if tpl == nil || mfaName == "" || mfaValue == "" {
		return nil
	}
	return tpl.BuildClaimMFA(mfaValue)
}

func BuildClaimRequest(t *Target, cfg *Conf) *ClaimRequest {
	body := fmt.Sprintf(`{"code":"%s"}`, t.Vanity)

	sb := new(strings.Builder)

	fmt.Fprintf(sb, "PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n", t.GuildID)
	fmt.Fprintf(sb, "Host: discord.com\r\n")
	fmt.Fprintf(sb, "Authorization: %s\r\n", t.Token)
	if cfg.Fingerprint.SuperPropsB64 != "" {
		fmt.Fprintf(sb, "X-Super-Properties: %s\r\n", cfg.Fingerprint.SuperPropsB64)
	}

	// MFA slot: BuildClaimMFA replaces this placeholder with the proper header.
	mfaSlotEnd := sb.Len()
	sb.WriteString("X-Discord-MFA: XXXXXX\r\n")

	fmt.Fprintf(sb, "Content-Type: application/json\r\n")
	fmt.Fprintf(sb, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(sb, "User-Agent: %s\r\n", cfg.Fingerprint.UserAgent)
	sb.WriteString("\r\n")
	sb.WriteString(body)

	buf := []byte(sb.String())

	// Split at the MFA placeholder: prefix is everything before the placeholder
	// line, suffix is everything after it (rest of headers + body).
	prefix := make([]byte, mfaSlotEnd)
	copy(prefix, buf[:mfaSlotEnd])

	afterMFA := mfaSlotEnd + len("X-Discord-MFA: XXXXXX\r\n")
	suffix := make([]byte, len(buf)-afterMFA)
	copy(suffix, buf[afterMFA:])

	// No-MFA request: same headers but with the MFA line omitted entirely.
	// Discord responds 401/60003 with a ticket.
	noMFA := buildNoMFARequest(t, cfg, body)

	return &ClaimRequest{
		prefix:    prefix,
		mfaSuffix: suffix,
		noMFA:     noMFA,
	}
}

func (c *ClaimRequest) BuildNoMFA() []byte {
	if len(c.noMFA) == 0 {
		return nil
	}
	n := len(c.noMFA)
	buf := getClaimBuf(n)
	copy(buf, c.noMFA)
	return buf[:n]
}

// BuildClaimMFA renders a pre-built MFA claim PATCH by splicing the proper MFA
// header into the template slot. No Cookie header is sent — matching the proven
// working JS sniper (main.js tryClaim), which intentionally omits it (including
// __Secure-recent_mfa triggers 403/10008).
func (c *ClaimRequest) BuildClaimMFA(token string) []byte {
	const mfaHeader = "X-Discord-MFA-Authorization: "
	total := len(c.prefix) + len(mfaHeader) + len(token) + 2 + len(c.mfaSuffix)
	buf := getClaimBuf(total)

	n := 0
	n += copy(buf[n:], c.prefix)
	n += copy(buf[n:], mfaHeader)
	n += copy(buf[n:], token)
	n += copy(buf[n:], "\r\n")
	n += copy(buf[n:], c.mfaSuffix)

	return buf[:n]
}

// buildNoMFARequest builds a complete PATCH request with the minimal header set
// but NO MFA header. Discord responds 401 with code 60003 and a ticket.
func buildNoMFARequest(t *Target, cfg *Conf, body string) []byte {
	sb := new(strings.Builder)
	fmt.Fprintf(sb, "PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n", t.GuildID)
	fmt.Fprintf(sb, "Host: discord.com\r\n")
	fmt.Fprintf(sb, "Authorization: %s\r\n", t.Token)
	if cfg.Fingerprint.SuperPropsB64 != "" {
		fmt.Fprintf(sb, "X-Super-Properties: %s\r\n", cfg.Fingerprint.SuperPropsB64)
	}
	fmt.Fprintf(sb, "Content-Type: application/json\r\n")
	fmt.Fprintf(sb, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(sb, "User-Agent: %s\r\n", cfg.Fingerprint.UserAgent)
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return []byte(sb.String())
}
