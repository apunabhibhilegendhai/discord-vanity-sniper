package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildClaimMFARendersCorrectHeaders(t *testing.T) {
	target := &Target{
		GuildID: "123456789",
		Vanity:  "testvanity",
		Token:   "FAKE_TOKEN",
	}
	cfg := &Conf{
		Fingerprint: Fingerprint{
			DcfDuid:       "dcf-123",
			SdcfDuid:      "sdcf-456",
			SuperPropsB64: "SPB64",
			UserAgent:     "TestUA/1.0",
		},
	}

	tpl := BuildClaimRequest(target, cfg)
	if tpl == nil {
		t.Fatal("BuildClaimRequest returned nil")
	}

	token := "MFA.JWT.TOKEN"
	out := tpl.BuildClaimMFA(token)

	s := string(out)
	t.Logf("=== Rendered request ===\n%s", s)

	// Must have the proper MFA header line (full name + value + CRLF).
	if !strings.Contains(s, "X-Discord-MFA-Authorization: "+token+"\r\n") {
		t.Errorf("missing/corrupt X-Discord-MFA-Authorization header")
	}
	// Must NOT contain the old placeholder.
	if strings.Contains(s, "XXXXXX") {
		t.Errorf("old MFA placeholder 'XXXXXX' leaked into output")
	}
	if strings.Contains(s, "X-Discord-MFA:") {
		t.Errorf("old MFA header 'X-Discord-MFA:' present in output")
	}
	// Must NOT contain Cookie header (matching working main.js tryClaim).
	if strings.Contains(s, "Cookie:") {
		t.Errorf("Cookie header present but should be omitted (main.js sends none)")
	}
	// Must NOT contain the anti-abuse-triggering x-headers.
	if strings.Contains(s, "Origin:") {
		t.Errorf("Origin header present but should be omitted")
	}
	if strings.Contains(s, "Referer:") {
		t.Errorf("Referer header present but should be omitted")
	}
	if strings.Contains(s, "X-Discord-Locale:") {
		t.Errorf("X-Discord-Locale present but should be omitted")
	}
	if strings.Contains(s, "X-Discord-Timezone:") {
		t.Errorf("X-Discord-Timezone present but should be omitted")
	}
	if strings.Contains(s, "X-Context-Properties:") {
		t.Errorf("X-Context-Properties present but should be omitted")
	}
	// Sanity: the request line and host must be intact.
	if !strings.HasPrefix(s, "PATCH /api/v9/guilds/123456789/vanity-url HTTP/1.1\r\n") {
		t.Errorf("request line corrupt")
	}
	if !strings.Contains(s, "Host: discord.com\r\n") {
		t.Errorf("Host header missing")
	}
	if !strings.Contains(s, "Authorization: FAKE_TOKEN\r\n") {
		t.Errorf("Authorization header missing")
	}
	// Body must come last (trim trailing pool padding — getClaimBuf over-allocates).
	trimmed := bytes.TrimRight(out, "\x00 ")
	if !bytes.HasSuffix(trimmed, []byte(`{"code":"testvanity"}`)) {
		t.Errorf("body not at end of request; got tail %q", trimmed[len(trimmed)-40:])
	}
	// Header/body separator must appear exactly once in the trimmed output.
	if c := bytes.Count(trimmed, []byte("\r\n\r\n")); c != 1 {
		t.Errorf("expected exactly one header/body separator, got %d", c)
	}
	// Must have exactly the main.js header set: request-line, Host, Auth, SP, MFA,
	// Content-Type, Content-Length, User-Agent = 8 header lines + blank line.
	lines := strings.SplitN(s, "\r\n", -1)
	headerLines := 0
	for _, line := range lines {
		if line == "" {
			break
		}
		headerLines++
	}
	if headerLines != 8 {
		t.Errorf("expected 8 header lines (got %d): request-line + Host + Auth + SP + MFA + CT + CL + UA", headerLines)
	}
}

func TestBuildClaimMFAEmptyCookieOmitsCookieValue(t *testing.T) {
	target := &Target{
		GuildID: "123",
		Vanity:  "v",
		Token:   "TOK",
	}
	cfg := &Conf{
		Fingerprint: Fingerprint{
			DcfDuid:       "d",
			SdcfDuid:      "s",
			SuperPropsB64: "sp",
			UserAgent:     "UA",
		},
	}
	tpl := BuildClaimRequest(target, cfg)
	out := tpl.BuildClaimMFA("jwt")
	s := string(out)
	t.Logf("=== Rendered request (no cookie) ===\n%s", s)
	// No Cookie header even with empty cookie.
	if strings.Contains(s, "Cookie:") {
		t.Errorf("Cookie header present with empty cookie")
	}
}
