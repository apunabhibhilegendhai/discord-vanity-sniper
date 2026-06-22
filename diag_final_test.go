//go:build live

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestClaimCookieOnly(t *testing.T) {
	cfg, err := LoadConfig("config.json")
	if err != nil { t.Fatalf("%v", err) }
	target := &cfg.Targets[0]

	sessions := NewSessionStore(cfg.SessionPath)
	sessions.Load()
	mfa := NewMFAHandler(target, sessions, cfg.Password, cfg.TOTPSecret, cfg.BackupCodes, &cfg.Fingerprint)
	mfa.ClearToken()
	if !mfa.EnsureValid() { t.Fatalf("EnsureValid failed") }
	_, mfaValue := mfa.GetHeader()
	_, _, dcfDuid, sdcfDuid, ticketCookies := mfa.getFingerprintHeaders()

	// Scenario A: Cookie ONLY (no MFA header)
	body := fmt.Sprintf(`{"code":"%s"}`, target.Vanity)
	
	for label, includeMFA := range map[string]bool{"NO_MFA_HEADER": false, "WITH_MFA_HEADER": true} {
		conn, err := discordDialConn(10*time.Second)
		if err != nil { t.Fatalf("dial: %v", err) }
		conn.SetDeadline(time.Now().Add(10*time.Second))

		sb := new(strings.Builder)
		fmt.Fprintf(sb, "PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n", target.GuildID)
		fmt.Fprintf(sb, "Host: discord.com\r\n")
		fmt.Fprintf(sb, "Authorization: %s\r\n", target.Token)
		if cfg.Fingerprint.SuperPropsB64 != "" {
			fmt.Fprintf(sb, "X-Super-Properties: %s\r\n", cfg.Fingerprint.SuperPropsB64)
		}
		if includeMFA {
			fmt.Fprintf(sb, "X-Discord-MFA-Authorization: %s\r\n", mfaValue)
		}
		fmt.Fprintf(sb, "Content-Type: application/json\r\n")
		fmt.Fprintf(sb, "Content-Length: %d\r\n", len(body))
		fmt.Fprintf(sb, "User-Agent: %s\r\n", cfg.Fingerprint.UserAgent)
		fmt.Fprintf(sb, "Cookie: %s\r\n", buildCookieHeader(dcfDuid, sdcfDuid, ticketCookies))
		sb.WriteString("\r\n")
		sb.WriteString(body)
		bytes := []byte(sb.String())
		
		conn.Write(bytes)
		var resp []byte
		buf := make([]byte, 4096)
		for { n, rerr := conn.Read(buf); if n > 0 { resp = append(resp, buf[:n]...) }; if rerr != nil { break } }
		conn.Close()
		
		t.Logf("[%s] status: %s | body: %s", label, extractStatusLine(resp), extractBody(resp))
	}

	// Scenario C: With cookie but __Secure-recent_mfa ONLY (no other cookies)
	conn3, err := discordDialConn(10*time.Second)
	if err != nil { t.Fatalf("dial3: %v", err) }
	defer conn3.Close()
	conn3.SetDeadline(time.Now().Add(10*time.Second))
	
	// Extract just the __Secure-recent_mfa from ticketCookies
	var mfaCookie string
	for _, part := range strings.Split(ticketCookies, "; ") {
		if strings.HasPrefix(part, "__Secure-recent_mfa=") {
			mfaCookie = part
			break
		}
	}
	
	sb3 := new(strings.Builder)
	fmt.Fprintf(sb3, "PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n", target.GuildID)
	fmt.Fprintf(sb3, "Host: discord.com\r\n")
	fmt.Fprintf(sb3, "Authorization: %s\r\n", target.Token)
	if cfg.Fingerprint.SuperPropsB64 != "" {
		fmt.Fprintf(sb3, "X-Super-Properties: %s\r\n", cfg.Fingerprint.SuperPropsB64)
	}
	fmt.Fprintf(sb3, "X-Discord-MFA-Authorization: %s\r\n", mfaValue)
	fmt.Fprintf(sb3, "Content-Type: application/json\r\n")
	fmt.Fprintf(sb3, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(sb3, "User-Agent: %s\r\n", cfg.Fingerprint.UserAgent)
	if mfaCookie != "" {
		fmt.Fprintf(sb3, "Cookie: %s\r\n", mfaCookie)
	}
	sb3.WriteString("\r\n")
	sb3.WriteString(body)
	bytes3 := []byte(sb3.String())
	conn3.Write(bytes3)
	var resp3 []byte
	buf3 := make([]byte, 4096)
	for { n, rerr := conn3.Read(buf3); if n > 0 { resp3 = append(resp3, buf3[:n]...) }; if rerr != nil { break } }
	t.Logf("[COOKIE_ONLY_MFA] status: %s | body: %s", extractStatusLine(resp3), extractBody(resp3))
}
