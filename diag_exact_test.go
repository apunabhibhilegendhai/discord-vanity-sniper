//go:build live

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestClaimExactGetTicket(t *testing.T) {
	cfg, err := LoadConfig("config.json")
	if err != nil { t.Fatalf("%v", err) }
	target := &cfg.Targets[0]

	sessions := NewSessionStore(cfg.SessionPath)
	sessions.Load()
	mfa := NewMFAHandler(target, sessions, cfg.Password, cfg.TOTPSecret, cfg.BackupCodes, &cfg.Fingerprint)
	mfa.ClearToken()
	if !mfa.EnsureValid() { t.Fatalf("EnsureValid failed") }
	_, mfaValue := mfa.GetHeader()

	body := fmt.Sprintf(`{"code":"%s"}`, target.Vanity)

	// Test: EXACTLY like getTicket but WITH MFA header
	// getTicket sends: Cookie: __dcfduid=X; __sdcfduid=Y
	// (no _cfuvid, no __Secure-recent_mfa)
	for label, cookie := range map[string]string{
		"DEVICE_ONLY": fmt.Sprintf("__dcfduid=%s; __sdcfduid=%s", cfg.Fingerprint.DcfDuid, cfg.Fingerprint.SdcfDuid),
		"NO_COOKIE":   "",
	} {
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
		fmt.Fprintf(sb, "X-Discord-MFA-Authorization: %s\r\n", mfaValue)
		fmt.Fprintf(sb, "Content-Type: application/json\r\n")
		fmt.Fprintf(sb, "Content-Length: %d\r\n", len(body))
		fmt.Fprintf(sb, "User-Agent: %s\r\n", cfg.Fingerprint.UserAgent)
		if cookie != "" {
			fmt.Fprintf(sb, "Cookie: %s\r\n", cookie)
		}
		sb.WriteString("\r\n")
		sb.WriteString(body)
		bytes := []byte(sb.String())
		conn.Write(bytes)

		var resp []byte
		buf := make([]byte, 4096)
		for { n, rerr := conn.Read(buf); if n > 0 { resp = append(resp, buf[:n]...) }; if rerr != nil { break } }
		conn.Close()

		t.Logf("[%s] status: %s | body: %s", label, extractStatusLine(resp), extractBody(resp))
		
		if strings.Contains(extractBody(resp), "10008") {
			t.Logf("  => 403/10008")
		} else {
			t.Logf("  => NON-10008! Check above.")
		}
	}
}
