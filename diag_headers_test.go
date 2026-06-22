//go:build live

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestFullResponseHeaders(t *testing.T) {
	cfg, err := LoadConfig("config.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	target := &cfg.Targets[0]
	body := fmt.Sprintf(`{"code":"%s"}`, target.Vanity)

	// Get ticket + solve TOTP (new connection)
	conn, _ := discordDialConn(10*time.Second)
	conn.SetDeadline(time.Now().Add(30*time.Second))
	br := bufio.NewReaderSize(conn, 16384)

	readFull := func() []byte {
		var buf bytes.Buffer
		var cl int64 = -1
		chunked := false
		for {
			line, rerr := br.ReadString('\n')
			if rerr != nil { break }
			buf.WriteString(line)
			l := strings.TrimSuffix(line, "\r\n")
			if l == "" { break }
			lo := strings.ToLower(l)
			if strings.HasPrefix(lo, "content-length:") { fmt.Sscanf(l, "Content-Length: %d", &cl) }
			if strings.HasPrefix(lo, "transfer-encoding:") && strings.Contains(lo, "chunked") { chunked = true }
		}
		if chunked {
			for {
				line, _ := br.ReadString('\n')
				line = strings.TrimSuffix(line, "\r\n")
				var cs int64; fmt.Sscanf(line, "%x", &cs)
				if cs == 0 { br.ReadString('\n'); break }
				chunk := make([]byte, cs+2); io.ReadFull(br, chunk)
				buf.Write(chunk[:cs])
			}
		} else if cl >= 0 {
			chunk := make([]byte, cl); io.ReadFull(br, chunk)
			buf.Write(chunk)
		}
		return buf.Bytes()
	}

	r1 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\nHost: discord.com\r\nAuthorization: %s\r\nX-Super-Properties: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n%s",
		target.GuildID, target.Token, cfg.Fingerprint.SuperPropsB64, len(body), cfg.Fingerprint.UserAgent, body)
	conn.Write([]byte(r1))
	resp1 := readFull()
	ticket, _ := extractTicket(resp1)
	sc1 := extractSetCookies(resp1)

	code, _ := totp.GenerateCode(cfg.TOTPSecret, time.Now())
	sp := fmt.Sprintf(`{"ticket":"%s","mfa_type":"totp","data":"%s"}`, ticket, code)
	r2 := fmt.Sprintf("POST /api/v9/mfa/finish HTTP/1.1\r\nHost: discord.com\r\nAuthorization: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nUser-Agent: %s\r\nX-Super-Properties: %s\r\nCookie: __dcfduid=%s; __sdcfduid=%s; %s\r\nConnection: keep-alive\r\n\r\n%s",
		target.Token, len(sp), cfg.Fingerprint.UserAgent, cfg.Fingerprint.SuperPropsB64,
		cfg.Fingerprint.DcfDuid, cfg.Fingerprint.SdcfDuid, sc1, sp)
	conn.Write([]byte(r2))
	resp2 := readFull()
	mfaToken, _, _ := parseFinishResponse(resp2)
	sc2 := extractSetCookies(resp2)

	// Claim - dump ALL response headers
	merged := mergeCookieStrings(fmt.Sprintf("__dcfduid=%s; __sdcfduid=%s", cfg.Fingerprint.DcfDuid, cfg.Fingerprint.SdcfDuid), sc2)
	r3 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\nHost: discord.com\r\nAuthorization: %s\r\nX-Super-Properties: %s\r\nX-Discord-MFA-Authorization: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nUser-Agent: %s\r\nCookie: %s\r\nConnection: close\r\n\r\n%s",
		target.GuildID, target.Token, cfg.Fingerprint.SuperPropsB64, mfaToken, len(body), cfg.Fingerprint.UserAgent, merged, body)
		
	conn2, _ := discordDialConn(10*time.Second)
	conn2.SetDeadline(time.Now().Add(10*time.Second))
	conn2.Write([]byte(r3))

	var rawResp bytes.Buffer
	br2 := bufio.NewReaderSize(conn2, 8192)
	for {
		line, rerr := br2.ReadString('\n')
		if rerr != nil { break }
		rawResp.WriteString(line)
	}
	conn2.Close()
	
	// Print EVERYTHING
	t.Logf("=== FULL RESPONSE ===")
	for _, line := range strings.Split(rawResp.String(), "\r\n") {
		t.Logf("  %s", line)
	}

	// Also check: does the response set any cf-* headers?
	respStr := rawResp.String()
	if strings.Contains(respStr, "cf-") {
		t.Logf("--- Cloudflare headers found ---")
	}
	if strings.Contains(respStr, "x-discord") {
		t.Logf("--- X-Discord headers found ---")
	}
	
	// Decode the JWT fully
	t.Logf("=== JWT FULL DECODE ===")
	jwtParts := strings.Split(mfaToken, ".")
	for i, part := range jwtParts {
		if i > 1 { break } // skip signature
		pad := (4 - len(part)%4) % 4
		p := part + strings.Repeat("=", pad)
		decoded, err := base64.URLEncoding.DecodeString(p)
		if err == nil {
			t.Logf("JWT part %d: %s", i, string(decoded))
		}
	}
}
