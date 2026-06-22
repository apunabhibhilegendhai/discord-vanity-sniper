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

func TestExactJSSniperApproach(t *testing.T) {
	cfg, err := LoadConfig("config.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	target := &cfg.Targets[0]
	body := fmt.Sprintf(`{"code":"%s"}`, target.Vanity)

	// Get ticket + solve on one connection
	conn, _ := discordDialConn(10*time.Second)
	conn.SetDeadline(time.Now().Add(30*time.Second))
	br := bufio.NewReaderSize(conn, 16384)

	readResp := func() []byte {
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

	sp := cfg.Fingerprint.SuperPropsB64
	ua := cfg.Fingerprint.UserAgent

	// 1) getTicket (with minimal headers + Cookie for ticket)
	r1 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"Cookie: __dcfduid=%s; __sdcfduid=%s\r\n"+
		"Connection: keep-alive\r\n\r\n%s",
		target.GuildID, target.Token, sp, len(body), ua,
		cfg.Fingerprint.DcfDuid, cfg.Fingerprint.SdcfDuid, body)
	conn.Write([]byte(r1))
	resp1 := readResp()
	ticket, _ := extractTicket(resp1)
	sc1 := extractSetCookies(resp1)
	t.Logf("ticket=%s", ticket)

	// 2) Solve TOTP
	code, _ := totp.GenerateCode(cfg.TOTPSecret, time.Now())
	sp2 := fmt.Sprintf(`{"ticket":"%s","mfa_type":"totp","data":"%s"}`, ticket, code)
	r2 := fmt.Sprintf("POST /api/v9/mfa/finish HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"Cookie: %s\r\n"+
		"Connection: keep-alive\r\n\r\n%s",
		target.Token, len(sp2), ua, sp, sc1, sp2)
	conn.Write([]byte(r2))
	resp2 := readResp()
	mfaToken, _, _ := parseFinishResponse(resp2)
	sc2 := extractSetCookies(resp2)
	t.Logf("mfa token obtained (len=%d)", len(mfaToken))

	// Decode JWT
	jwtParts := strings.Split(mfaToken, ".")
	var jwtPayloadStr string
	if len(jwtParts) == 3 {
		pad := (4 - len(jwtParts[1])%4) % 4
		p := jwtParts[1] + strings.Repeat("=", pad)
		decoded, _ := base64.URLEncoding.DecodeString(p)
		jwtPayloadStr = string(decoded)
		t.Logf("JWT: %s", jwtPayloadStr)
	}

	// 3) Claim — EXACTLY 8 headers, NO Cookie, NO Origin, NO Referer, NO extra headers
	// Exactly like the JS sniper (per unit test TestBuildClaimMFARendersCorrectHeaders)
	t.Log("=== EXACT JS SNIPER: 8 headers, no Cookie ===")
	conn2, _ := discordDialConn(10*time.Second)
	conn2.SetDeadline(time.Now().Add(10*time.Second))

	r3 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"X-Discord-MFA-Authorization: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"\r\n%s",
		target.GuildID, target.Token, sp, mfaToken, len(body), ua, body)
	
	conn2.Write([]byte(r3))
	var rawResp bytes.Buffer
	br2 := bufio.NewReaderSize(conn2, 8192)
	for {
		line, rerr := br2.ReadString('\n')
		if rerr != nil { break }
		rawResp.WriteString(line)
	}
	conn2.Close()
	
	status := extractStatusLine(rawResp.Bytes())
	respBody := extractBody(rawResp.Bytes())
	t.Logf("8-header claim: status=%s body=%s", status, respBody)

	// 4) Same 8 headers but with just the __Secure-recent_mfa cookie
	t.Log("=== 8 headers + __Secure-recent_mfa cookie ===")
	conn3, _ := discordDialConn(10*time.Second)
	conn3.SetDeadline(time.Now().Add(10*time.Second))

	var mfaCookie string
	for _, part := range strings.Split(sc2, "; ") {
		if strings.HasPrefix(part, "__Secure-recent_mfa=") {
			mfaCookie = part
			break
		}
	}
	if mfaCookie == "" {
		mfaCookie = fmt.Sprintf("__Secure-recent_mfa=%s", mfaToken)
	}

	r4 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"X-Discord-MFA-Authorization: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"Cookie: %s\r\n"+
		"\r\n%s",
		target.GuildID, target.Token, sp, mfaToken, len(body), ua, mfaCookie, body)

	conn3.Write([]byte(r4))
	var rawResp3 bytes.Buffer
	br3 := bufio.NewReaderSize(conn3, 8192)
	for {
		line, rerr := br3.ReadString('\n')
		if rerr != nil { break }
		rawResp3.WriteString(line)
	}
	conn3.Close()

	status3 := extractStatusLine(rawResp3.Bytes())
	respBody3 := extractBody(rawResp3.Bytes())
	t.Logf("8-header+cookie claim: status=%s body=%s", status3, respBody3)

	// 5) Different approach: claim on the SAME connection as getTicket+solve
	// BUT with exactly the minimal 8 headers + cookie
	t.Log("=== SAME CONN: minimal headers ===")
	r5 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"X-Discord-MFA-Authorization: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"Cookie: %s\r\n"+
		"Connection: close\r\n\r\n%s",
		target.GuildID, target.Token, sp, mfaToken, len(body), ua, sc2, body)
	conn.Write([]byte(r5))
	resp5 := readResp()
	status5 := extractStatusLine(resp5)
	respBody5 := extractBody(resp5)
	t.Logf("same-conn claim: status=%s body=%s", status5, respBody5)
}
