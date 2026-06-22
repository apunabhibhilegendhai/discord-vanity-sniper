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

func TestSingleConnFlow(t *testing.T) {
	cfg, err := LoadConfig("config.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	target := &cfg.Targets[0]

	body := fmt.Sprintf(`{"code":"%s"}`, target.Vanity)

	conn, err := discordDialConn(30 * time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	br := bufio.NewReaderSize(conn, 16384)

	// readResponse reads one complete HTTP/1.1 response from bufio.Reader
	readResponse := func() []byte {
		var buf bytes.Buffer

		var contentLength int64 = -1
		chunked := false
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			buf.WriteString(line)
			line = strings.TrimSuffix(line, "\r\n")
			if line == "" {
				break
			}
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "content-length:") {
				fmt.Sscanf(line, "Content-Length: %d", &contentLength)
			}
			if strings.HasPrefix(lower, "transfer-encoding:") && strings.Contains(lower, "chunked") {
				chunked = true
			}
		}

		if chunked {
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					break
				}
				line = strings.TrimSuffix(line, "\r\n")
				var chunkSize int64
				fmt.Sscanf(line, "%x", &chunkSize)
				if chunkSize == 0 {
					br.ReadString('\n')
					break
				}
				chunk := make([]byte, chunkSize+2)
				_, err = io.ReadFull(br, chunk)
				if err != nil {
					break
				}
				buf.Write(chunk[:chunkSize])
			}
		} else if contentLength >= 0 {
			chunk := make([]byte, contentLength)
			_, err = io.ReadFull(br, chunk)
			if err == nil {
				buf.Write(chunk)
			}
		}

		return buf.Bytes()
	}

	// 1) getTicket
	t.Log("=== STEP 1: getTicket ===")
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	req1 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"\r\n"+
		"%s",
		target.GuildID, target.Token, cfg.Fingerprint.SuperPropsB64,
		len(body), cfg.Fingerprint.UserAgent, body)

	_, err = conn.Write([]byte(req1))
	if err != nil {
		t.Fatalf("write req1: %v", err)
	}
	resp1 := readResponse()
	t.Logf("getTicket: status=%s body=%s", extractStatusLine(resp1), extractBody(resp1))
	setCookies1 := extractSetCookies(resp1)
	t.Logf("getTicket: Set-Cookie: %s", setCookies1)

	ticket, err := extractTicket(resp1)
	if err != nil || ticket == "" {
		t.Fatalf("no ticket: %v", err)
	}
	t.Logf("getTicket: ticket=%s", ticket)

	// 2) Solve TOTP
	code, err := totp.GenerateCode(cfg.TOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("totp: %v", err)
	}
	t.Logf("=== STEP 2: solve TOTP (code=%s) ===", code)

	solvePayload := fmt.Sprintf(`{"ticket":"%s","mfa_type":"totp","data":"%s"}`, ticket, code)
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	req2 := fmt.Sprintf("POST /api/v9/mfa/finish HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"Cookie: __dcfduid=%s; __sdcfduid=%s; %s\r\n"+
		"Connection: keep-alive\r\n"+
		"\r\n"+
		"%s",
		target.Token, len(solvePayload), cfg.Fingerprint.UserAgent,
		cfg.Fingerprint.SuperPropsB64, cfg.Fingerprint.DcfDuid, cfg.Fingerprint.SdcfDuid,
		setCookies1, solvePayload)

	_, err = conn.Write([]byte(req2))
	if err != nil {
		t.Fatalf("write req2: %v", err)
	}
	resp2 := readResponse()
	t.Logf("solve: status=%s body=%s", extractStatusLine(resp2), extractBody(resp2))
	solveCookies := extractSetCookies(resp2)
	t.Logf("solve: Set-Cookie: %s", solveCookies)

	mfaToken, _, err := parseFinishResponse(resp2)
	if err != nil || mfaToken == "" {
		t.Fatalf("no MFA token: %v", err)
	}

	// Decode JWT payload
	jwtParts := strings.Split(mfaToken, ".")
	if len(jwtParts) == 3 {
		pad := (4 - len(jwtParts[1])%4) % 4
		padded := jwtParts[1] + strings.Repeat("=", pad)
		decoded, _ := base64.URLEncoding.DecodeString(padded)
		t.Logf("solve: JWT payload=%s", string(decoded))
	}

	// 3) Claim on same connection
	t.Log("=== STEP 3: claim ===")
	mergedCookies := mergeCookieStrings(
		fmt.Sprintf("__dcfduid=%s; __sdcfduid=%s", cfg.Fingerprint.DcfDuid, cfg.Fingerprint.SdcfDuid),
		solveCookies,
	)
	t.Logf("claim cookies: %s", mergedCookies)

	conn.SetDeadline(time.Now().Add(20 * time.Second))
	req3 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"X-Discord-MFA-Authorization: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"Cookie: %s\r\n"+
		"Connection: close\r\n"+
		"\r\n"+
		"%s",
		target.GuildID, target.Token, cfg.Fingerprint.SuperPropsB64,
		mfaToken, len(body), cfg.Fingerprint.UserAgent,
		mergedCookies, body)

	_, err = conn.Write([]byte(req3))
	if err != nil {
		t.Fatalf("write req3: %v", err)
	}
	resp3 := readResponse()
	t.Logf("claim: status=%s body=%s", extractStatusLine(resp3), extractBody(resp3))

	b3 := extractBody(resp3)
	if strings.Contains(b3, "10008") {
		t.Log("=> 403/10008 (still blocked)")
	} else if strings.Contains(b3, "60003") {
		t.Log("=> 401/60003 (MFA not accepted)")
	} else {
		t.Log("=> POSSIBLE SUCCESS! Check above")
	}
}
