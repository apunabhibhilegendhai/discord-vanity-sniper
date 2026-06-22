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

func TestBackupAndMFACode(t *testing.T) {
	cfg, err := LoadConfig("config.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	target := &cfg.Targets[0]

	body := fmt.Sprintf(`{"code":"%s"}`, target.Vanity)

	// First, get a ticket
	conn, err := discordDialConn(20 * time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	br := bufio.NewReaderSize(conn, 16384)

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
				if err != nil { break }
				line = strings.TrimSuffix(line, "\r\n")
				var chunkSize int64
				fmt.Sscanf(line, "%x", &chunkSize)
				if chunkSize == 0 {
					br.ReadString('\n')
					break
				}
				chunk := make([]byte, chunkSize+2)
				io.ReadFull(br, chunk)
				buf.Write(chunk[:chunkSize])
			}
		} else if contentLength >= 0 {
			chunk := make([]byte, contentLength)
			io.ReadFull(br, chunk)
			buf.Write(chunk)
		}
		return buf.Bytes()
	}

	req1 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"\r\n%s",
		target.GuildID, target.Token, cfg.Fingerprint.SuperPropsB64,
		len(body), cfg.Fingerprint.UserAgent, body)

	conn.Write([]byte(req1))
	resp1 := readResponse()
	ticket, _ := extractTicket(resp1)
	setCookies1 := extractSetCookies(resp1)
	t.Logf("getTicket: ticket=%s", ticket)
	t.Logf("getTicket: set-cookie=%s", setCookies1)

	if ticket == "" {
		t.Fatal("no ticket")
	}

	// === A) Solve with BACKUP code ===
	backupCode := cfg.BackupCodes[0]
	t.Logf("=== Trying backup code: %s ===", backupCode)
	
	solvePayload := fmt.Sprintf(`{"ticket":"%s","mfa_type":"backup","data":"%s"}`, ticket, backupCode)
	req2 := fmt.Sprintf("POST /api/v9/mfa/finish HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"Cookie: __dcfduid=%s; __sdcfduid=%s; %s\r\n"+
		"Connection: keep-alive\r\n"+
		"\r\n%s",
		target.Token, len(solvePayload), cfg.Fingerprint.UserAgent,
		cfg.Fingerprint.SuperPropsB64, cfg.Fingerprint.DcfDuid, cfg.Fingerprint.SdcfDuid,
		setCookies1, solvePayload)

	conn.Write([]byte(req2))
	resp2 := readResponse()
	t2 := extractStatusLine(resp2)
	b2 := extractBody(resp2)
	t.Logf("backup solve: status=%s body=%s", t2, b2)

	if strings.Contains(t2, "200") {
		mfaToken, _, _ := parseFinishResponse(resp2)
		jwtParts := strings.Split(mfaToken, ".")
		if len(jwtParts) == 3 {
			pad := (4 - len(jwtParts[1])%4) % 4
			padded := jwtParts[1] + strings.Repeat("=", pad)
			decoded, _ := base64.URLEncoding.DecodeString(padded)
			t.Logf("backup JWT payload=%s", string(decoded))
		}

		// Try claim with backup MFA token
		solveCookies := extractSetCookies(resp2)
		mergedCookies := mergeCookieStrings(
			fmt.Sprintf("__dcfduid=%s; __sdcfduid=%s", cfg.Fingerprint.DcfDuid, cfg.Fingerprint.SdcfDuid),
			solveCookies,
		)
		req3 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
			"Host: discord.com\r\n"+
			"Authorization: %s\r\n"+
			"X-Super-Properties: %s\r\n"+
			"X-Discord-MFA-Authorization: %s\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: %d\r\n"+
			"User-Agent: %s\r\n"+
			"Cookie: %s\r\n"+
			"Connection: close\r\n\r\n%s",
			target.GuildID, target.Token, cfg.Fingerprint.SuperPropsB64,
			mfaToken, len(body), cfg.Fingerprint.UserAgent,
			mergedCookies, body)
			
		conn2, _ := discordDialConn(10*time.Second)
		conn2.Write([]byte(req3))
		conn2.SetDeadline(time.Now().Add(10*time.Second))
		br2 := bufio.NewReaderSize(conn2, 4096)
		var resp3 []byte
		resp3b := new(bytes.Buffer)
		for {
			line, rerr := br2.ReadString('\n')
			if rerr != nil { break }
			resp3b.WriteString(line)
		}
		resp3 = resp3b.Bytes()
		conn2.Close()
		t.Logf("backup claim: status=%s body=%s", extractStatusLine(resp3), extractBody(resp3))
	}

	// === B) Try mfa_code in PATCH body ===
	t.Log("=== Trying mfa_code in body ===")
	code, _ := totp.GenerateCode(cfg.TOTPSecret, time.Now())
	
	bodyWithMFA := fmt.Sprintf(`{"code":"%s","mfa_code":"%s"}`, target.Vanity, code)
	conn3, _ := discordDialConn(10*time.Second)
	conn3.SetDeadline(time.Now().Add(10*time.Second))
	req4 := fmt.Sprintf("PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
		"Host: discord.com\r\n"+
		"Authorization: %s\r\n"+
		"X-Super-Properties: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: %s\r\n"+
		"Cookie: __dcfduid=%s; __sdcfduid=%s\r\n"+
		"Connection: close\r\n\r\n%s",
		target.GuildID, target.Token, cfg.Fingerprint.SuperPropsB64,
		len(bodyWithMFA), cfg.Fingerprint.UserAgent,
		cfg.Fingerprint.DcfDuid, cfg.Fingerprint.SdcfDuid, bodyWithMFA)
	conn3.Write([]byte(req4))
	br3 := bufio.NewReaderSize(conn3, 4096)
	var resp4 bytes.Buffer
	for {
		line, rerr := br3.ReadString('\n')
		if rerr != nil { break }
		resp4.WriteString(line)
	}
	conn3.Close()
	t.Logf("mfa_code claim: status=%s body=%s", extractStatusLine(resp4.Bytes()), extractBody(resp4.Bytes()))
}
