//go:build live

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestVerifyPassword(t *testing.T) {
	cfg, err := LoadConfig("config.json")
	if err != nil { t.Fatalf("%v", err) }

	// Try login with email+password to verify password is correct
	conn, _ := discordDialConn(10*time.Second)
	conn.SetDeadline(time.Now().Add(20*time.Second))
	br := bufio.NewReaderSize(conn, 16384)

	readResp := func() []byte {
		var buf bytes.Buffer
		var cl int64 = -1
		chunked := false
		for {
			line, rerr := br.ReadString('\n'); if rerr != nil { break }
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

	loginBody := fmt.Sprintf(`{"login":"%s","password":"%s"}`, cfg.Email, cfg.Password)
	r := fmt.Sprintf("POST /api/v9/auth/login HTTP/1.1\r\nHost: discord.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\nUser-Agent: %s\r\nX-Super-Properties: %s\r\nConnection: close\r\n\r\n%s",
		len(loginBody), cfg.Fingerprint.UserAgent, cfg.Fingerprint.SuperPropsB64, loginBody)
	conn.Write([]byte(r))
	resp := readResp()

	status := extractStatusLine(resp)
	body := extractBody(resp)
	t.Logf("LOGIN: status=%s", status)
	t.Logf("LOGIN: body=%s", body)

	if strings.Contains(body, `"token"`) {
		t.Logf("=> PASSWORD IS CORRECT! Login returned a token")
	} else if strings.Contains(body, `"mfa"`) {
		t.Logf("=> PASSWORD IS CORRECT! MFA required to complete login")
	} else if strings.Contains(body, `60008`) {
		t.Logf("=> PASSWORD IS WRONG (60008)")
	} else {
		t.Logf("=> Unknown response, check above")
	}

	// Also try password validation endpoint
	validateBody := fmt.Sprintf(`{"password":"%s"}`, cfg.Password)
	conn2, _ := discordDialConn(10*time.Second)
	conn2.SetDeadline(time.Now().Add(10*time.Second))
	br2 := bufio.NewReaderSize(conn2, 16384)

	readResp2 := func() []byte {
		var buf bytes.Buffer
		var cl int64 = -1
		chunked := false
		for {
			line, rerr := br2.ReadString('\n'); if rerr != nil { break }
			buf.WriteString(line)
			l := strings.TrimSuffix(line, "\r\n")
			if l == "" { break }
			lo := strings.ToLower(l)
			if strings.HasPrefix(lo, "content-length:") { fmt.Sscanf(l, "Content-Length: %d", &cl) }
			if strings.HasPrefix(lo, "transfer-encoding:") && strings.Contains(lo, "chunked") { chunked = true }
		}
		if chunked {
			for {
				line, _ := br2.ReadString('\n')
				line = strings.TrimSuffix(line, "\r\n")
				var cs int64; fmt.Sscanf(line, "%x", &cs)
				if cs == 0 { br2.ReadString('\n'); break }
				chunk := make([]byte, cs+2); io.ReadFull(br2, chunk)
				buf.Write(chunk[:cs])
			}
		} else if cl >= 0 {
			chunk := make([]byte, cl); io.ReadFull(br2, chunk)
			buf.Write(chunk)
		}
		return buf.Bytes()
	}

	r2 := fmt.Sprintf("POST /api/v9/auth/password/validate HTTP/1.1\r\nHost: discord.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\nUser-Agent: %s\r\nX-Super-Properties: %s\r\nConnection: close\r\n\r\n%s",
		len(validateBody), cfg.Fingerprint.UserAgent, cfg.Fingerprint.SuperPropsB64, validateBody)
	conn2.Write([]byte(r2))
	resp2 := readResp2()
	t.Logf("PASSWORD VALIDATE: status=%s body=%s", extractStatusLine(resp2), extractBody(resp2))
}
