package sniper

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDialHTTPProxyResponses(t *testing.T) {
	tests := []struct {
		name      string
		fragments []string
		wantErr   []string
	}{
		{
			name: "fragmented-success",
			fragments: []string{
				"HTTP/1.1 200 Connection established\r\n",
				"Proxy-Agent: test\r\n\r\n",
			},
		},
		{
			name:      "auth-required",
			fragments: []string{"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"},
			wantErr:   []string{"authentication required", "407"},
		},
		{
			name:      "forbidden",
			fragments: []string{"HTTP/1.1 403 Forbidden\r\n\r\n"},
			wantErr:   []string{"CONNECT failed", "403"},
		},
		{
			name:      "malformed",
			fragments: []string{"NOT HTTP\r\n\r\n"},
			wantErr:   []string{"malformed status line"},
		},
		{
			name:      "truncated",
			fragments: []string{"HTTP/1.1 200 OK\r\n"},
			wantErr:   []string{"truncated"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeProxy(t, func(conn net.Conn) error {
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return fmt.Errorf("read CONNECT request: %w", err)
				}
				req.Body.Close()
				if req.Method != http.MethodConnect {
					return fmt.Errorf("method = %s, want CONNECT", req.Method)
				}

				for i, fragment := range tc.fragments {
					if _, err := conn.Write([]byte(fragment)); err != nil {
						return err
					}
					// Keep the fragments in separate reads so a single conn.Read
					// cannot accidentally receive the whole header block.
					if i < len(tc.fragments)-1 {
						time.Sleep(20 * time.Millisecond)
					}
				}
				if len(tc.wantErr) > 0 {
					return nil
				}

				var ping [4]byte
				if _, err := io.ReadFull(conn, ping[:]); err != nil {
					return fmt.Errorf("read ping: %w", err)
				}
				if string(ping[:]) != "ping" {
					return fmt.Errorf("read %q, want ping", ping)
				}
				_, err = conn.Write([]byte("pong"))
				return err
			})

			conn, err := dialProxy("http://"+srv.addr, "discord.com:443")
			if len(tc.wantErr) > 0 {
				if conn != nil {
					conn.Close()
					t.Fatal("dialProxy returned a conn for a failed CONNECT")
				}
				if err == nil {
					t.Fatal("dialProxy returned nil error for a failed CONNECT")
				}
				for _, want := range tc.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err, want)
					}
				}
				srv.wait(t)
				return
			}

			if err != nil {
				t.Fatalf("dialProxy: %v", err)
			}
			defer conn.Close()

			// Any unread proxy header bytes would be read here instead of pong.
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("write ping: %v", err)
			}
			var pong [4]byte
			if _, err := io.ReadFull(conn, pong[:]); err != nil {
				t.Fatalf("read pong: %v", err)
			}
			if string(pong[:]) != "pong" {
				t.Fatalf("read %q, want pong (proxy header not fully consumed)", pong)
			}
			srv.wait(t)
		})
	}
}
