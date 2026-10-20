package sniper

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeProxyServer accepts exactly one connection and runs handle on it. A real
// loopback listener lets the production dialer exercise partial and truncated
// replies over TCP.
type fakeProxyServer struct {
	addr      string
	done      chan struct{}
	handleErr error
}

func startFakeProxy(t *testing.T, handle func(net.Conn) error) *fakeProxyServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	s := &fakeProxyServer{addr: ln.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		conn, err := ln.Accept()
		if err != nil {
			s.handleErr = err
			return
		}
		defer conn.Close()
		s.handleErr = handle(conn)
	}()
	return s
}

func (s *fakeProxyServer) wait(t *testing.T) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Fatal("fake SOCKS5 server did not finish")
	}
	if s.handleErr != nil {
		t.Errorf("fake SOCKS5 handler: %v", s.handleErr)
	}
}

func readSOCKS5Greeting(conn net.Conn) error {
	var got [3]byte
	if _, err := io.ReadFull(conn, got[:]); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if got != [3]byte{0x05, 0x01, 0x00} {
		return fmt.Errorf("greeting = % x, want 05 01 00", got)
	}
	return nil
}

// readSOCKS5ConnectTarget consumes a domain-name CONNECT request and returns
// host:port. The dialer always targets discord.com, so other address types are
// not needed by these tests.
func readSOCKS5ConnectTarget(conn net.Conn) (string, error) {
	var h [4]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return "", fmt.Errorf("read connect header: %w", err)
	}
	if h != [4]byte{0x05, 0x01, 0x00, 0x03} {
		return "", fmt.Errorf("connect header = % x, want 05 01 00 03", h)
	}
	var l [1]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return "", err
	}
	name := make([]byte, int(l[0]))
	if _, err := io.ReadFull(conn, name); err != nil {
		return "", err
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", name, int(port[0])<<8|int(port[1])), nil
}

func TestDialSOCKS5SuccessConsumesFullReply(t *testing.T) {
	targetCh := make(chan string, 1)
	srv := startFakeProxy(t, func(conn net.Conn) error {
		if err := readSOCKS5Greeting(conn); err != nil {
			return err
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return err
		}
		target, err := readSOCKS5ConnectTarget(conn)
		if err != nil {
			return err
		}
		targetCh <- target

		// Domain-form BND.ADDR plus a nonzero BND.PORT: both must be consumed
		// before the caller sees the conn.
		reply := append([]byte{0x05, 0x00, 0x00, 0x03, byte(len("proxy.local"))}, "proxy.local"...)
		reply = append(reply, 0x1f, 0x90)
		if _, err := conn.Write(reply); err != nil {
			return err
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

	conn, err := dialProxy("socks5://"+srv.addr, "discord.com:443")
	if err != nil {
		t.Fatalf("dialProxy: %v", err)
	}
	defer conn.Close()

	if targetSeen := <-targetCh; targetSeen != "discord.com:443" {
		t.Fatalf("proxy saw target %q, want discord.com:443", targetSeen)
	}

	// Unconsumed reply bytes would be read here instead of the server's pong.
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	var pong [4]byte
	if _, err := io.ReadFull(conn, pong[:]); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if string(pong[:]) != "pong" {
		t.Fatalf("read %q, want pong (proxy reply not fully consumed)", pong)
	}
	srv.wait(t)
}

func TestDialSOCKS5ErrorRepliesAreClear(t *testing.T) {
	tests := []struct {
		name    string
		handle  func(net.Conn) error
		wantErr []string
	}{
		{
			name: "refusal",
			handle: func(conn net.Conn) error {
				if err := readSOCKS5Greeting(conn); err != nil {
					return err
				}
				if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
					return err
				}
				if _, err := readSOCKS5ConnectTarget(conn); err != nil {
					return err
				}
				_, err := conn.Write([]byte{0x05, 0x05, 0x00, 0x01})
				return err
			},
			wantErr: []string{"connection refused", "status 0x05"},
		},
		{
			name: "auth-required",
			handle: func(conn net.Conn) error {
				if err := readSOCKS5Greeting(conn); err != nil {
					return err
				}
				// 0xff: no acceptable methods, i.e. auth is required.
				_, err := conn.Write([]byte{0x05, 0xff})
				return err
			},
			wantErr: []string{"requires authentication"},
		},
		{
			name: "truncated",
			handle: func(conn net.Conn) error {
				if err := readSOCKS5Greeting(conn); err != nil {
					return err
				}
				if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
					return err
				}
				if _, err := readSOCKS5ConnectTarget(conn); err != nil {
					return err
				}
				// Header promises an 11-byte domain, then sends only 5 bytes.
				_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x03, 0x0b, 'p', 'r', 'o', 'x', 'y'})
				return err
			},
			wantErr: []string{"truncated"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeProxy(t, tc.handle)
			conn, err := dialProxy("socks5://"+srv.addr, "discord.com:443")
			if conn != nil {
				conn.Close()
				t.Fatal("dialProxy returned a conn for a failed reply")
			}
			if err == nil {
				t.Fatal("dialProxy returned nil error for a failed reply")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			srv.wait(t)
		})
	}
}
