package main

import (
	"crypto/tls"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Conn is the minimal connection interface the claim hot path, pool, and MFA
// paths depend on. Both *crypto/tls.Conn and *utls.UConn satisfy it, so the
// pool can hold warm utls connections (Chrome JA3) without callers caring
// which concrete type underlies a given conn.
type Conn interface {
	Handshake() error
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// http1ChromeSpec was a shared global — removed. The spec must be built fresh
// per connection to avoid shared mutable state in utls extension fields. See
// newChromeUConn for details.

// buildHTTP1Spec creates a fresh utls ClientHello spec from the active browser
// profile's preset with ALPN forced to http/1.1 only. Called per-connection
// (not cached) because utls ApplyPreset warns that TLSExtension fields are
// shared across connections using the same spec — concurrent handshakes would
// mutate each other's extension state (random values, session IDs, etc.).
func buildHTTP1Spec() (utls.ClientHelloSpec, error) {
	if activeProfile == nil {
		// Can't take the address of a map index expression; copy into a local
		// first, then take its address.
		chrome := browserPresets()["chrome"]
		activeProfile = &chrome
	}
	spec, err := utls.UTLSIdToSpec(activeProfile.UTLSSpecID)
	if err != nil {
		return spec, err
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
			break
		}
	}
	return spec, nil
}

// newUConn builds a utls UConn that presents the active browser profile's JA3
// fingerprint (Chrome or Firefox) but negotiates ONLY HTTP/1.1 over ALPN.
//
// Why this is necessary: we speak raw HTTP/1.1 everywhere (buildMFARequest,
// login, getTicket all write "PATCH ... HTTP/1.1" by hand). For that to work,
// Discord must negotiate http/1.1 during the TLS handshake. A real Chrome
// ClientHello advertises "h2, http/1.1" in ALPN — and since Discord supports h2,
// it negotiates h2 and then sends an HTTP/2 SETTINGS frame as its first
// response byte. Our HTTP/1.1 parser reads that binary frame as garbage
// ("status: unknown", empty body, 57 bytes of \x04 frame), and every request
// silently fails.
//
// Setting Config.NextProtos = ["http/1.1"] does NOT fix this: utls builds the
// ClientHello from the *spec*, and the spec's ALPN extension still lists h2.
// The negotiated protocol comes from the spec's advertised list intersected
// with the server's, not from Config.NextProtos. So we must edit the spec
// itself: swap the ALPN extension's protocol list to ["http/1.1"] before the
// handshake. The JA3/JA4 fingerprint is otherwise identical to the chosen
// browser's; only the ALPN value differs, which is benign (browsers legitimately
// advertise h2 fallback to http/1.1, and many network setups strip h2).
func newUConn(raw net.Conn, host string) (*utls.UConn, error) {
	// Build a fresh spec per connection. utls ApplyPreset shares extension
	// state across connections using the same ClientHelloSpec — concurrent
	// handshakes corrupt each other's random values, session IDs, etc.
	// Building per-conn avoids this entirely.
	spec, err := buildHTTP1Spec()
	if err != nil {
		// Fallback: use the active profile's preset directly. This risks h2
		// negotiation, but keeps TLS reachable instead of hard-failing.
		if activeProfile == nil {
			chrome := browserPresets()["chrome"]
			activeProfile = &chrome
		}
		return utls.UClient(raw, &utls.Config{
			ServerName: host,
			NextProtos: []string{"http/1.1"},
		}, activeProfile.UTLSSpecID), nil
	}

	conn := utls.UClient(raw, &utls.Config{
		ServerName: host,
		NextProtos: []string{"http/1.1"},
	}, utls.HelloCustom)
	if err := conn.ApplyPreset(&spec); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// discordDialTLS opens a raw TCP conn to host:443 and wraps it in a utls
// ClientHello matching the active browser profile's JA3 fingerprint while forcing
// ALPN to http/1.1 (see newUConn). Discord/Cloudflare fingerprint the TLS
// handshake (JA3/JA4) before any HTTP byte is read; Go's default crypto/tls
// stack presents a unique Go JA3 that gets challenged or flagged. Matching
// a real browser's ClientHello is what every working sniper does, so requests
// sail through unmolested.
//
// All discord.com HTTPS calls (pool, MFA solve, token validate/mint, gateway
// REST check) route through this. timeout is the TCP dial budget.
//
// Retries with exponential backoff on transient TLS handshake failures.
// Cloudflare throttles rapid new TLS sessions from the same IP — the pool
// warm-up (10 conns) + login can saturate this and cause subsequent dials
// (MFA pre-solve, REST check) to fail with "tls: internal error". Retrying
// after a short backoff lets Cloudflare's rate window slide and the handshake
// land. The claim hot path uses pooled conns, so the retry loop only runs for
// non-hot-path dials (MFA, REST, login).
func discordDialTLS(host string, timeout time.Duration) (*utls.UConn, error) {
	const maxRetries = 3
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<(attempt-1)) * 500 * time.Millisecond // 500ms, 1s, 2s
			time.Sleep(backoff)
		}

		raw, err := net.DialTimeout("tcp", host+":443", timeout)
		if err != nil {
			lastErr = err
			continue
		}

		// Tune the socket so small writes/reads don't pay Nagle/buffering tax on
		// the claim hot path. Skip for non-TCP (proxies) — those aren't *net.TCPConn.
		if tcp, ok := raw.(*net.TCPConn); ok {
			tcp.SetNoDelay(true)
			tcp.SetReadBuffer(1 << 20)
			tcp.SetWriteBuffer(1 << 20)
		}

		conn, err := newUConn(raw, host)
		if err != nil {
			raw.Close()
			lastErr = err
			continue
		}

		if err := conn.Handshake(); err != nil {
			raw.Close()
			lastErr = err
			continue
		}
		return conn, nil
	}
	return nil, lastErr
}

// utlsWrap wraps an already-connected raw conn (e.g. a CONNECT/SOCKS5 proxy
// tunnel) in the same browser-profile+http1.1 ClientHello. This is the
// proxy-tunnel counterpart to discordDialTLS, which dials directly. Keeping the
// wrap step separate lets the proxy dial code own the TCP tuning and the TLS
// layer stay identical across direct and proxied paths — the JA3 fingerprint
// Discord sees is the same either way.
func utlsWrap(raw net.Conn) (*utls.UConn, error) {
	conn, err := newUConn(raw, "discord.com")
	if err != nil {
		return nil, err
	}
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// discordDialConn returns a freshly dialed utls Conn to discord.com for the
// non-pooled call sites (login, MFA solve, REST verify). Centralizing this keeps
// the browser profile's JA3 in one place and gives every path the same socket tuning.
// Callers must Close the returned conn.
func discordDialConn(timeout time.Duration) (Conn, error) {
	return discordDialTLS("discord.com", timeout)
}

// _ is a compile-time guard that *tls.Conn and *utls.UConn both satisfy Conn.
// This is defensive: if a future refactor swaps the concrete type in pool.go,
// this assertion fails the build instead of silently breaking a method call.
var (
	_ Conn = (*tls.Conn)(nil)
	_ Conn = (*utls.UConn)(nil)
)
