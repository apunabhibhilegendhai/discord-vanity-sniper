//go:build realnet

package sniper

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sort"
	"testing"
	"time"
)

// The realnet harness is deliberately not part of the default suite. It makes
// unauthenticated TCP/TLS/HTTP requests to discord.com, so it needs a network
// connection but no token or config.json. Run it with:
//
//	go test -tags=realnet -count=1 -run TestRealMeasurement -v .
//
// It measures the same network floor quoted in PRD.md and the research report
// (TCP connect, TLS total, warm gateway TTFB) and reruns the local free→wire
// measurements with their hard thresholds.
const (
	realNetSamples = 10
	realNetDial    = 10 * time.Second
	realNetRead    = 15 * time.Second
)

func TestRealMeasurement(t *testing.T) {
	t.Run("network floor", func(t *testing.T) {
		measureRealNetworkFloor(t)
	})

	t.Run("local free→wire", func(t *testing.T) {
		reportHotPath(t, "signal-handler→wire", measureFreeToWire(t, 300, 1))
		reportHotPath(t, "burst5-first-wire", measureFreeToWire(t, 200, 5))
		reportHotPath(t, "channel-send→wire", measureSignalToWire(t, 300))
	})
}

func measureRealNetworkFloor(t *testing.T) {
	t.Helper()

	tcp := make([]time.Duration, 0, realNetSamples)
	for i := 0; i < realNetSamples; i++ {
		started := time.Now()
		conn, err := net.DialTimeout("tcp", "discord.com:443", realNetDial)
		if err != nil {
			t.Fatalf("TCP dial %d/%d: %v", i+1, realNetSamples, err)
		}
		tcp = append(tcp, time.Since(started))
		conn.Close()
	}

	tlsSamples := make([]time.Duration, 0, realNetSamples)
	for i := 0; i < realNetSamples; i++ {
		raw, err := net.DialTimeout("tcp", "discord.com:443", realNetDial)
		if err != nil {
			t.Fatalf("TLS dial %d/%d: %v", i+1, realNetSamples, err)
		}
		raw.SetDeadline(time.Now().Add(realNetRead))

		started := time.Now()
		conn, err := newUConn(raw, "discord.com")
		if err != nil {
			raw.Close()
			t.Fatalf("TLS wrap %d/%d: %v", i+1, realNetSamples, err)
		}
		if err := conn.Handshake(); err != nil {
			conn.Close()
			t.Fatalf("TLS handshake %d/%d: %v", i+1, realNetSamples, err)
		}
		tlsSamples = append(tlsSamples, time.Since(started))
		conn.Close()
	}

	conn, err := realWarmTLSConn()
	if err != nil {
		t.Fatalf("warm TLS connection: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	ttfb := make([]time.Duration, 0, realNetSamples)
	request := []byte("GET /api/v9/gateway HTTP/1.1\r\nHost: discord.com\r\nConnection: keep-alive\r\n\r\n")
	for i := 0; i < realNetSamples; i++ {
		conn.SetDeadline(time.Now().Add(realNetRead))
		started := time.Now()
		if _, err := conn.Write(request); err != nil {
			t.Fatalf("gateway write %d/%d: %v", i+1, realNetSamples, err)
		}
		if _, err := br.Peek(1); err != nil {
			t.Fatalf("gateway first byte %d/%d: %v", i+1, realNetSamples, err)
		}
		elapsed := time.Since(started)

		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("gateway read %d/%d: %v", i+1, realNetSamples, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("gateway status %d/%d: %s", i+1, realNetSamples, resp.Status)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			resp.Body.Close()
			t.Fatalf("gateway body %d/%d: %v", i+1, realNetSamples, err)
		}
		resp.Body.Close()
		if resp.Close {
			t.Fatalf("gateway closed the keep-alive connection after sample %d/%d", i+1, realNetSamples)
		}
		ttfb = append(ttfb, elapsed)
	}

	logRealSamples(t, "TCP connect", tcp)
	logRealSamples(t, "TLS total (TCP+handshake)", tlsSamples)
	logRealSamples(t, "warm gateway TTFB", ttfb)
}

func realWarmTLSConn() (Conn, error) {
	raw, err := net.DialTimeout("tcp", "discord.com:443", realNetDial)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(realNetRead))
	conn, err := newUConn(raw, "discord.com")
	if err != nil {
		raw.Close()
		return nil, err
	}
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func logRealSamples(t *testing.T, name string, ds []time.Duration) {
	t.Helper()
	if len(ds) == 0 {
		t.Fatalf("%s produced no samples", name)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	pick := func(q float64) time.Duration {
		return ds[int(q*float64(len(ds)-1))]
	}
	t.Logf("%s n=%d p50=%v p95=%v min=%v max=%v",
		name, len(ds), pick(.50), pick(.95), ds[0], ds[len(ds)-1])
}
