package sniper

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pooledConn pairs a warm conn with the moment it BEGAN idling in the pool
// (idledAt). The idle clock is what matters for Cloudflare's silent half-close:
// after ~15s idle the server tears down its side while the local socket stays
// open, and isConnAlive can't tell (it probes a locally-open conn and sees a
// benign timeout). idledAt lets Get() and the rewarmer reject/evict conns whose
// idle age has crossed maxIdleAge BEFORE handing them to the hot path, where a
// stale conn would write into a void and read back an empty response — exactly
// the cold-start symptom the sniper hit on every first burst.
type pooledConn struct {
	conn    Conn
	idledAt time.Time
}

type ConnPool struct {
	mu    sync.Mutex
	conns []pooledConn
	proxy string
	addr  string

	// dialFn is a test seam. Production leaves it nil and uses dial(), which
	// performs the real TLS/proxy handshake. Tests inject a fake dialer so the
	// warm-up cadence (including the 200ms inter-dial sleep) can be measured
	// without opening network sockets.
	dialFn func() (Conn, error)

	// target is the desired warm pool size. The rewarmer tops the pool back up
	// to this many conns in the background so a burst that drains the pool
	// (claim conns are never recycled) doesn't force a synchronous dial on the
	// next burst's hot path. Zero means "no rewarmer" (legacy behavior).
	target    int
	rewarmMu  sync.Mutex
	rewarming bool
	stopCh    chan struct{}
	doneCh    chan struct{}
}

// aliveProbePool backs isConnAlive's 1-byte read probe so each probe doesn't
// heap-allocate a fresh slice. sync.Pool is lock-free in the uncontended case.
var aliveProbePool = sync.Pool{
	New: func() interface{} { b := make([]byte, 1); return &b },
}

func NewConnPool(proxy string, count int) (*ConnPool, error) {
	return newConnPool(proxy, count, nil)
}

// newConnPool is NewConnPool with an optional dial seam. The warm-up loop and
// its 200ms per-dial cadence are identical either way; only the dial itself is
// replaceable. Used by the arming measurement tests.
func newConnPool(proxy string, count int, dialFn func() (Conn, error)) (*ConnPool, error) {
	p := &ConnPool{
		proxy:  proxy,
		addr:   "discord.com:443",
		target: count,
		dialFn: dialFn,
	}
	for i := 0; i < count; i++ {
		conn, err := p.dial()
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("warm conn %d: %w", i, err)
		}
		p.conns = append(p.conns, pooledConn{conn: conn, idledAt: time.Now()})
		time.Sleep(200 * time.Millisecond)
	}
	return p, nil
}

// StartRewarmer launches a background goroutine that keeps the pool topped up
// to its target size. Claim connections are never recycled (dontRecycle in
// claimer.go), so without a rewarmer a burst drains the pool and the NEXT
// burst's pool.Get() falls through to a synchronous TCP+TLS dial — hundreds of
// ms of latency handed to a competitor for free. The rewarmer refills in the
// background so the next burst always finds warm conns.
//
// It dials at most one conn at a time with a short cadence to avoid
// Cloudflare's new-TLS-session rate limit (the same limit that forced the
// 200ms sleep in NewConnPool warm-up). Idempotent: a second call is a no-op.
func (p *ConnPool) StartRewarmer() {
	if p.target <= 0 {
		return
	}
	p.rewarmMu.Lock()
	if p.stopCh != nil {
		p.rewarmMu.Unlock()
		return
	}
	p.stopCh = make(chan struct{})
	p.doneCh = make(chan struct{})
	p.rewarmMu.Unlock()

	go p.rewarmer()
}

func (p *ConnPool) rewarmer() {
	defer close(p.doneCh)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.safeFillOnce()
		}
	}
}

// safeFillOnce contains a panic in the background refill loop. The rewarmer
// runs for the whole session; a panic reaching its root would end an
// unattended Actions-hosted session over a bookkeeping slip.
func (p *ConnPool) safeFillOnce() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[pool %s] recovered from panic in rewarmer: %v", proxyLabel(p.proxy), r)
		}
	}()
	p.fillOnce()
}

// fillOnce tops the pool up to target with at most one dial per tick. Dialing
// one-at-a-time (not a parallel batch) keeps us under Cloudflare's new-session
// rate window and mirrors the gentle warm-up cadence that's known to work.
//
// It ALSO evicts pooled conns whose idle age has crossed maxIdleAge. The
// rewarmer runs every 100ms, so a conn that's been sitting at the bottom of the
// pool since startup would otherwise age out silently and be handed to the next
// Get() as a dead-but-undetectable half-closed conn. Evicting it here means the
// steady-state pool is always stocked with fresh conns: every evicted slot is
// refilled by a subsequent tick's dial, so by the time a burst needs a warm conn
// one is available and still under the idle limit.
func (p *ConnPool) fillOnce() {
	p.mu.Lock()
	// Evict stale conns in place. We walk the slice once, compacting live conns
	// to the front and closing stale ones. Order doesn't matter — Get() takes
	// from the back, and freshness is uniform after a few ticks of refill.
	now := time.Now()
	live := p.conns[:0]
	for _, pc := range p.conns {
		if now.Sub(pc.idledAt) > maxIdleAge {
			pc.conn.Close()
			continue
		}
		live = append(live, pc)
	}
	p.conns = live
	need := p.target - len(p.conns)
	p.mu.Unlock()
	if need <= 0 {
		return
	}
	// Dial OUTSIDE p.mu so a slow dial doesn't block pool.Get() / Put. The new
	// conn is appended under the lock only if the pool is still under target
	// (it may have been refilled by another tick or by a Put in the meantime).
	conn, err := p.dial()
	if err != nil {
		// Transient (Cloudflare throttle / network). The next tick retries; no
		// need to log on every failure — the pool simply stays one short until
		// the dial lands. The claim path will still find warm conns if any.
		return
	}
	p.mu.Lock()
	if len(p.conns) < p.target {
		p.conns = append(p.conns, pooledConn{conn: conn, idledAt: time.Now()})
	} else {
		// Pool filled while we were dialing — close the surplus conn.
		conn.Close()
	}
	p.mu.Unlock()
}

// StopRewarmer stops the background rewarmer and waits for it to exit. Safe to
// call even if StartRewarmer was never called or already stopped.
func (p *ConnPool) StopRewarmer() {
	p.rewarmMu.Lock()
	stopCh := p.stopCh
	doneCh := p.doneCh
	p.rewarmMu.Unlock()
	if stopCh == nil {
		return
	}
	close(stopCh)
	if doneCh != nil {
		<-doneCh
	}
	p.rewarmMu.Lock()
	p.stopCh = nil
	p.doneCh = nil
	p.rewarmMu.Unlock()
}

// dial opens a TLS conn to the pool's target. Direct (no-proxy) connections
// use discordDialTLS, which presents a Chrome ClientHello (utls) so the warm
// conns in the pool have a JA3 fingerprint Discord/Cloudflare accept without
// challenge. Proxy connections tunnel CONNECT/SOCKS5 first, then wrap utls
// over the tunnel.
func (p *ConnPool) dial() (Conn, error) {
	if p.dialFn != nil {
		return p.dialFn()
	}
	if p.proxy == "" {
		// discordDialTLS returns *utls.UConn; return it as Conn.
		conn, err := discordDialTLS("discord.com", 5*time.Second)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	// Proxy path: establish the raw tunnel, tune if TCP, then wrap utls.
	raw, err := dialProxy(p.proxy, p.addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
		tcp.SetReadBuffer(1 << 20)
		tcp.SetWriteBuffer(1 << 20)
	}
	utlsConn, err := utlsWrap(raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return utlsConn, nil
}

func (p *ConnPool) Get() (Conn, error) {
	for {
		p.mu.Lock()
		if len(p.conns) > 0 {
			pc := p.conns[len(p.conns)-1]
			p.conns = p.conns[:len(p.conns)-1]
			p.mu.Unlock()

			// Age guard: if this conn has been idle in the pool longer than
			// maxIdleAge, Cloudflare has almost certainly half-closed it
			// server-side. isConnAlive can't detect a half-close (the local
			// side is open, so the probe times out → "alive"), so we reject by
			// AGE first, before the probe. This is the same failure mode the
			// sentry's held-conn guard handles, applied at the pool boundary so
			// no caller ever receives a stale conn. Drop it and try the next.
			if time.Since(pc.idledAt) > maxIdleAge {
				pc.conn.Close()
				continue
			}

			// Health check: a pooled conn may have been hard-reset (RST/EOF) by
			// the server while idle — a disjoint failure mode from the idle
			// half-close above, which the age guard already handled. Drop it and
			// dial a fresh one instead of handing out a dead conn that fails
			// the first Write and silently loses a claim.
			if isConnAlive(pc.conn) {
				return pc.conn, nil
			}
			pc.conn.Close()
			// Loop: try the next pooled conn, or dial if the pool is empty.
			continue
		}
		p.mu.Unlock()
		return p.dial()
	}
}

// maxIdleAge is the maximum time a connection may be held idle before a sentry
// must refresh it. Cloudflare silently closes (half-closes) idle TLS conns
// after ~15s: the local side stays open, so isConnAlive's past-deadline probe
// still reports "alive" (no data pending → timeout), but the next Write is
// accepted by the kernel and discarded by the server, and the read returns
// EOF with NO HTTP status — exactly the "empty response" symptom the sniper
// saw on every cold-start burst.
//
// A sentry that grabbed its warm conn at arm time and held it across pool
// warm-up (~1s) + gateway READY (~2s) + cold-start MFA solve (~12s) easily
// exceeds 15s before the first fire. Tracking conn age and refreshing past
// this threshold (10s, comfortably under the ~15s server limit) guarantees
// the held conn is always live at fire time. After the first claim, runOnce
// replaces the conn via pool.Get() on retry, so steady-state fires see a
// freshly acquired conn and skip the refresh entirely — the cost is paid only
// on the cold-start path where it's unavoidable.
const maxIdleAge = 10 * time.Second

// isConnAlive returns true if conn still appears usable.
//
// IMPORTANT: this probe CANNOT detect a server-side half-close of an idle conn
// (Cloudflare's ~15s idle timeout). A half-closed conn is still open on the
// local side, so the past-deadline Read returns "timeout" (no data pending),
// which is misread as healthy. Use this probe to catch genuinely-reset conns
// (RST / EOF), but pair it with maxIdleAge age-tracking (see sentry) for
// idle-close protection — the two failure modes are disjoint and a conn can
// pass this probe while being dead to the server.
//
// This runs on the CLAIM HOT PATH — pool.Get() calls it for every pooled conn
// before handing it out, and the burst path calls Get() once per worker. The
// previous implementation set a read deadline 50ms in the future and did a
// 1-byte Read: a healthy idle conn has no data, so Read BLOCKED THE FULL 50ms
// before returning a timeout. With N pooled conns that was up to N×50ms of
// pure sleep added to every claim — directly contradicting the <150ms latency
// target and giving competitors the window.
//
// Fix: set the deadline in the PAST. Read then returns immediately — a live
// idle conn yields a deadline-exceeded timeout (still good), a closed conn
// yields io.EOF / "connection reset" (dead). No blocking. The probe is now
// O(1) instead of O(50ms).
func isConnAlive(conn Conn) bool {
	// Past deadline: any pending or next Read returns immediately.
	conn.SetReadDeadline(time.Now().Add(-time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})

	// Borrow a 1-byte probe from the pool instead of heap-allocating per call.
	// isConnAlive runs on the claim hot path (pool.Get probes every pooled conn
	// it hands out), so even a tiny per-call allocation adds up under a burst.
	bufp := aliveProbePool.Get().(*[]byte)
	n, err := conn.Read(*bufp)
	aliveProbePool.Put(bufp)
	if n > 0 {
		// Unexpected data on an idle conn — treat as unhealthy.
		return false
	}
	if err == nil {
		return true
	}
	// A timeout means the conn is still open and waiting for data (healthy).
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}

// PutSafe returns conn to the pool only if it's still alive. Use this when the
// last request used "Connection: close" (so the server may have closed it) or
// when an error occurred mid-request. Returns true if the conn was recycled.
// idledAt is stamped now so the age guard in Get()/fillOnce() measures idle time
// from the moment the conn re-entered the pool, not from when it was first
// dialed.
func (p *ConnPool) PutSafe(conn Conn) bool {
	if !isConnAlive(conn) {
		conn.Close()
		return false
	}
	p.mu.Lock()
	p.conns = append(p.conns, pooledConn{conn: conn, idledAt: time.Now()})
	p.mu.Unlock()
	return true
}

func (p *ConnPool) Put(conn Conn) {
	p.mu.Lock()
	p.conns = append(p.conns, pooledConn{conn: conn, idledAt: time.Now()})
	p.mu.Unlock()
}

func (p *ConnPool) Close() {
	p.mu.Lock()
	for _, pc := range p.conns {
		pc.conn.Close()
	}
	p.conns = nil
	p.mu.Unlock()
}

func dialProxy(proxyURL, target string) (net.Conn, error) {
	if proxyURL == "" {
		return net.DialTimeout("tcp", target, 5*time.Second)
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	proxyAddr := u.Host
	if u.Port() == "" {
		proxyAddr = u.Host + ":1080"
	}

	switch u.Scheme {
	case "http", "https":
		return dialHTTPProxy(proxyAddr, target, u)
	case "socks5":
		return dialSOCKS5(proxyAddr, target)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}
}

func dialHTTPProxy(proxyAddr, target string, u *url.URL) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if u.User != nil {
		pass, _ := u.User.Password()
		auth := basicAuth(u.User.Username(), pass)
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	// Read through the end of the response headers one byte at a time. The
	// response may arrive in arbitrary fragments, and reading past the blank
	// line would consume bytes from the tunneled TLS stream.
	const maxHeaderBytes = 8 << 10
	headers := make([]byte, 0, 256)
	var one [1]byte
	for {
		if len(headers) >= maxHeaderBytes {
			conn.Close()
			return nil, fmt.Errorf("http proxy: response headers exceed %d bytes", maxHeaderBytes)
		}
		n, readErr := conn.Read(one[:])
		if n > 0 {
			headers = append(headers, one[0])
			if bytes.HasSuffix(headers, []byte("\r\n\r\n")) {
				break
			}
		}
		if readErr != nil {
			conn.Close()
			if readErr == io.EOF {
				return nil, fmt.Errorf("http proxy: truncated response headers")
			}
			return nil, fmt.Errorf("http proxy: read response headers: %w", readErr)
		}
	}

	lineEnd := bytes.IndexByte(headers, '\n')
	if lineEnd < 0 {
		conn.Close()
		return nil, fmt.Errorf("http proxy: malformed response: missing status line")
	}
	statusLine := strings.TrimSuffix(string(headers[:lineEnd]), "\r")
	fields := strings.Fields(statusLine)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		conn.Close()
		return nil, fmt.Errorf("http proxy: malformed status line %q", statusLine)
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil || status < 100 || status > 999 {
		conn.Close()
		return nil, fmt.Errorf("http proxy: malformed status line %q", statusLine)
	}
	if status == 407 {
		conn.Close()
		return nil, fmt.Errorf("http proxy: authentication required (407)")
	}
	if status < 200 || status > 299 {
		conn.Close()
		return nil, fmt.Errorf("http proxy: CONNECT failed: %s", statusLine)
	}

	return conn, nil
}

func dialSOCKS5(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting write: %w", err)
	}

	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting reply: %w", err)
	}
	if greeting[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5: unsupported protocol version 0x%02x", greeting[0])
	}
	switch greeting[1] {
	case 0x00:
		// No authentication required.
	case 0xff:
		conn.Close()
		return nil, fmt.Errorf("socks5: proxy requires authentication (no acceptable auth method)")
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: proxy selected unsupported auth method 0x%02x", greeting[1])
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}

	ip := net.ParseIP(host)
	var atyp byte = 0x03
	var addrBytes []byte
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp = 0x01
			addrBytes = ip4
		} else {
			atyp = 0x04
			addrBytes = ip.To16()
		}
	} else {
		addrBytes = []byte(host)
	}

	p := []byte{0x05, 0x01, 0x00, atyp}
	if atyp == 0x03 {
		p = append(p, byte(len(addrBytes)))
	}
	p = append(p, addrBytes...)

	pn, _ := strconv.Atoi(port)
	p = append(p, byte(pn>>8), byte(pn))
	if _, err := conn.Write(p); err != nil {
		conn.Close()
		return nil, err
	}

	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect reply: %w", err)
	}
	if reply[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect reply: unsupported protocol version 0x%02x", reply[0])
	}
	if reply[1] != 0x00 {
		conn.Close()
		return nil, socks5ReplyError(reply[1])
	}

	// The success reply carries BND.ADDR and BND.PORT after the fixed header.
	// Consume them completely: returning the conn with reply bytes still queued
	// would make the next reader (the TLS ClientHello/ServerHello path) interpret
	// proxy bytes as TLS records and fail the handshake.
	if err := readSOCKS5BoundAddr(conn, reply[3]); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// readSOCKS5BoundAddr consumes the variable-length BND.ADDR/BND.PORT tail of a
// SOCKS5 CONNECT reply. ATYP 0x01 is IPv4, 0x04 is IPv6, and 0x03 is a
// length-prefixed domain name. Any short read means the reply was truncated.
func readSOCKS5BoundAddr(r io.Reader, atyp byte) error {
	var addrLen int
	switch atyp {
	case 0x01:
		addrLen = net.IPv4len
	case 0x04:
		addrLen = net.IPv6len
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return fmt.Errorf("socks5: truncated bound-address length: %w", err)
		}
		addrLen = int(l[0])
	default:
		return fmt.Errorf("socks5: unsupported bound-address type 0x%02x", atyp)
	}

	if addrLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(addrLen)); err != nil {
			return fmt.Errorf("socks5: truncated bound address: %w", err)
		}
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return fmt.Errorf("socks5: truncated bound port: %w", err)
	}
	return nil
}

// socks5ReplyError maps the common REP failure codes to actionable messages.
// A zero status is success and is handled by the caller before this runs.
func socks5ReplyError(code byte) error {
	reason := "unknown failure"
	switch code {
	case 0x01:
		reason = "general SOCKS server failure"
	case 0x02:
		reason = "connection not allowed by ruleset"
	case 0x03:
		reason = "network unreachable"
	case 0x04:
		reason = "host unreachable"
	case 0x05:
		reason = "connection refused"
	}
	return fmt.Errorf("socks5 connect failed: %s (status 0x%02x)", reason, code)
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	buf := make([]byte, (len(auth)*4+2)/3)
	enc := encodeBase64(buf, []byte(auth))
	return string(buf[:enc])
}

const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func encodeBase64(dst, src []byte) int {
	i, j := 0, 0
	for i < len(src) {
		var val int
		if i+2 < len(src) {
			val = int(src[i])<<16 | int(src[i+1])<<8 | int(src[i+2])
		} else if i+1 < len(src) {
			val = int(src[i])<<16 | int(src[i+1])<<8
		} else {
			val = int(src[i]) << 16
		}

		dst[j] = base64Chars[(val>>18)&0x3F]
		dst[j+1] = base64Chars[(val>>12)&0x3F]
		if i+1 < len(src) {
			dst[j+2] = base64Chars[(val>>6)&0x3F]
		} else {
			dst[j+2] = '='
		}
		if i+2 < len(src) {
			dst[j+3] = base64Chars[val&0x3F]
		} else {
			dst[j+3] = '='
		}
		i += 3
		j += 4
	}
	return j
}
