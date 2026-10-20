package sniper

import (
	"bytes"
	"sort"
	"strings"
	"testing"
	"time"
)

// pollerCadenceSlack is the hard pass/fail allowance over one simulated RTT.
// Five reference runs with a 20ms socket read produced medians of 20.35–20.43ms;
// the old post-response 5ms sleep produced ~25ms. Three milliseconds catches
// that regression with ~2.5ms of measured headroom.
const pollerCadenceSlack = 3 * time.Millisecond

func TestBuildClaimMFARendersCorrectHeaders(t *testing.T) {
	target := &Target{
		GuildID: "123456789",
		Vanity:  "testvanity",
		Token:   "FAKE_TOKEN",
	}
	cfg := &Conf{
		Fingerprint: Fingerprint{
			DcfDuid:       "dcf-123",
			SdcfDuid:      "sdcf-456",
			SuperPropsB64: "SPB64",
			UserAgent:     "TestUA/1.0",
		},
	}

	tpl := BuildClaimRequest(target, cfg)
	if tpl == nil {
		t.Fatal("BuildClaimRequest returned nil")
	}

	token := "MFA.JWT.TOKEN"
	out := tpl.BuildClaimMFA(token)

	s := string(out)
	t.Logf("=== Rendered request ===\n%s", s)

	// Must have the proper MFA header line (full name + value + CRLF).
	if !strings.Contains(s, "X-Discord-MFA-Authorization: "+token+"\r\n") {
		t.Errorf("missing/corrupt X-Discord-MFA-Authorization header")
	}
	// Must NOT contain the old placeholder.
	if strings.Contains(s, "XXXXXX") {
		t.Errorf("old MFA placeholder 'XXXXXX' leaked into output")
	}
	if strings.Contains(s, "X-Discord-MFA:") {
		t.Errorf("old MFA header 'X-Discord-MFA:' present in output")
	}
	// Must NOT contain Cookie header (matching working main.js tryClaim).
	if strings.Contains(s, "Cookie:") {
		t.Errorf("Cookie header present but should be omitted (main.js sends none)")
	}
	// Must NOT contain the anti-abuse-triggering x-headers.
	if strings.Contains(s, "Origin:") {
		t.Errorf("Origin header present but should be omitted")
	}
	if strings.Contains(s, "Referer:") {
		t.Errorf("Referer header present but should be omitted")
	}
	if strings.Contains(s, "X-Discord-Locale:") {
		t.Errorf("X-Discord-Locale present but should be omitted")
	}
	if strings.Contains(s, "X-Discord-Timezone:") {
		t.Errorf("X-Discord-Timezone present but should be omitted")
	}
	if strings.Contains(s, "X-Context-Properties:") {
		t.Errorf("X-Context-Properties present but should be omitted")
	}
	// Sanity: the request line and host must be intact.
	if !strings.HasPrefix(s, "PATCH /api/v9/guilds/123456789/vanity-url HTTP/1.1\r\n") {
		t.Errorf("request line corrupt")
	}
	if !strings.Contains(s, "Host: discord.com\r\n") {
		t.Errorf("Host header missing")
	}
	if !strings.Contains(s, "Authorization: FAKE_TOKEN\r\n") {
		t.Errorf("Authorization header missing")
	}
	// Body must come last (trim trailing pool padding — getClaimBuf over-allocates).
	trimmed := bytes.TrimRight(out, "\x00 ")
	if !bytes.HasSuffix(trimmed, []byte(`{"code":"testvanity"}`)) {
		t.Errorf("body not at end of request; got tail %q", trimmed[len(trimmed)-40:])
	}
	// Header/body separator must appear exactly once in the trimmed output.
	if c := bytes.Count(trimmed, []byte("\r\n\r\n")); c != 1 {
		t.Errorf("expected exactly one header/body separator, got %d", c)
	}
	// Must have exactly the main.js header set: request-line, Host, Auth, SP, MFA,
	// Content-Type, Content-Length, User-Agent = 8 header lines + blank line.
	lines := strings.SplitN(s, "\r\n", -1)
	headerLines := 0
	for _, line := range lines {
		if line == "" {
			break
		}
		headerLines++
	}
	if headerLines != 9 {
		t.Errorf("expected 9 header lines (got %d): request-line + Host + Auth + SP + MFA + CT + CL + UA + Connection", headerLines)
	}
}

func TestParseVanityCode(t *testing.T) {
	tests := []struct {
		name   string
		resp   string
		want   string
		wantOK bool
	}{
		{
			name:   "vanity set to target",
			resp:   "HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\n{\"code\":\"deltafinal\"}",
			want:   "deltafinal",
			wantOK: true,
		},
		{
			name:   "no vanity (null)",
			resp:   "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"code\":null}",
			wantOK: true,
		},
		{
			name:   "different vanity set",
			resp:   "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"code\":\"other\"}",
			want:   "other",
			wantOK: true,
		},
		{
			name:   "empty code string",
			resp:   "HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\n{\"code\":\"\"}",
			wantOK: true,
		},
		{
			name:   "no body",
			resp:   "HTTP/1.1 200 OK\r\n\r\n",
			wantOK: false,
		},
		{
			name:   "truncated body",
			resp:   "HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n{\"code\":\"delt",
			wantOK: false,
		},
		{
			name:   "wrong value type",
			resp:   "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{\"code\":12}",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseVanityCode([]byte(tt.resp))
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("parseVanityCode = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// TestPollerIgnoresMalformedResponse proves a broken/truncated poll response
// cannot trigger a claim burst. The old parser returned "" for both a null code
// and a parse error, and poll() read that as "free".
func TestPollerIgnoresMalformedResponse(t *testing.T) {
	ch := make(chan time.Time, 1)
	fc := newFakeConn("target")
	fc.response = []byte("HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n{\"code\":\"tar")

	p := &Poller{
		target:    &Target{GuildID: "1", Vanity: "target"},
		reqBuf:    []byte("GET /api/v9/guilds/1/vanity-url HTTP/1.1\r\n\r\n"),
		readBuf:   make([]byte, 2048),
		available: ch,
		conn:      fc,
	}
	p.poll()

	select {
	case <-ch:
		t.Fatal("malformed response signalled availability")
	default:
	}
}

// TestPollerCadenceTargetsOneRTT guards the observation cadence: the 5ms
// interval is measured from the START of the poll, so a response that already
// took longer than the interval does not get another fixed sleep appended.
// With a 20ms simulated RTT, the old post-response sleep produced a ~25ms gap;
// the cycle-target loop should stay within ~1ms of the RTT itself.
func TestPollerCadenceTargetsOneRTT(t *testing.T) {
	const rtt = 20 * time.Millisecond
	ch := make(chan time.Time, 200)
	stop := make(chan struct{})
	fc := newFakeConn("other")
	fc.readDelay = rtt

	p := &Poller{
		target:    &Target{GuildID: "1", Vanity: "target"},
		reqBuf:    []byte("GET /api/v9/guilds/1/vanity-url HTTP/1.1\r\n\r\n"),
		readBuf:   make([]byte, 2048),
		available: ch,
		stop:      stop,
		done:      make(chan struct{}),
		conn:      fc,
	}

	go p.Run()
	time.Sleep(600 * time.Millisecond)
	close(stop)
	p.Stop()

	var gaps []time.Duration
	var prev time.Time
collect:
	for {
		select {
		case ts := <-ch:
			if !prev.IsZero() {
				gaps = append(gaps, ts.Sub(prev))
			}
			prev = ts
		default:
			break collect
		}
	}
	if len(gaps) < 10 {
		t.Fatalf("only %d observation gaps, want at least 10", len(gaps))
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	median := gaps[len(gaps)/2]
	t.Logf("simulated RTT=%v median observation gap=%v (n=%d)", rtt, median, len(gaps))

	if median > rtt+pollerCadenceSlack {
		t.Fatalf("median observation gap %v adds a fixed sleep to the %v RTT; want <= %v", median, rtt, rtt+pollerCadenceSlack)
	}
}

func TestBuildClaimMFAEmptyCookieOmitsCookieValue(t *testing.T) {
	target := &Target{
		GuildID: "123",
		Vanity:  "v",
		Token:   "TOK",
	}
	cfg := &Conf{
		Fingerprint: Fingerprint{
			DcfDuid:       "d",
			SdcfDuid:      "s",
			SuperPropsB64: "sp",
			UserAgent:     "UA",
		},
	}
	tpl := BuildClaimRequest(target, cfg)
	out := tpl.BuildClaimMFA("jwt")
	s := string(out)
	t.Logf("=== Rendered request (no cookie) ===\n%s", s)
	// No Cookie header even with empty cookie.
	if strings.Contains(s, "Cookie:") {
		t.Errorf("Cookie header present with empty cookie")
	}
}
