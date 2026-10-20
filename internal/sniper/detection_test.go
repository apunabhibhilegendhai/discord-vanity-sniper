package sniper

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

const detectionGuild = "123456789012345678"

// TestVanityFreeDecision pins the single decision function's contract:
// unparseable/partial payloads are never free, while a valid empty code is.
func TestVanityFreeDecision(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		observed string
		valid    bool
		want     bool
	}{
		{"valid empty code is free", "wanted", "", true, true},
		{"different code is free", "wanted", "other", true, true},
		{"matching code is not free", "wanted", "wanted", true, false},
		{"unparseable empty payload is not free", "wanted", "", false, false},
		{"unparseable different payload is not free", "wanted", "other", false, false},
		{"unparseable matching-looking payload is not free", "wanted", "wanted", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vanityFree(tt.current, tt.observed, tt.valid); got != tt.want {
				t.Fatalf("vanityFree(%q, %q, %v) = %v, want %v",
					tt.current, tt.observed, tt.valid, got, tt.want)
			}
		})
	}
}

func TestParseJSONCodeValidity(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{"null means no vanity", `null`, "", true},
		{"empty string is valid", `""`, "", true},
		{"string code", `"other"`, "other", true},
		{"number is invalid", `12`, "", false},
		{"boolean is invalid", `true`, "", false},
		{"empty raw is invalid", ``, "", false},
		{"partial string is invalid", `"oth`, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseJSONCode(json.RawMessage(tt.raw))
			if got != tt.want || ok != tt.ok {
				t.Fatalf("parseJSONCode(%s) = (%q, %v), want (%q, %v)", tt.raw, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func newDetectionGateway(t *testing.T) *Gateway {
	t.Helper()
	return NewGateway(
		&Target{GuildID: detectionGuild, Vanity: "wanted"},
		make(chan time.Time, 16),
		NewSessionStore(t.TempDir()+"/sessions.json"),
	)
}

func expectSignal(t *testing.T, ch chan time.Time) {
	t.Helper()
	select {
	case <-ch:
	default:
		t.Fatal("expected an availability signal")
	}
}

func expectNoSignal(t *testing.T, ch chan time.Time) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal("unexpected availability signal")
	default:
	}
}

func restResponse(body string) []byte {
	return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
}

// TestDetectionRoutesSignalOnDifferentCode covers the positive path on every
// route that can observe a vanity code.
func TestDetectionRoutesSignalOnDifferentCode(t *testing.T) {
	t.Run("GUILD_UPDATE json fallback", func(t *testing.T) {
		g := newDetectionGateway(t)
		// Spaces around the colon force the fast path to decline so this
		// exercises the JSON fallback, not handleGuildUpdateFast.
		g.handleDispatch("GUILD_UPDATE",
			json.RawMessage(`{"id" : "`+detectionGuild+`", "vanity_url_code" : "other"}`),
			time.Now())
		expectSignal(t, g.available)
	})

	t.Run("READY", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.handleDispatch("READY", json.RawMessage(
			`{"session_id":"s","resume_gateway_url":"u","user":{"id":"u","username":"n"},`+
				`"guilds":[{"id":"`+detectionGuild+`","vanity_url_code":"other"}]}`),
			time.Now())
		expectSignal(t, g.available)
	})

	t.Run("GUILD_CREATE", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.handleDispatch("GUILD_CREATE", json.RawMessage(
			`{"id":"`+detectionGuild+`","vanity_url_code":"other"}`), time.Now())
		expectSignal(t, g.available)
	})

	t.Run("REST", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.evaluateVanityREST(restResponse(`{"code":"other"}`), true)
		expectSignal(t, g.available)
	})

	t.Run("Poller", func(t *testing.T) {
		ch := make(chan time.Time, 1)
		p := &Poller{
			target:    &Target{GuildID: detectionGuild, Vanity: "wanted"},
			reqBuf:    []byte("GET /api/v9/guilds/" + detectionGuild + "/vanity-url HTTP/1.1\r\n\r\n"),
			readBuf:   make([]byte, 2048),
			available: ch,
			conn:      newFakeConn("other"),
		}
		p.poll()
		expectSignal(t, ch)
	})
}

// TestDetectionRoutesMalformedPayloadsDoNotSignal proves a failed or partial
// parse cannot resolve to free on any route.
func TestDetectionRoutesMalformedPayloadsDoNotSignal(t *testing.T) {
	t.Run("GUILD_UPDATE fast path", func(t *testing.T) {
		g := newDetectionGateway(t)
		if g.handleGuildUpdateFast(
			[]byte(`{"id":"`+detectionGuild+`","vanity_url_code":12}`), time.Now()) {
			t.Fatal("malformed fast-path payload should fall back")
		}
		expectNoSignal(t, g.available)
	})

	t.Run("GUILD_UPDATE json fallback", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.handleDispatch("GUILD_UPDATE",
			json.RawMessage(`{"id" : "`+detectionGuild+`", "vanity_url_code" : 12}`),
			time.Now())
		expectNoSignal(t, g.available)
	})

	t.Run("GUILD_UPDATE fast path truncated object", func(t *testing.T) {
		g := newDetectionGateway(t)
		// The code string is complete, but the object is not. This used to be
		// indistinguishable from a valid frame to the byte scanner.
		if g.handleGuildUpdateFast(
			[]byte(`{"id":"`+detectionGuild+`","vanity_url_code":"other"`), time.Now()) {
			t.Fatal("truncated fast-path payload should fall back")
		}
		expectNoSignal(t, g.available)
	})

	t.Run("READY", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.handleDispatch("READY", json.RawMessage(
			`{"session_id":"s","guilds":[{"id":"`+detectionGuild+`","vanity_url_code":12}]}`),
			time.Now())
		expectNoSignal(t, g.available)
	})

	t.Run("READY truncated JSON", func(t *testing.T) {
		g := newDetectionGateway(t)
		// A partial document can leave a syntactically complete guild entry in
		// the decoder's output. The route must reject the whole parse.
		g.handleDispatch("READY", json.RawMessage(
			`{"session_id":"s","guilds":[{"id":"`+detectionGuild+`","vanity_url_code":"other"}]`),
			time.Now())
		expectNoSignal(t, g.available)
	})

	t.Run("GUILD_CREATE", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.handleDispatch("GUILD_CREATE", json.RawMessage(
			`{"id":"`+detectionGuild+`","vanity_url_code":12}`), time.Now())
		expectNoSignal(t, g.available)
	})

	t.Run("GUILD_DELETE truncated JSON", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.handleDispatch("GUILD_DELETE", json.RawMessage(
			`{"id":"`+detectionGuild+`"`), time.Now())
		expectNoSignal(t, g.available)
	})

	t.Run("REST unparseable body", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.evaluateVanityREST(restResponse(`{"code":12}`), true)
		expectNoSignal(t, g.available)
	})

	t.Run("REST incomplete response", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.evaluateVanityREST(restResponse(`{"code":"other"}`), false)
		expectNoSignal(t, g.available)
	})

	t.Run("Poller wrong value type", func(t *testing.T) {
		ch := make(chan time.Time, 1)
		fc := newFakeConn("other")
		fc.response = restResponse(`{"code":12}`)
		p := &Poller{
			target:    &Target{GuildID: detectionGuild, Vanity: "wanted"},
			reqBuf:    []byte("GET /api/v9/guilds/" + detectionGuild + "/vanity-url HTTP/1.1\r\n\r\n"),
			readBuf:   make([]byte, 2048),
			available: ch,
			conn:      fc,
		}
		p.poll()
		expectNoSignal(t, ch)
	})
}

// TestDetectionEmptyCodeStillFree guards the semantics the refactor must not
// change: a guild with no vanity set (valid empty code) is still claimable on
// every route.
func TestDetectionEmptyCodeStillFree(t *testing.T) {
	t.Run("READY null", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.handleDispatch("READY", json.RawMessage(
			`{"session_id":"s","guilds":[{"id":"`+detectionGuild+`","vanity_url_code":null}]}`),
			time.Now())
		expectSignal(t, g.available)
	})

	t.Run("GUILD_CREATE null", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.handleDispatch("GUILD_CREATE", json.RawMessage(
			`{"id":"`+detectionGuild+`","vanity_url_code":null}`), time.Now())
		expectSignal(t, g.available)
	})

	t.Run("REST null", func(t *testing.T) {
		g := newDetectionGateway(t)
		g.evaluateVanityREST(restResponse(`{"code":null}`), true)
		expectSignal(t, g.available)
	})

	t.Run("Poller null", func(t *testing.T) {
		ch := make(chan time.Time, 1)
		fc := newFakeConn("other")
		fc.response = restResponse(`{"code":null}`)
		p := &Poller{
			target:    &Target{GuildID: detectionGuild, Vanity: "wanted"},
			reqBuf:    []byte("GET /api/v9/guilds/" + detectionGuild + "/vanity-url HTTP/1.1\r\n\r\n"),
			readBuf:   make([]byte, 2048),
			available: ch,
			conn:      fc,
		}
		p.poll()
		expectSignal(t, ch)
	})
}
