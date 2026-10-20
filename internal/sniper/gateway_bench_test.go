package sniper

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"testing"
	"time"
)

const benchGuildUpdate = `{"t":"GUILD_UPDATE","s":48123,"op":0,"d":{"id":"123456789012345678","name":"Example Guild","icon":"a1b2c3","description":"A guild used for benchmark payloads","vanity_url_code":"example","features":["COMMUNITY","NEWS","VANITY_URL","ANIMATED_ICON","BANNER","INVITE_SPLASH"],"premium_tier":3,"premium_subscription_count":42,"preferred_locale":"en-US","nsfw":false,"region":"us-east","verification_level":3,"default_message_notifications":1,"explicit_content_filter":2,"roles":[{"id":"111","name":"role one","permissions":"8","color":0,"hoist":false,"mentionable":false},{"id":"222","name":"role two","permissions":"8","color":1,"hoist":false,"mentionable":false}],"emojis":[],"stickers":[],"joined_at":"2020-01-01T00:00:00.000000+00:00","large":false,"unavailable":false,"member_count":1000}}`

func TestGuildUpdateFastPathSignalsOnlyOurGuild(t *testing.T) {
	sessions := NewSessionStore(t.TempDir() + "/sessions.json")
	g := NewGateway(&Target{GuildID: "123456789012345678", Vanity: "wanted"},
		make(chan time.Time, 16), sessions)

	if !g.handleGuildUpdateFast([]byte(`{"id":"123456789012345678","vanity_url_code":"other"}`), time.Now()) {
		t.Fatal("expected fast path to handle our guild")
	}
	select {
	case <-g.available:
	default:
		t.Fatal("a different vanity code did not signal availability")
	}

	g.handleGuildUpdateFast([]byte(`{"id":"123456789012345678","vanity_url_code":"wanted"}`), time.Now())
	select {
	case <-g.available:
		t.Fatal("our own vanity code signalled availability")
	default:
	}

	g.handleGuildUpdateFast([]byte(`{"id":"999","vanity_url_code":"other"}`), time.Now())
	select {
	case <-g.available:
		t.Fatal("another guild's update signalled availability")
	default:
	}

	if g.handleGuildUpdateFast([]byte(`{"id":"123456789012345678","vanity_url_code":12}`), time.Now()) {
		t.Fatal("unexpected shape should fall back to JSON")
	}
}

// TestRawGuildUpdateFrameSkipsDecode drives the whole compact frame through the
// pre-decode path that listen() now uses. It must signal for our guild changing
// vanity, stay quiet for our own vanity and other guilds, and bail out (false)
// for anything that is not a dispatch so the normal decode still runs.
func TestRawGuildUpdateFrameSkipsDecode(t *testing.T) {
	g := NewGateway(&Target{GuildID: "123456789012345678", Vanity: "wanted"},
		make(chan time.Time, 16), NewSessionStore(t.TempDir()+"/sessions.json"))

	if !g.handleRawGuildUpdateFrame([]byte(benchGuildUpdate), time.Now()) {
		t.Fatal("compact GUILD_UPDATE frame was not handled")
	}
	select {
	case <-g.available:
	default:
		t.Fatal("different vanity did not signal availability")
	}

	own := []byte(`{"t":"GUILD_UPDATE","s":2,"op":0,"d":{"id":"123456789012345678","vanity_url_code":"wanted"}}`)
	if !g.handleRawGuildUpdateFrame(own, time.Now()) {
		t.Fatal("own-vanity frame was not handled")
	}
	select {
	case <-g.available:
		t.Fatal("our own vanity signalled availability")
	default:
	}

	other := []byte(`{"t":"GUILD_UPDATE","s":3,"op":0,"d":{"id":"999999999999999999","vanity_url_code":"other"}}`)
	if !g.handleRawGuildUpdateFrame(other, time.Now()) {
		t.Fatal("other guild's frame was not handled")
	}
	select {
	case <-g.available:
		t.Fatal("another guild's update signalled availability")
	default:
	}

	nonDispatch := []byte(`{"t":"GUILD_UPDATE","s":4,"op":7,"d":{"id":"123456789012345678","vanity_url_code":"other"}}`)
	if g.handleRawGuildUpdateFrame(nonDispatch, time.Now()) {
		t.Fatal("non-dispatch frame was handled by the raw path")
	}

	if seq, ok := scanJSONIntField(other, "s"); !ok || seq != 3 {
		t.Fatalf("scanJSONIntField(s) = (%d, %v), want (3, true)", seq, ok)
	}
}

func BenchmarkGuildUpdateDecodeJSON(b *testing.B) {
	data := []byte(benchGuildUpdate)
	var guild struct {
		ID            string `json:"id"`
		VanityURLCode string `json:"vanity_url_code"`
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := json.Unmarshal(data, &guild); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGuildUpdateFrameRaw measures the complete pre-decode path listen()
// takes for a GUILD_UPDATE (type + op + guild id + vanity scans).
func BenchmarkGuildUpdateFrameRaw(b *testing.B) {
	oldWriter := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(oldWriter)

	g := NewGateway(&Target{GuildID: "123456789012345678", Vanity: "wanted"},
		make(chan time.Time, b.N+1), NewSessionStore(b.TempDir()+"/sessions.json"))
	data := []byte(benchGuildUpdate)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !g.handleRawGuildUpdateFrame(data, time.Now()) {
			b.Fatal("frame not handled")
		}
	}
}

// BenchmarkGuildUpdateFrameDecode measures the existing envelope + payload
// decode for the same frame, for comparison with the raw path.
func BenchmarkGuildUpdateFrameDecode(b *testing.B) {
	data := []byte(benchGuildUpdate)
	var packet struct {
		Op   int             `json:"op"`
		Seq  int             `json:"s,omitempty"`
		Type string          `json:"t,omitempty"`
		Data json.RawMessage `json:"d,omitempty"`
	}
	var guild struct {
		ID            string `json:"id"`
		VanityURLCode string `json:"vanity_url_code"`
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := json.Unmarshal(data, &packet); err != nil {
			b.Fatal(err)
		}
		if err := json.Unmarshal(packet.Data, &guild); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGuildUpdateDecodeScan(b *testing.B) {
	data := []byte(benchGuildUpdate)
	needle := []byte(`"id":"123456789012345678"`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !bytes.Contains(data, needle) {
			b.Fatal("missing guild id")
		}
		if _, ok := scanJSONStringField(data, "vanity_url_code"); !ok {
			b.Fatal("missing vanity code")
		}
	}
}
