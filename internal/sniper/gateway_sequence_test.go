package sniper

import (
	"encoding/json"
	"testing"
	"time"
)

type gatewayBookkeeping struct {
	sequence int
	pending  int64
	flushed  int64
	attempts int
}

func snapshotBookkeeping(g *Gateway) gatewayBookkeeping {
	g.mu.Lock()
	s := gatewayBookkeeping{sequence: g.state.Sequence, attempts: g.resumeAttempts}
	g.mu.Unlock()
	s.pending = g.seqPending.Load()
	s.flushed = g.lastFlushedSeq.Load()
	return s
}

// TestRawAndDispatchSequenceParity feeds one GUILD_UPDATE frame through both
// production routes and requires identical envelope bookkeeping. The fallback
// case also proves the raw route leaves state untouched until the JSON route
// handles the frame, so the frame is noted exactly once.
func TestRawAndDispatchSequenceParity(t *testing.T) {
	tests := []struct {
		name       string
		frame      string
		rawHandled bool
	}{
		{
			name:       "compact raw route",
			frame:      `{"t":"GUILD_UPDATE","s":48123,"op":0,"d":{"id":"` + detectionGuild + `","vanity_url_code":"other"}}`,
			rawHandled: true,
		},
		{
			name:       "raw fallback",
			frame:      `{"t":"GUILD_UPDATE","s":48123,"op":0,"d":{"id" : "` + detectionGuild + `", "vanity_url_code" : "other"}}`,
			rawHandled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var packet struct {
				Op   int             `json:"op"`
				Seq  int             `json:"s"`
				Type string          `json:"t"`
				Data json.RawMessage `json:"d"`
			}
			if err := json.Unmarshal([]byte(tc.frame), &packet); err != nil {
				t.Fatalf("unmarshal frame: %v", err)
			}

			applyDispatch := func(g *Gateway) {
				g.noteFrame(packet.Seq, packet.Op == 0)
				g.handleDispatch(packet.Type, packet.Data, time.Now())
			}

			route := newDetectionGateway(t)
			route.mu.Lock()
			route.resumeAttempts = 2
			route.mu.Unlock()
			before := snapshotBookkeeping(route)

			handled := route.handleRawGuildUpdateFrame([]byte(tc.frame), time.Now())
			if handled != tc.rawHandled {
				t.Fatalf("raw handled = %v, want %v", handled, tc.rawHandled)
			}

			if handled {
				expectSignal(t, route.available)
			} else {
				// A fallback must not have noted the envelope early.
				expectNoSignal(t, route.available)
				if got := snapshotBookkeeping(route); got != before {
					t.Fatalf("raw fallback changed bookkeeping: got %+v, want %+v", got, before)
				}
				applyDispatch(route)
				expectSignal(t, route.available)
			}

			dispatchOnly := newDetectionGateway(t)
			dispatchOnly.mu.Lock()
			dispatchOnly.resumeAttempts = 2
			dispatchOnly.mu.Unlock()
			applyDispatch(dispatchOnly)
			expectSignal(t, dispatchOnly.available)

			if got, want := snapshotBookkeeping(route), snapshotBookkeeping(dispatchOnly); got != want {
				t.Fatalf("route state = %+v, dispatch state = %+v", got, want)
			}
		})
	}
}

// TestResumeAttemptCap drives the counter across reconnect attempts. Each call
// represents the op-9 handling for one reconnect; the third resumable failure
// forces a fresh IDENTIFY, and the counter starts over for a later episode.
func TestResumeAttemptCap(t *testing.T) {
	g := newDetectionGateway(t)

	check := func(label string, resumable bool, wantAttempts int, wantFallback bool) {
		t.Helper()
		attempts, fallback := g.noteInvalidSession(resumable)
		if attempts != wantAttempts || fallback != wantFallback {
			t.Fatalf("%s: got (attempts=%d, fallback=%v), want (%d, %v)",
				label, attempts, fallback, wantAttempts, wantFallback)
		}
	}

	check("non-resumable first attempt", false, 1, true)
	check("first resumable attempt", true, 1, false)
	check("second resumable attempt", true, 2, false)
	check("third resumable attempt hits cap", true, 3, true)
	check("attempt after fallback starts over", true, 1, false)

	g.noteFrame(0, true)
	check("dispatch clears the counter", true, 1, false)
}
