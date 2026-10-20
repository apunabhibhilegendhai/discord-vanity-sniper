package sniper

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"
)

// TestMorePoolsThanBurstFiresOnlyBurstPools locks in the documented cap:
// burst_count is the number of simultaneous PATCH writes, so when there are
// more proxy pools than sentries, only the first burst_count pools fire.
func TestMorePoolsThanBurstFiresOnlyBurstPools(t *testing.T) {
	const (
		guildID = "999999999999999999"
		vanity  = "capped"
		burst   = 2
		poolsN  = 3
	)

	target := &Target{GuildID: guildID, Vanity: vanity, Token: "test-token"}
	cfg := &Conf{
		BurstCount: burst,
		Fingerprint: Fingerprint{
			UserAgent:     "test-ua",
			SuperPropsB64: "test-super-props",
		},
	}
	sessions := NewSessionStore(filepath.Join(t.TempDir(), "session_state.json"))
	mfa := NewMFAHandler(target, sessions, "", "", nil, &cfg.Fingerprint)
	stats := &Stats{StartTime: time.Now()}

	pools := make([]*ConnPool, poolsN)
	conns := make([]*fakeConn, poolsN)
	for i := range pools {
		conns[i] = newFakeConn(vanity)
		pools[i] = &ConnPool{
			addr:   "discord.com:443",
			target: 1,
			conns:  []pooledConn{{conn: conns[i], idledAt: time.Now()}},
		}
	}

	claimer := NewClaimer(target, cfg, pools, mfa, stats, nil, NewRateLimiter(),
		burst, false, 1, 1, nil)
	claimer.publishBytes()
	t.Cleanup(func() {
		close(claimer.stop)
		claimer.sentryWG.Wait()
		for _, p := range pools {
			p.Close()
		}
	})

	claimer.tryClaim(time.Now())

	// Exactly the pools with a sentry must carry a claim; the rest stay quiet.
	want := []byte(`{"code":"capped"}`)
	for i, fc := range conns {
		req := fc.requestBytes()
		if i < burst {
			if !bytes.Contains(req, want) {
				t.Errorf("pool %d should have received the claim, got %q", i, req)
			}
		} else if len(req) != 0 {
			t.Errorf("pool %d had no sentry but wrote %d bytes", i, len(req))
		}
	}

	t.Logf("burst=%d pools=%d: pools 0-%d fired; pool %d stayed idle", burst, poolsN, burst-1, burst)
}
