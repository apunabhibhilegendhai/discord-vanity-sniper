package sniper

import (
	"encoding/json"
	"testing"
	"time"
)

// TestChecksCounterTracksObservations proves both detection triggers feed the
// shared Stats.Checks counter through observeVanity, so the dashboard's checks
// and speed figures are no longer permanently zero. It also reports the
// observation rate a short run computes from the counter.
func TestChecksCounterTracksObservations(t *testing.T) {
	stats := &Stats{StartTime: time.Now()}
	target := &Target{GuildID: "guild-1", Vanity: "wanted"}

	// Gateway trigger: a valid GUILD_UPDATE vanity observation increments once.
	g := NewGateway(target, make(chan time.Time, 1), NewSessionStore(t.TempDir()+"/sessions.json"))
	g.stats = stats
	g.handleDispatch("GUILD_UPDATE",
		json.RawMessage(`{"id":"guild-1","vanity_url_code":"other"}`), time.Now())

	afterGateway, _, _ := stats.Snapshot()
	if afterGateway != 1 {
		t.Fatalf("gateway observation: checks = %d, want 1", afterGateway)
	}

	// Poller trigger: run the real poll loop over a fake connection and verify
	// repeated observations keep advancing the same counter.
	stop := make(chan struct{})
	p := NewPoller(target, "token", "ua", "sp", make(chan time.Time, 1), stop)
	p.stats = stats
	p.conn = newFakeConn("wanted") // valid, not free: counts but never signals
	go p.Run()
	time.Sleep(60 * time.Millisecond)
	close(stop)
	p.Stop()

	afterPoller, _, _ := stats.Snapshot()
	if afterPoller <= afterGateway {
		t.Fatalf("poller made no observations: checks stayed at %d", afterPoller)
	}

	elapsed := time.Since(stats.StartTime)
	speed := float64(afterPoller) / elapsed.Seconds()
	if speed <= 0 {
		t.Fatalf("non-zero checks produced a zero observation rate (%.3f/s)", speed)
	}
	t.Logf("checks=%d over %s => %.1f observations/s", afterPoller, elapsed.Round(time.Millisecond), speed)
}
