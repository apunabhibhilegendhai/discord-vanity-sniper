package sniper

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newArmTestConf(t *testing.T, lanes, warm int) *Conf {
	t.Helper()
	targets := make([]Target, lanes)
	for i := range targets {
		targets[i] = Target{
			GuildID: fmt.Sprintf("%018d", i+1),
			Vanity:  fmt.Sprintf("lane-%d", i),
			Token:   "test-token",
			Proxies: []string{""},
		}
	}
	return &Conf{
		Targets:     targets,
		WarmConns:   warm,
		BurstCount:  1,
		SessionPath: filepath.Join(t.TempDir(), "sessions.json"),
		Fingerprint: Fingerprint{
			UserAgent:     "test-ua",
			SuperPropsB64: "test-super-props",
		},
	}
}

// fakeArmWarmPools runs the real NewConnPool warm-up loop (including its 200ms
// per-dial cadence) against an in-memory conn. It measures the arming cost
// without touching the network.
func fakeArmWarmPools(t *Target, warm int) ([]*ConnPool, []string) {
	pool, err := newConnPool("", warm, func() (Conn, error) {
		return newFakeConn(t.Vanity), nil
	})
	if err != nil {
		return nil, []string{err.Error()}
	}
	return []*ConnPool{pool}, nil
}

func bareArmOrchestrator(cfg *Conf, warm warmPoolsFunc) *Orchestrator {
	sessions := NewSessionStore(cfg.SessionPath)
	sessions.Load()
	return &Orchestrator{
		cfg:       cfg,
		stats:     &Stats{StartTime: time.Now(), lat: newLatencyTracker()},
		webhook:   NewWebhookSender(cfg.WebhookURL),
		rateLim:   NewRateLimiter(),
		sessions:  sessions,
		stopCh:    make(chan struct{}),
		warmPools: warm,
	}
}

// stopArmedOrchestrator tears down runners that were armed but never started.
// StartAll is deliberately not called by the measurement harness, so claimer
// Stop (which waits for done, closed by Run) would block; close the stop
// channels directly instead.
func stopArmedOrchestrator(o *Orchestrator) {
	for _, r := range o.runners {
		if r == nil {
			continue
		}
		if r.mfaCancel != nil {
			close(r.mfaCancel)
		}
		if r.claimer != nil {
			close(r.claimer.stop)
			r.claimer.sentryWG.Wait()
		}
		for _, p := range r.pools {
			p.StopRewarmer()
			p.Close()
		}
	}
}

func armedSpread(runners []*TargetRunner) time.Duration {
	var first, last time.Time
	for _, r := range runners {
		at := r.ArmedAt()
		if first.IsZero() || at.Before(first) {
			first = at
		}
		if at.After(last) {
			last = at
		}
	}
	return last.Sub(first)
}

// TestArmSchedulerIsParallelAndFailureIsVisible proves the arm phase launches
// every lane without waiting for the previous one, and that one failing lane is
// skipped visibly rather than stalling or taking down the rest.
func TestArmSchedulerIsParallelAndFailureIsVisible(t *testing.T) {
	const lanes = 4
	const laneCost = 120 * time.Millisecond

	cfg := newArmTestConf(t, lanes, 5)
	index := make(map[*Target]int, lanes)
	for i := range cfg.Targets {
		index[&cfg.Targets[i]] = i
	}

	var mu sync.Mutex
	finished := make([]time.Time, lanes)
	armLane := func(target *Target) (*TargetRunner, []string, error) {
		i := index[target]
		if i == 2 {
			time.Sleep(laneCost)
			return nil, nil, errors.New("simulated arm failure")
		}
		time.Sleep(laneCost)
		mu.Lock()
		finished[i] = time.Now()
		mu.Unlock()
		return &TargetRunner{target: target}, []string{"simulated warning"}, nil
	}

	start := time.Now()
	o := newOrchestrator(cfg, armLane, nil)
	elapsed := time.Since(start)

	if elapsed >= 2*laneCost {
		t.Fatalf("arm phase took %s; lanes were not concurrent (serial would be ~%s)", elapsed, lanes*laneCost)
	}
	if got := len(o.runners); got != lanes-1 {
		t.Fatalf("armed runners = %d, want %d", got, lanes-1)
	}
	failures := o.ArmFailures()
	if len(failures) != 1 {
		t.Fatalf("arm failures = %d, want 1", len(failures))
	}
	if failures[0].Index != 2 || failures[0].Vanity != "lane-2" {
		t.Fatalf("failure = %+v, want lane-2 at index 2", failures[0])
	}
	for _, r := range o.runners {
		if len(r.ArmWarnings()) == 0 {
			t.Errorf("runner %s has no visible arm warning", r.target.Vanity)
		}
	}

	// The surviving lanes must still start; the failed lane is skipped rather
	// than blocking StartAll forever.
	var startedCount atomic.Int32
	o.startHook = func(*TargetRunner) { startedCount.Add(1) }
	o.StartAll()
	if got := startedCount.Load(); got != lanes-1 {
		t.Fatalf("StartAll started %d runners, want %d", got, lanes-1)
	}

	mu.Lock()
	defer mu.Unlock()
	var first, last time.Time
	for i := 0; i < lanes; i++ {
		if i == 2 {
			continue
		}
		if first.IsZero() || finished[i].Before(first) {
			first = finished[i]
		}
		if finished[i].After(last) {
			last = finished[i]
		}
	}
	spread := last.Sub(first)
	if spread >= laneCost {
		t.Fatalf("first/last lane spread = %s, want < %s", spread, laneCost)
	}
	t.Logf("parallel arm scheduler: lanes=%d wall=%s first-last=%dµs (serial would be ~%s)",
		lanes, elapsed.Round(time.Millisecond), spread.Microseconds(), lanes*laneCost)
}

// TestArmingWallTimeSerialVsParallel measures the real arm path with the real
// NewConnPool 200ms-per-dial warm-up, but a fake in-memory dialer. It reports
// the before/after wall time and the first-to-last warm spread.
func TestArmingWallTimeSerialVsParallel(t *testing.T) {
	const lanes = 3
	const warmConns = 5
	const dialCadence = 200 * time.Millisecond

	serialCfg := newArmTestConf(t, lanes, warmConns)
	serial := bareArmOrchestrator(serialCfg, fakeArmWarmPools)
	defer stopArmedOrchestrator(serial)

	serialStart := time.Now()
	for i := range serialCfg.Targets {
		r, _, err := serial.armTarget(&serialCfg.Targets[i])
		if err != nil {
			t.Fatalf("serial arm %d: %v", i, err)
		}
		serial.runners = append(serial.runners, r)
	}
	serialDur := time.Since(serialStart)
	serialSpread := armedSpread(serial.runners)

	parallelCfg := newArmTestConf(t, lanes, warmConns)
	parallelStart := time.Now()
	parallel := newOrchestrator(parallelCfg, nil, fakeArmWarmPools)
	parallelDur := time.Since(parallelStart)
	defer stopArmedOrchestrator(parallel)

	if got := len(parallel.runners); got != lanes {
		t.Fatalf("parallel armed runners = %d, want %d", got, lanes)
	}
	parallelSpread := armedSpread(parallel.runners)

	// One lane costs warmConns*dialCadence plus small setup. Serial pays that
	// N times; parallel should be close to one lane.
	oneLane := warmConns * dialCadence
	if serialDur < lanes*oneLane*3/4 {
		t.Fatalf("serial arm = %s, expected at least ~%s", serialDur, lanes*oneLane)
	}
	if parallelDur > serialDur*3/4 {
		t.Fatalf("parallel arm = %s, serial = %s; parallel is not materially faster", parallelDur, serialDur)
	}
	if parallelSpread > 250*time.Millisecond {
		t.Fatalf("parallel first/last spread = %s, want < 250ms", parallelSpread)
	}

	t.Logf("arming serial: lanes=%d warm=%d wall=%s first-last=%dµs",
		lanes, warmConns, serialDur.Round(time.Millisecond), serialSpread.Microseconds())
	t.Logf("arming parallel: lanes=%d warm=%d wall=%s first-last=%dµs speedup=%.2fx",
		lanes, warmConns, parallelDur.Round(time.Millisecond), parallelSpread.Microseconds(),
		float64(serialDur)/float64(parallelDur))
}

// TestArmBarrierTimeoutReleasesOtherLanes proves a lane that never returns
// cannot hold the arm barrier (and therefore StartAll) forever.
func TestArmBarrierTimeoutReleasesOtherLanes(t *testing.T) {
	cfg := newArmTestConf(t, 3, 1)
	block := make(chan struct{})
	armLane := func(target *Target) (*TargetRunner, []string, error) {
		if target.Vanity == "lane-0" {
			<-block
		}
		return &TargetRunner{target: target}, nil, nil
	}

	start := time.Now()
	o := newOrchestratorWithTimeout(cfg, armLane, nil, 100*time.Millisecond)
	elapsed := time.Since(start)
	close(block)

	if elapsed > time.Second {
		t.Fatalf("arm barrier took %s; timed-out lane stalled startup", elapsed)
	}
	if got := len(o.runners); got != 2 {
		t.Fatalf("armed runners = %d, want 2", got)
	}
	failures := o.ArmFailures()
	if len(failures) != 1 || failures[0].Index != 0 {
		t.Fatalf("arm failures = %+v, want only lane-0", failures)
	}
	t.Logf("arm timeout: lane-0 failed after %s; other lanes still armed", elapsed.Round(time.Millisecond))
}

func TestArmTargetRejectsTokenlessLane(t *testing.T) {
	cfg := newArmTestConf(t, 1, 1)
	cfg.Targets[0].Token = ""
	o := bareArmOrchestrator(cfg, fakeArmWarmPools)

	runner, _, err := o.armTarget(&cfg.Targets[0])
	if err == nil {
		t.Fatal("tokenless lane armed without an error")
	}
	if runner != nil {
		t.Fatal("tokenless lane returned a runner")
	}
}
