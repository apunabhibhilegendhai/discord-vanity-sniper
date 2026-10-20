package sniper

import (
	"io"
	"log"
	"sort"
	"testing"
	"time"
)

// Hot-path thresholds are measured, not aspirational. Across eight reference
// runs on this host (n=200-300 per run) the observed distributions were:
//
//	span                    p50            p95            p99
//	signal-handler→wire     0.6-7.4µs      3.3-40.2µs     9.9-129.6µs
//
// The limits below leave roughly 2.7x headroom over the worst measured p50,
// 6x over p95, and 15x over p99. A regression that turns the microsecond
// wake→wire path into a millisecond path now fails the default suite instead of
// only appearing in a log line.
const (
	hotPathP50Limit = 20 * time.Microsecond
	hotPathP95Limit = 250 * time.Microsecond
	hotPathP99Limit = 2 * time.Millisecond
)

// TestHotPathFreeToWire measures the delay from the claimer receiving an
// availability signal to the claim PATCH bytes being written. The socket is a
// fake, so the number is entirely local: firstClaim work, fire broadcast,
// sentry wake, and conn.Write. It is the part of a snipe that code can actually
// improve; network RTT is measured by the realnet harness.
//
// The harness deliberately uses QueryPerformanceCounter on Windows because the
// default clock there advances in ~650µs steps.
func TestHotPathFreeToWire(t *testing.T) {
	ds := measureFreeToWire(t, 300, 1)
	reportHotPath(t, "signal-handler→wire", ds)
}

// TestHotPathBurstFirstWire measures the first wire write when the default
// five-sentry burst is armed. Extra sentries must not delay the first PATCH.
func TestHotPathBurstFirstWire(t *testing.T) {
	ds := measureFreeToWire(t, 200, 5)
	reportHotPath(t, "burst5-first-wire", ds)
}

// TestHotPathSignalToWire includes the availability-channel send/receive that
// sits between the gateway/poller and tryClaim, so it measures the whole local
// free→wire span rather than only the handler entry.
func TestHotPathSignalToWire(t *testing.T) {
	ds := measureSignalToWire(t, 300)
	reportHotPath(t, "channel-send→wire", ds)
}

func measureFreeToWire(t *testing.T, iterations, burst int) []time.Duration {
	t.Helper()

	var claimer *Claimer
	if burst > 1 {
		claimer, _ = newTestClaimerWithBurst(t, "123456789012345678", "harness", burst)
	} else {
		claimer, _ = newTestClaimer(t, "123456789012345678", "harness")
	}

	oldWriter := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(oldWriter)

	wireAt := make(chan int64, 1)
	claimer.wireHook = func() {
		select {
		case wireAt <- hotNow():
		default:
		}
	}

	ds := make([]time.Duration, 0, iterations)
	timeouts := 0
	for i := 0; i < iterations; i++ {
		claimer.target.mu.Lock()
		claimer.target.claimed = false
		claimer.target.mu.Unlock()
		claimer.resetSuccessGate(false)

		start := hotNow()
		claimer.tryClaim(time.Now())

		select {
		case end := <-wireAt:
			ds = append(ds, hotDuration(start, end))
		case <-time.After(2 * time.Second):
			timeouts++
		}
	}
	if timeouts > 0 {
		t.Fatalf("%d/%d claim iterations never reached the wire", timeouts, iterations)
	}
	return ds
}

func measureSignalToWire(t *testing.T, iterations int) []time.Duration {
	t.Helper()

	claimer, _ := newTestClaimer(t, "123456789012345678", "harness")

	oldWriter := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(oldWriter)

	wireAt := make(chan int64, 1)
	claimer.wireHook = func() {
		select {
		case wireAt <- hotNow():
		default:
		}
	}

	doneCh := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case t0 := <-claimer.available:
				claimer.tryClaim(t0)
				doneCh <- struct{}{}
			case <-claimer.stop:
				return
			}
		}
	}()

	ds := make([]time.Duration, 0, iterations)
	timeouts := 0
	for i := 0; i < iterations; i++ {
		claimer.target.mu.Lock()
		claimer.target.claimed = false
		claimer.target.mu.Unlock()
		claimer.resetSuccessGate(false)

		start := hotNow()
		claimer.available <- time.Now()

		select {
		case end := <-wireAt:
			ds = append(ds, hotDuration(start, end))
		case <-time.After(2 * time.Second):
			timeouts++
		}
		<-doneCh
	}
	if timeouts > 0 {
		t.Fatalf("%d/%d claim iterations never reached the wire", timeouts, iterations)
	}
	return ds
}

func reportHotPath(t *testing.T, name string, ds []time.Duration) {
	t.Helper()
	if len(ds) == 0 {
		t.Fatalf("%s produced no samples", name)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	pick := func(q float64) time.Duration {
		return ds[int(q*float64(len(ds)-1))]
	}
	var total time.Duration
	for _, d := range ds {
		total += d
	}
	p50, p95, p99 := pick(.50), pick(.95), pick(.99)
	t.Logf("%s n=%d mean=%v p50=%v p95=%v p99=%v max=%v",
		name, len(ds), total/time.Duration(len(ds)), p50, p95, p99, ds[len(ds)-1])

	if p50 > hotPathP50Limit {
		t.Errorf("%s p50=%v exceeds %v", name, p50, hotPathP50Limit)
	}
	if p95 > hotPathP95Limit {
		t.Errorf("%s p95=%v exceeds %v", name, p95, hotPathP95Limit)
	}
	if p99 > hotPathP99Limit {
		t.Errorf("%s p99=%v exceeds %v", name, p99, hotPathP99Limit)
	}
}
