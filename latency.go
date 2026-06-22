package main

import (
	"sort"
	"sync"
	"time"
)

// latSample breaks a claim episode into four spans, each measured from a fixed
// point in the wake→wire path:
//
//	T0 — WS frame fully decoded in gateway.listen() (frame arrival).
//	T1 — fire() closes the broadcast channel (claim work published).
//	T2 — winning sentry's conn.Write returns (bytes on the wire).
//	T3 — winning sentry reads the 200/204 response (claim landed).
//
//	Dispatch = T1−T0  gateway dispatch + channel handoff + claimer wake
//	                  + tryClaim + firstClaim + publishBytes.
//	Local    = T2−T1  fire broadcast + sentry wake + atomic load + Write syscall.
//	RTT      = T3−T2  network round-trip (the RTT-dominated portion).
//	Total    = T3−T0  the end-to-end number that wins or loses the race.
type latSample struct {
	dispatch time.Duration
	local    time.Duration
	rtt      time.Duration
	total    time.Duration
}

const latRingSize = 256

// latencyTracker is a fixed-capacity ring buffer of recent claim-latency samples.
// record() runs on the POST-success path (once per claim episode, inside
// firstSuccessOnce), never on the wake→wire hot path, so the mutex is
// effectively uncontended. Percentiles copies the ring under the same lock for
// the 5s dashboard ticker.
type latencyTracker struct {
	mu   sync.Mutex
	ring [latRingSize]latSample
	idx  int // next write slot (monotonic)
	n    int // count of valid samples (capped at latRingSize)
}

func newLatencyTracker() *latencyTracker {
	return &latencyTracker{}
}

func (lt *latencyTracker) record(s latSample) {
	if lt == nil {
		return
	}
	lt.mu.Lock()
	lt.ring[lt.idx%latRingSize] = s
	lt.idx++
	if lt.n < latRingSize {
		lt.n++
	}
	lt.mu.Unlock()
}

// Percentiles returns p50 and p99 for each span across the valid samples.
// Returns ok=false when there are no samples yet (e.g. before the first claim).
func (lt *latencyTracker) Percentiles() (p50, p99 latSample, ok bool) {
	if lt == nil {
		return
	}
	lt.mu.Lock()
	if lt.n == 0 {
		lt.mu.Unlock()
		return
	}
	// Copy valid samples out from the ring. The oldest sample is at
	// (idx - n) mod size; walk forward from there.
	samples := make([]latSample, lt.n)
	start := (lt.idx - lt.n + latRingSize) % latRingSize
	for i := 0; i < lt.n; i++ {
		samples[i] = lt.ring[(start+i)%latRingSize]
	}
	lt.mu.Unlock()

	p50.dispatch, p99.dispatch = percentilePair(extract(samples, func(s latSample) time.Duration { return s.dispatch }))
	p50.local, p99.local = percentilePair(extract(samples, func(s latSample) time.Duration { return s.local }))
	p50.rtt, p99.rtt = percentilePair(extract(samples, func(s latSample) time.Duration { return s.rtt }))
	p50.total, p99.total = percentilePair(extract(samples, func(s latSample) time.Duration { return s.total }))
	ok = true
	return
}

// Count returns the number of recorded samples (capped at the ring size).
func (lt *latencyTracker) Count() int {
	if lt == nil {
		return 0
	}
	lt.mu.Lock()
	n := lt.n
	lt.mu.Unlock()
	return n
}

func extract(samples []latSample, f func(latSample) time.Duration) []time.Duration {
	out := make([]time.Duration, len(samples))
	for i, s := range samples {
		out[i] = f(s)
	}
	return out
}

// percentilePair sorts vals in place and returns the p50 and p99 via the
// nearest-rank method.
func percentilePair(vals []time.Duration) (p50, p99 time.Duration) {
	if len(vals) == 0 {
		return 0, 0
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	p50 = vals[rank(len(vals), 50)]
	p99 = vals[rank(len(vals), 99)]
	return
}

// rank returns the 0-based nearest-rank index for percentile p (0–100).
func rank(n, p int) int {
	idx := (p*n + 99) / 100 // ceil(p/100 * n), 1-based
	if idx < 1 {
		idx = 1
	}
	if idx > n {
		idx = n
	}
	return idx - 1
}
