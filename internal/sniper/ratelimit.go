package sniper

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*RateBucket
	globalUntil time.Time
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*RateBucket),
	}
}

func (r *RateLimiter) GetBucket(key string) *RateBucket {
	r.mu.Lock()
	b, ok := r.buckets[key]
	if !ok {
		b = &RateBucket{remaining: 50, limit: 50}
		r.buckets[key] = b
	}
	r.mu.Unlock()
	return b
}

func (r *RateLimiter) Wait(key string) {
	b := r.GetBucket(key)

	for {
		b.mu.Lock()
		now := time.Now()

		if now.Before(b.backoff) {
			wait := b.backoff.Sub(now)
			b.mu.Unlock()
			time.Sleep(wait)
			continue
		}

		if now.Before(b.resetAt) && b.remaining <= 0 {
			wait := b.resetAt.Sub(now)
			if wait > 5*time.Second {
				wait = 5 * time.Second
			}
			b.mu.Unlock()
			time.Sleep(wait)
			continue
		}

		if now.After(b.resetAt) {
			b.remaining = b.limit
		}

		if b.remaining > 0 {
			b.remaining--
			b.mu.Unlock()
			return
		}

		b.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
}

func (r *RateLimiter) WaitGlobal() {
	for {
		r.mu.Lock()
		now := time.Now()
		if now.Before(r.globalUntil) {
			wait := r.globalUntil.Sub(now)
			r.mu.Unlock()
			time.Sleep(wait)
			continue
		}
		r.mu.Unlock()
		return
	}
}

// WaitRetry waits out a 429 retry: Discord's JSON retry_after when the response
// states one, otherwise a fixed attempt-scaled pause so a bare 429 cannot become
// an immediate retry storm, then the bucket's Retry-After window.
func (r *RateLimiter) WaitRetry(key string, resp []byte, attempt int) {
	if wait, stated := jsonRetryAfter(resp); stated {
		if wait > 0 {
			b := r.GetBucket(key)
			b.mu.Lock()
			if until := time.Now().Add(time.Duration(wait * float64(time.Second))); until.After(b.backoff) {
				b.backoff = until
			}
			b.mu.Unlock()
		}
	} else if !r.backoffPending(key) {
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
	r.Wait(key)
}

func (r *RateLimiter) backoffPending(key string) bool {
	b := r.GetBucket(key)
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Now().Before(b.backoff)
}

// jsonRetryAfter returns Discord's JSON retry_after in seconds, and whether the
// field was present at all: a stated 0 means "retry now".
func jsonRetryAfter(resp []byte) (float64, bool) {
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return 0, false
	}
	body := resp[idx+4:]
	k := bytes.Index(body, []byte(`"retry_after":`))
	if k < 0 {
		return 0, false
	}
	rest := bytes.TrimLeft(body[k+len(`"retry_after":`):], " ")
	end := 0
	for end < len(rest) {
		switch rest[end] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '-', '+', 'e', 'E':
			end++
			continue
		}
		break
	}
	v, err := strconv.ParseFloat(string(rest[:end]), 64)
	if end == 0 || err != nil {
		return 0, false
	}
	return v, true
}

func (r *RateLimiter) HandleResponse(key string, headers []string) {
	b := r.GetBucket(key)
	b.mu.Lock()
	defer b.mu.Unlock()

	// Two passes: X-RateLimit-Global's fallback window needs the Retry-After
	// value, and Discord sends them in arbitrary order — a single pass would
	// take the conservative default whenever Retry-After comes later.

	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch {
		case strings.EqualFold(name, "X-RateLimit-Limit"):
			if v, err := strconv.Atoi(val); err == nil {
				b.limit = v
			}
		case strings.EqualFold(name, "X-RateLimit-Remaining"):
			if v, err := strconv.Atoi(val); err == nil {
				b.remaining = v
			}
		case strings.EqualFold(name, "X-RateLimit-Reset"):
			// Discord sends this as a Unix timestamp in SECONDS (may be fractional).
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				secs := int64(v)
				nanos := int64((v - float64(secs)) * 1e9)
				b.resetAt = time.Unix(secs, nanos)
			}
		case strings.EqualFold(name, "X-RateLimit-Scope"):
			b.scope = val
		case strings.EqualFold(name, "Retry-After"):
			// Discord sends fractional seconds (e.g. "0.342"); parse as float.
			// (An older version used Millisecond here — 1000× too short.)
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				if v < 0 {
					v = 0
				}
				b.lastRetryAfter = val
				wait := time.Duration(v * float64(time.Second))
				b.backoff = time.Now().Add(wait)
			}
		}
	}

	// Second pass for the global window so it can consult Retry-After.
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		if strings.EqualFold(name, "X-RateLimit-Global") && val == "true" {
			// Honor Retry-After for the global window when present; fall back
			// to a conservative 10s default.
			wait := 10 * time.Second
			if v, err := strconv.ParseFloat(b.lastRetryAfter, 64); err == nil && v > 0 {
				wait = time.Duration(v * float64(time.Second))
			}
			r.mu.Lock()
			r.globalUntil = time.Now().Add(wait)
			r.mu.Unlock()
		}
	}
}
