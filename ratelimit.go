package main

import (
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

func (r *RateLimiter) HandleResponse(key string, headers []string) {
	b := r.GetBucket(key)
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch name {
		case "X-RateLimit-Limit":
			if v, err := strconv.Atoi(val); err == nil {
				b.limit = v
			}
		case "X-RateLimit-Remaining":
			if v, err := strconv.Atoi(val); err == nil {
				b.remaining = v
			}
		case "X-RateLimit-Reset":
			// Discord sends this as a Unix timestamp in SECONDS (may be fractional).
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				secs := int64(v)
				nanos := int64((v - float64(secs)) * 1e9)
				b.resetAt = time.Unix(secs, nanos)
			}
		case "X-RateLimit-Scope":
			b.scope = val
		case "Retry-After":
			// Retry-After is in SECONDS per RFC 7231 / Discord convention.
			// (Previously this used Millisecond, which was 1000× too short.)
			if v, err := strconv.Atoi(val); err == nil {
				wait := time.Duration(v) * time.Second
				b.backoff = time.Now().Add(wait)
				b.lastRetryAfter = val
			}
		case "X-RateLimit-Global":
			if val == "true" {
				// Honor Retry-After for the global window when present; fall back
				// to a conservative 10s default.
				wait := 10 * time.Second
				if v, err := strconv.Atoi(b.lastRetryAfter); err == nil && v > 0 {
					wait = time.Duration(v) * time.Second
				}
				r.mu.Lock()
				r.globalUntil = time.Now().Add(wait)
				r.mu.Unlock()
			}
		}
	}
}
