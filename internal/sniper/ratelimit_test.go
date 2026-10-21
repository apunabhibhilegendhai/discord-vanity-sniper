package sniper

import (
	"testing"
	"time"
)

func resp429(body string) []byte {
	return []byte("HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\r\n" + body)
}

func TestJsonRetryAfter(t *testing.T) {
	if secs, ok := jsonRetryAfter(resp429(`{"retry_after":0.25,"global":false}`)); !ok || secs != 0.25 {
		t.Fatalf("jsonRetryAfter = %v, %v; want 0.25, true", secs, ok)
	}
	if secs, ok := jsonRetryAfter(resp429(`{"retry_after":0}`)); !ok || secs != 0 {
		t.Fatalf("jsonRetryAfter = %v, %v; want 0, true", secs, ok)
	}
	if _, ok := jsonRetryAfter(resp429(`{"message":"limited"}`)); ok {
		t.Fatal("jsonRetryAfter reported a value for a body without retry_after")
	}
}

// Guards the removed 500ms retry floor: with a stated retry_after the wait is
// the stated value, not a fixed pause stacked on top of it.
func TestWaitRetryHonorsStatedWait(t *testing.T) {
	rl := NewRateLimiter()
	start := time.Now()
	rl.WaitRetry("g", resp429(`{"retry_after":0.05}`), 0)
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond || elapsed > 400*time.Millisecond {
		t.Fatalf("WaitRetry took %v, want ~50ms from the stated retry_after", elapsed)
	}
}

// A 429 that states no wait at all keeps the conservative pause.
func TestWaitRetryFallsBackWithoutStatedWait(t *testing.T) {
	rl := NewRateLimiter()
	start := time.Now()
	rl.WaitRetry("g", resp429(`{"message":"limited"}`), 0)
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("WaitRetry took %v, want at least the 500ms fallback", elapsed)
	}
}

// A body without retry_after still honors the integer Retry-After header.
func TestWaitRetryHonorsHeaderOnly(t *testing.T) {
	rl := NewRateLimiter()
	rl.HandleResponse("g", []string{"Retry-After: 1"})
	start := time.Now()
	rl.WaitRetry("g", resp429(`{"message":"limited"}`), 0)
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("WaitRetry took %v, want the 1s header window", elapsed)
	}
}
