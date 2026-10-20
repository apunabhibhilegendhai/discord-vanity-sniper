//go:build !windows

package sniper

import "time"

// Non-Windows fallback for the latency harness. time.Now is nanosecond
// resolution on the supported Unix platforms.
func hotNow() int64 { return time.Now().UnixNano() }

func hotDuration(start, end int64) time.Duration {
	return time.Duration(end - start)
}
