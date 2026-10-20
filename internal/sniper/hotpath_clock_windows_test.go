//go:build windows

package sniper

import (
	"syscall"
	"time"
	"unsafe"
)

// The default Windows Go clock in this environment advances in ~650µs steps,
// which is far too coarse to measure a sub-millisecond claim path. The latency
// harness uses QueryPerformanceCounter directly so before/after numbers are
// comparable and honest.

var (
	qpcProc    = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryPerformanceCounter")
	qpcFreqPrc = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryPerformanceFrequency")
	qpcFreq    int64
)

func init() {
	var freq int64
	qpcFreqPrc.Call(uintptr(unsafe.Pointer(&freq)))
	qpcFreq = freq
}

func hotNow() int64 {
	var counter int64
	qpcProc.Call(uintptr(unsafe.Pointer(&counter)))
	return counter
}

func hotDuration(start, end int64) time.Duration {
	if qpcFreq <= 0 {
		return 0
	}
	return time.Duration((end - start) * int64(time.Second) / qpcFreq)
}
