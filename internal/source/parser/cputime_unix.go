//go:build darwin || linux || freebsd || netbsd || openbsd

package parser

import (
	"time"

	"golang.org/x/sys/unix"
)

// threadCPU is the CPU time the calling OS thread has used. The caller locks its goroutine to the
// thread, so the difference between two readings is the work this file took, whatever else the
// machine was doing.
func threadCPU() (time.Duration, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &ts); err != nil {
		return 0, false
	}
	return time.Duration(ts.Nano()), true
}
