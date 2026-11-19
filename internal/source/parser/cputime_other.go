//go:build !(darwin || linux || freebsd || netbsd || openbsd)

package parser

import "time"

// threadCPU is unavailable here; the budget falls back to wall-clock time
func threadCPU() (time.Duration, bool) { return 0, false }
