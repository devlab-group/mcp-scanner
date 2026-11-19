package osv

import (
	"os"
	"testing"
	"time"
)

// Tests that answer with 5xx would otherwise wait out the real retry delays
func TestMain(m *testing.M) {
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	os.Exit(m.Run())
}
