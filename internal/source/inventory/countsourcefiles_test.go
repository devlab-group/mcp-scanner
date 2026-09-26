package inventory

import "testing"

func TestCountSourceFiles_UnreadableDirReportsTruncated(t *testing.T) {
	n, truncated := countSourceFiles("/nonexistent-path-for-countsourcefiles-test", 8)
	if n != 0 {
		t.Fatalf("want n=0 for an unreadable directory, got %d", n)
	}
	if !truncated {
		t.Fatal("want truncated=true for an unreadable directory - the caller must not mistake it for a genuinely empty one")
	}
}
