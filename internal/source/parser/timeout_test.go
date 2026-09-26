package parser

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/internal/source/language"
)

func TestParseFile_PathologicalCommentRunStaysBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("import os\n\n")
	line := "# " + strings.Repeat("x", 70) + "\n"
	for b.Len() < 300<<10 { // a few hundred KB, well under the 512 KiB file size limit
		b.WriteString(line)
	}
	src := []byte(b.String())

	// Shorten the deadline so the test does not depend on machine parsing speed
	parseDeadline = 100 * time.Millisecond
	t.Cleanup(func() { parseDeadline = ParseTimeout })

	start := time.Now()
	_, err := ParseFile(context.Background(), language.ByID(language.Python), "big.py", src)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrParseTimeout) {
		t.Fatalf("err = %v, want ErrParseTimeout", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ParseFile took %s with a %s deadline, want it stopped near the deadline", elapsed, parseDeadline)
	}
}
