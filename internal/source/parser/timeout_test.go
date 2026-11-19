package parser

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

func TestParseFile_PathologicalCommentRunStaysBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("import os\n\n")
	line := "# " + strings.Repeat("x", 70) + "\n"
	for b.Len() < 300<<10 { // a few hundred KB, well under the 512 KiB file size limit
		b.WriteString(line)
	}
	src := []byte(b.String())

	// A short deadline keeps the test independent of machine parsing speed
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

// Nested Java methods parse quickly but require expensive enclosing-class
// lookups during extraction. That work must share the parse deadline.
func TestParseFile_ExtractionPastTheDeadlineIsATimeout(t *testing.T) {
	const depth = 4000
	src := []byte(strings.Repeat("class A { void f() { ", depth) + strings.Repeat("} }", depth) + "\n")
	adapter := language.ByID(language.Java)

	start := time.Now()
	tree, err := ParseTree(context.Background(), adapter, src)
	if err != nil {
		t.Fatalf("ParseTree: %v", err)
	}
	parse := time.Since(start)
	start = time.Now()
	tree.Close()
	release := time.Since(start)

	// Allow the measured parse time plus one second for extraction
	parseDeadline = parse + time.Second
	t.Cleanup(func() { parseDeadline = ParseTimeout })

	start = time.Now()
	_, err = ParseFile(context.Background(), adapter, "A.java", src)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrParseTimeout) {
		t.Fatalf("err = %v, want ErrParseTimeout", err)
	}
	// Allow measured tree cleanup time plus a margin for machine and race-detector
	// variation; continued extraction after the deadline should exceed this allowance.
	if over, limit := elapsed-parseDeadline, 2*release+500*time.Millisecond; over > limit {
		t.Fatalf("ParseFile ran %s past its %s deadline, want at most %s (twice the %s it takes to free the tree, plus 500ms)",
			over, parseDeadline, limit, release)
	}
}

// Check fillAncestry's budget directly because tree cleanup can obscure the
// duration of its linear walk in an end-to-end timing assertion
func TestFillAncestry_StopsWhenTheBudgetIsSpent(t *testing.T) {
	src := []byte("x = " + strings.Repeat("f(", 5000) + "0" + strings.Repeat(")", 5000) + ";\n")
	adapter := language.ByID(language.JavaScript)
	tree, err := ParseTree(context.Background(), adapter, src)
	if err != nil {
		t.Fatalf("ParseTree: %v", err)
	}
	defer tree.Close()

	if !fillAncestry(newBudget(), adapter.Grammar.ForKinds, tree.RootNode(), map[uintptr]callAncestry{}) {
		t.Error("walk with time left reported the budget spent")
	}
	spent := budget{wallEnd: time.Now().Add(-time.Second)}
	if fillAncestry(spent, adapter.Grammar.ForKinds, tree.RootNode(), map[uintptr]callAncestry{}) {
		t.Error("walk of a tree with thousands of nodes finished on a spent budget")
	}
}

// Reject excessive tree depth before queries run so tree-sitter's 16-bit match
// depth cannot turn incomplete matches into an apparently complete result
func TestParseFile_TreePastTheDepthLimitIsALimit(t *testing.T) {
	const depth = 20000 // two levels each, past MaxTreeDepth
	src := []byte("x = " + strings.Repeat("f(", depth) + "0" + strings.Repeat(")", depth) + ";\n")
	res, err := ParseFile(context.Background(), language.ByID(language.JavaScript), "a.js", src)
	if !errors.Is(err, ErrDepthLimit) {
		t.Fatalf("err = %v, want ErrDepthLimit", err)
	}
	if res != nil {
		t.Errorf("got a result with %d calls alongside the error, want none", len(res.Calls))
	}
	if _, err := ParseTree(context.Background(), language.ByID(language.JavaScript), src); !errors.Is(err, ErrDepthLimit) {
		t.Errorf("ParseTree err = %v, want ErrDepthLimit", err)
	}
}

// The budget counts the CPU time of the thread doing the work: time spent waiting - a loaded
// machine, a sleep - does not use it up, while the same time spent computing does. That is what
// keeps a scan's result the same on a busy host.
func TestBudgetCountsCPUTimeNotWaiting(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, ok := threadCPU(); !ok {
		t.Skip("thread CPU time is not available on this platform; the budget uses wall time here")
	}
	parseDeadline = 50 * time.Millisecond
	t.Cleanup(func() { parseDeadline = ParseTimeout })

	waiting := newBudget()
	time.Sleep(200 * time.Millisecond)
	if waiting.spent() {
		t.Error("200ms of sleeping used up a 50ms CPU budget")
	}

	working := newBudget()
	x := 0
	for start := time.Now(); time.Since(start) < 200*time.Millisecond; {
		x++
	}
	_ = x
	if !working.spent() {
		t.Error("200ms of computing did not use up a 50ms CPU budget")
	}
}
