package main

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAnalyzerListingsNameEveryKnownAnalyzer(t *testing.T) {
	for _, details := range []bool{false, true} {
		var buf bytes.Buffer
		printAnalyzers(&buf, details)
		for _, name := range knownAnalyzerNames {
			if !strings.Contains(buf.String(), name) {
				t.Errorf("details=%v: listing does not mention %q", details, name)
			}
		}
	}
}

func TestAnalyzerDetailsWrap(t *testing.T) {
	var buf bytes.Buffer
	printAnalyzers(&buf, true)
	for i, line := range strings.Split(buf.String(), "\n") {
		if utf8.RuneCountInString(line) <= wrapWidth {
			continue
		}
		if len(strings.Fields(strings.TrimLeft(line, " -"))) > 1 {
			t.Errorf("line %d is %d columns wide and could have been folded: %s",
				i+1, utf8.RuneCountInString(line), line)
		}
	}
}

func TestWrapIndent(t *testing.T) {
	got := wrapIndent(strings.Repeat("word ", 40), "  - ", "    ")
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("40 words folded to %d line(s): %q", len(lines), got)
	}
	if !strings.HasPrefix(lines[0], "  - word") {
		t.Errorf("first line does not carry the bullet: %q", lines[0])
	}
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "    word") {
			t.Errorf("continuation line is not hanging-indented: %q", l)
		}
	}
}
