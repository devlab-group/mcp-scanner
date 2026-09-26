// Package conventions holds the checks that keep the repository readable
// as one piece of work rather than as a record of how it was built
package conventions

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var processReferences = regexp.MustCompile(

	`\b(?:HIGH|MEDIUM|LOW|INFO|CRITICAL)-[0-9]+[a-z]?\b` +
		`|\b(?:second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|eleventh|twelfth|thirteenth)\s+review\b` +
		`|\baudit\s+[0-9]+\b` +
		`|\bCLAUDE\.md\b` +
		`|\b(?:the|an independent|a security) review(?:er)?\b` +
		`|\bthe reviewer\b`)

func TestNoInternalProcessReferences(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("not a git checkout, nothing to walk: %v", err)
	}

	for rel := range strings.SplitSeq(strings.TrimRight(string(out), "\x00"), "\x00") {
		if rel == "" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // a submodule entry or a file removed since ls-files ran
		}
		for i, line := range strings.Split(string(body), "\n") {
			if m := processReferences.FindString(line); m != "" {
				t.Errorf("%s:%d refers to %q, which is not in this repository: say what the case is instead\n\t%s",
					rel, i+1, m, strings.TrimSpace(line))
			}
		}
	}
}

func TestProcessReferencePatternMatchesWhatItClaims(t *testing.T) {
	for _, s := range []string{
		"HIGH" + "-1",
		"MEDIUM" + "-12",
		"CRITICAL" + "-1a",
		"the ninth " + "review",
		"audit " + "11",
		"CLAUDE" + ".md",
		"the " + "reviewer",
	} {
		if !processReferences.MatchString(s) {
			t.Errorf("%q is the shape this guard exists to catch and the pattern misses it", s)
		}
	}

	for _, s := range []string{
		"HIGH", "MEDIUM", "LOW", "INFO", "CRITICAL",
		"model.SeverityHigh", "severity: CRITICAL",
		"the fixed, reviewed state", "reviewing the scan output",
	} {
		if processReferences.MatchString(s) {
			t.Errorf("%q is ordinary vocabulary and the pattern flags it", s)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	return strings.TrimSpace(string(out))
}
