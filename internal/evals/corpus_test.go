package evals

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func write(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "case.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsMislabelledCases(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "vulnerable", "a"), `
id: a
category: command_injection
notes: a case that claims to be vulnerable but expects nothing
target: {kind: source, path: .}
expected: {vulnerable: false}
`)
	if _, err := Load(root); err == nil {
		t.Fatal("a vulnerable case that expects no finding must be rejected")
	}
}

func TestLoadRequiresNotes(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "benign", "b"), `
id: b
category: none
target: {kind: source, path: .}
expected: {vulnerable: false}
`)
	if _, err := Load(root); err == nil {
		t.Fatal("a case without notes must be rejected")
	}
}

func TestLoadReadsValidCase(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "vulnerable", "ci-001"), `
id: command-injection-001
category: command_injection
notes: tool argument reaches exec.Command through a helper
target: {kind: source, path: .}
expected:
  vulnerable: true
  minimum_severity: high
  rules: [taint.command-injection]
analyzers: [taint]
`)
	cases, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 {
		t.Fatalf("loaded %d cases, want 1", len(cases))
	}
	c := cases[0]
	if c.Class != ClassVulnerable {
		t.Fatalf("class = %s, want vulnerable", c.Class)
	}
	if c.ScanTarget().Kind != model.TargetSource {
		t.Fatalf("target kind = %s", c.ScanTarget().Kind)
	}
}

func TestMetrics(t *testing.T) {
	m := Metrics{TP: 9, TN: 10, FP: 1, FN: 1}
	if p := m.Precision(); p < 0.89 || p > 0.91 {
		t.Fatalf("precision = %v", p)
	}
	if r := m.Recall(); r < 0.89 || r > 0.91 {
		t.Fatalf("recall = %v", r)
	}
	if m.F1() <= 0 {
		t.Fatal("f1 should be positive")
	}
}

func TestGapCasesStayOutOfTheMatrix(t *testing.T) {
	var m Metrics
	m.Add("GAP")
	m.Add("GAP")
	if m.TN != 0 || m.TP != 0 || m.FP != 0 || m.FN != 0 {
		t.Fatalf("a blind-spot case reached the confusion matrix: %+v", m)
	}
	if m.Gaps != 2 {
		t.Fatalf("Gaps = %d, want 2", m.Gaps)
	}
	if !strings.Contains(m.String(), "blind spot") {
		t.Errorf("the summary line must say the gap cases are there: %s", m.String())
	}
}

func TestEmptyMetricsDoNotDivideByZero(t *testing.T) {
	var m Metrics
	if m.Precision() != 0 || m.Recall() != 0 || m.F1() != 0 {
		t.Fatal("empty metrics should be zero, not NaN")
	}
}
