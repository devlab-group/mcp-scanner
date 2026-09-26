package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/revinand/mcp-scanner/internal/policy"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/pkg/scanner"
)

type fakeAnalyzer struct {
	name string
	fn   func() model.AnalyzerResult
}

func (f fakeAnalyzer) Name() string { return f.name }
func (f fakeAnalyzer) Analyze(context.Context, model.Target, *analyzer.AnalysisContext) model.AnalyzerResult {
	return f.fn()
}

func scannerWith(as ...analyzer.Analyzer) *scanner.Scanner {
	reg := analyzer.NewRegistry()
	for _, a := range as {
		reg.Register(a)
	}
	return scanner.New(reg, nil, nil)
}

func baseResolved(t *testing.T) resolved {
	t.Helper()
	return resolved{format: "summary", pol: policy.Default()}
}

// This is the exit-code mapping the task calls out to test directly:
// clean scan -> ExitOK
func TestExitCodeCleanScanIsOK(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{
			Analyzer: "a", Status: model.AnalyzerCompleted, Required: true,
			Coverage: model.Coverage{FilesDiscovered: 1, FilesParsed: 1},
		}
	}})
	r := baseResolved(t)
	code, err := runScanAndReport(context.Background(), sc, model.Target{Kind: model.TargetSource, Path: "."}, r)
	if err != nil {
		t.Fatal(err)
	}
	if code != policy.ExitOK {
		t.Fatalf("code = %d, want ExitOK", code)
	}
}

// A blocking finding on an otherwise clean, completed scan -> ExitPolicyFail
func TestExitCodePolicyFail(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{
			Analyzer: "a", Status: model.AnalyzerCompleted, Required: true,
			Coverage: model.Coverage{FilesDiscovered: 1, FilesParsed: 1},
			Findings: []model.Finding{{
				RuleID: "r", Category: "c", Title: "t", Severity: model.SeverityHigh, Confidence: 0.9,
				EvidenceLevel: model.EvidenceStatic, Description: "d", Analyzer: "a",
				Evidence: []model.Evidence{{Level: model.EvidenceStatic}},
			}},
		}
	}})
	r := baseResolved(t)
	r.pol.FailOn = model.SeverityLow
	code, err := runScanAndReport(context.Background(), sc, model.Target{Kind: model.TargetSource, Path: "."}, r)
	if err != nil {
		t.Fatal(err)
	}
	if code != policy.ExitPolicyFail {
		t.Fatalf("code = %d, want ExitPolicyFail", code)
	}
}

// A required analyzer that errors leaves the scan status ERROR/UNKNOWN,
// which FailOnUnknown (on by default) maps to ExitIncomplete
func TestExitCodeIncompleteScan(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{Analyzer: "a", Status: model.AnalyzerFailed, Required: true}
	}})
	r := baseResolved(t)
	code, err := runScanAndReport(context.Background(), sc, model.Target{Kind: model.TargetSource, Path: "."}, r)
	if err != nil {
		t.Fatal(err)
	}
	if code != policy.ExitIncomplete {
		t.Fatalf("code = %d, want ExitIncomplete", code)
	}
}

// Asking for an analyzer that is not registered is a usage error, not a
// scan outcome: it must never reach policy at all
func TestExitCodeUsageErrorOnUnknownAnalyzer(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{Analyzer: "a", Status: model.AnalyzerCompleted, Required: true}
	}})
	r := baseResolved(t)
	r.sopts.Analyzers = []string{"does-not-exist"}
	code, err := runScanAndReport(context.Background(), sc, model.Target{Kind: model.TargetSource, Path: "."}, r)
	if err == nil {
		t.Fatal("expected an error for an unknown analyzer name")
	}
	if code != policy.ExitUsage {
		t.Fatalf("code = %d, want ExitUsage", code)
	}
}

// A report that cannot be written (bad output path) is an internal
// failure, distinct from every scan-outcome code above
func TestExitCodeInternalFailureOnBadOutputPath(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{Analyzer: "a", Status: model.AnalyzerCompleted, Required: true}
	}})
	r := baseResolved(t)
	r.output = filepath.Join(t.TempDir(), "does", "not", "exist", "report.json")
	code, err := runScanAndReport(context.Background(), sc, model.Target{Kind: model.TargetSource, Path: "."}, r)
	if err == nil {
		t.Fatal("expected an error writing to a nonexistent directory")
	}
	if code != policy.ExitInternal {
		t.Fatalf("code = %d, want ExitInternal", code)
	}
}

func TestOpenOutputWritesToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	w, closeFn, err := openOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("hello"))
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestOpenOutputRestrictsFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	_, closeFn, err := openOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("report file mode = %o, want 0600", perm)
	}
}
