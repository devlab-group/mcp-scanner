package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/runtime/sandbox"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// fixtureDeadline gives normal fixture runs enough time on a loaded host. Timeout tests use
// their own shorter deadline.
const fixtureDeadline = 60 * time.Second

func requireDocker(t *testing.T) *sandbox.Docker {
	t.Helper()
	d := sandbox.New()
	if err := d.Available(context.Background()); err != nil {
		t.Skipf("docker not available, skipping: %v", err)
	}
	return d
}

func buildFixture(t *testing.T, pkg string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Join(wd, "..", "..", "..") // internal/analyzers/runtime -> repo root
	out := filepath.Join(t.TempDir(), "fixture")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/runtime/"+pkg)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building fixture %s: %v\n%s", pkg, err, b)
	}
	return out
}

func stringSchema(propName string) map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{propName: map[string]any{"type": "string"}},
		"required":   []any{propName},
	}
}

func numberSchema(propName string) map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{propName: map[string]any{"type": "number"}},
		"required":   []any{propName},
	}
}

func TestEndToEndCommandInjectionConfirmed(t *testing.T) {
	requireDocker(t)
	bin := buildFixture(t, "cmdinjection")

	a := &Analyzer{Timeout: fixtureDeadline}
	ac := &analyzer.AnalysisContext{
		Runtime: sandbox.New(),
		Snapshot: snapshotWith(model.ToolInfo{
			Name: "run_report", Description: "runs a report", InputSchema: stringSchema("name"),
		}),
	}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: bin}, ac)

	if res.Status != model.AnalyzerCompleted && res.Status != model.AnalyzerPartial {
		t.Fatalf("unexpected status %s (errors: %+v)", res.Status, res.Errors)
	}
	found := false
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding: %v", err)
		}
		if f.RuleID == "runtime.command_injection_confirmed" && f.EvidenceLevel == model.EvidenceConfirmed {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a confirmed command_injection finding, got %+v", res.Findings)
	}
}

func TestEndToEndPathTraversalConfirmed(t *testing.T) {
	requireDocker(t)
	bin := buildFixture(t, "pathtraversal")

	a := &Analyzer{Timeout: fixtureDeadline}
	ac := &analyzer.AnalysisContext{
		Runtime: sandbox.New(),
		Snapshot: snapshotWith(model.ToolInfo{
			Name: "read_file", Description: "reads a file by path", InputSchema: stringSchema("path"),
		}),
	}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: bin}, ac)

	if res.Status != model.AnalyzerCompleted && res.Status != model.AnalyzerPartial {
		t.Fatalf("unexpected status %s (errors: %+v)", res.Status, res.Errors)
	}
	found := false
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding: %v", err)
		}
		if f.RuleID == "runtime.path_traversal_confirmed" && f.EvidenceLevel == model.EvidenceConfirmed {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a confirmed path_traversal finding, got %+v", res.Findings)
	}
}

// TestEndToEndBenignProducesNoFindings is the required negative control:
// a well-behaved target must not be flagged just for existing
func TestEndToEndBenignProducesNoFindings(t *testing.T) {
	requireDocker(t)
	bin := buildFixture(t, "benign")

	a := &Analyzer{Timeout: fixtureDeadline}
	ac := &analyzer.AnalysisContext{
		Runtime: sandbox.New(),
		Snapshot: snapshotWith(model.ToolInfo{
			Name: "greet", Description: "prints a greeting", InputSchema: stringSchema("name"),
		}),
	}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: bin}, ac)

	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("expected COMPLETED against a benign target, got %s (errors: %+v)", res.Status, res.Errors)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected zero findings against a benign target, got %+v", res.Findings)
	}
	if res.Coverage.CapabilitiesAnalyzed == 0 {
		t.Fatalf("expected the benign tool to still count as analyzed")
	}
}

func TestEndToEndUnusableSandboxImageBecomesError(t *testing.T) {
	requireDocker(t)
	bin := buildFixture(t, "benign")

	d := sandbox.New()
	d.Image = "Mcpscan-Test-INVALID-Image-Name"

	a := &Analyzer{Timeout: fixtureDeadline}
	ac := &analyzer.AnalysisContext{
		Runtime: d,
		Snapshot: snapshotWith(model.ToolInfo{
			Name: "greet", Description: "prints a greeting", InputSchema: stringSchema("name"),
		}),
	}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: bin}, ac)

	if res.Status != model.AnalyzerFailed {
		t.Fatalf("expected ERROR when the sandbox itself cannot run, got %s (findings: %+v)", res.Status, res.Findings)
	}
	if len(res.Errors) == 0 {
		t.Fatalf("expected an error message explaining the sandbox failure")
	}
	if res.Coverage.CapabilitiesAnalyzed != 0 {
		t.Fatalf("a candidate the sandbox never actually ran must not count as analyzed")
	}
}

func TestEndToEndSandboxTimeoutNeverAggregatesToSafe(t *testing.T) {
	requireDocker(t)
	bin := buildFixture(t, "sleeper")

	a := &Analyzer{Timeout: 3 * time.Second}
	ac := &analyzer.AnalysisContext{
		Runtime: sandbox.New(),
		Snapshot: snapshotWith(model.ToolInfo{
			Name: "sleep_tool", Description: "never returns", InputSchema: numberSchema("limit"),
		}),
	}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: bin}, ac)

	if res.Status == model.AnalyzerCompleted {
		t.Fatalf("a target that only ever times out must never report COMPLETED, got %s (coverage: %+v)", res.Status, res.Coverage)
	}
	if res.Coverage.CapabilitiesAnalyzed != 0 {
		t.Fatalf("a capability whose every run timed out must not count as analyzed, got %+v", res.Coverage)
	}

	scan := &model.ScanResult{Analyzers: []model.AnalyzerResult{res}}
	scan.Analyzers[0].Required = true
	scan.Aggregate(model.SeverityLow)
	if scan.Verdict != model.VerdictUnknown {
		t.Fatalf("expected UNKNOWN, got status=%s verdict=%s reasons=%v", scan.Status, scan.Verdict, scan.VerdictReasons)
	}
}

func TestEndToEndMemoryKillNeverAggregatesToSafe(t *testing.T) {
	requireDocker(t)
	bin := buildFixture(t, "memoryhog")

	a := &Analyzer{Timeout: 60 * time.Second}
	ac := &analyzer.AnalysisContext{
		Runtime: sandbox.New(),
		Snapshot: snapshotWith(model.ToolInfo{
			Name: "grow", Description: "allocates", InputSchema: numberSchema("limit"),
		}),
	}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: bin}, ac)

	if res.Status == model.AnalyzerCompleted {
		t.Fatalf("a target that is killed on every run must never report COMPLETED, got %s (coverage: %+v)", res.Status, res.Coverage)
	}
	if res.Coverage.CapabilitiesAnalyzed != 0 {
		t.Fatalf("a capability whose every run was killed must not count as analyzed, got %+v", res.Coverage)
	}

	scan := &model.ScanResult{Analyzers: []model.AnalyzerResult{res}}
	scan.Analyzers[0].Required = true
	scan.Aggregate(model.SeverityLow)
	if scan.Verdict != model.VerdictUnknown {
		t.Fatalf("expected UNKNOWN, got status=%s verdict=%s reasons=%v", scan.Status, scan.Verdict, scan.VerdictReasons)
	}
}

func TestEndToEndCrashAfterHandshakeNeverAggregatesToSafe(t *testing.T) {
	requireDocker(t)
	bin := buildFixture(t, "initonly")

	a := &Analyzer{Timeout: fixtureDeadline}
	ac := &analyzer.AnalysisContext{
		Runtime:  sandbox.New(),
		Snapshot: snapshotWith(model.ToolInfo{Name: "read_file", Description: "reads", InputSchema: stringSchema("path")}),
	}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: bin}, ac)

	if res.Coverage.CapabilitiesAnalyzed != 0 {
		t.Fatalf("a capability whose every call crashed after the handshake must not count as analyzed, got %+v", res.Coverage)
	}
	scan := &model.ScanResult{Analyzers: []model.AnalyzerResult{res}}
	scan.Analyzers[0].Required = true
	scan.Aggregate(model.SeverityLow)
	if scan.Verdict != model.VerdictUnknown {
		t.Fatalf("expected UNKNOWN, got status=%s verdict=%s reasons=%v", scan.Status, scan.Verdict, scan.VerdictReasons)
	}
}
