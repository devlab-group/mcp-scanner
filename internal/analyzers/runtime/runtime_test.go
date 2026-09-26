package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/internal/testutil"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func staticCommand(t *testing.T, base string) string {
	t.Helper()
	bin := buildFixture(t, "benign")
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("reading built fixture: %v", err)
	}
	command := filepath.Join(t.TempDir(), base)
	if err := os.WriteFile(command, data, 0o755); err != nil {
		t.Fatalf("staging %q: %v", command, err)
	}
	return command
}

// fakeExecutor is a minimal analyzer.RuntimeExecutor double, so every
// gating branch and the confirmation logic can be tested without Docker
type fakeExecutor struct {
	availErr error
	run      func(req analyzer.RuntimeRequest) analyzer.RuntimeResult
	calls    int
}

func (f *fakeExecutor) Available(ctx context.Context) error { return f.availErr }
func (f *fakeExecutor) Execute(ctx context.Context, req analyzer.RuntimeRequest) analyzer.RuntimeResult {
	f.calls++
	if f.run != nil {
		return f.run(req)
	}
	return analyzer.RuntimeResult{Started: true, Answered: true}
}

func snapshotWith(tool model.ToolInfo) *model.Snapshot {
	return &model.Snapshot{Tools: []model.ToolInfo{tool}}
}

func pathTool() model.ToolInfo {
	return model.ToolInfo{
		Name:        "read_file",
		Description: "reads a file by path",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"path": map[string]any{"type": "string"}},
			"required":   []any{"path"},
		},
	}
}

func TestAnalyzeSkipsWhenRuntimeNil(t *testing.T) {
	a := New()
	ac := &analyzer.AnalysisContext{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: "/bin/true"}, ac)
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("expected SKIPPED, got %s", res.Status)
	}
}

func TestAnalyzeUnavailableWhenRuntimeErrors(t *testing.T) {
	a := New()
	fe := &fakeExecutor{availErr: errors.New("docker daemon not reachable")}
	ac := &analyzer.AnalysisContext{Runtime: fe}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: "/bin/true"}, ac)
	if res.Status != model.AnalyzerUnavailable {
		t.Fatalf("expected UNAVAILABLE, got %s", res.Status)
	}
	if len(res.Errors) == 0 || res.Errors[0].Message != "docker daemon not reachable" {
		t.Fatalf("expected the Available() error to be carried through, got %+v", res.Errors)
	}
	if fe.calls != 0 {
		t.Fatalf("Execute must never be called when Available fails")
	}
}

func TestAnalyzeSkipsRemoteTarget(t *testing.T) {
	a := New()
	fe := &fakeExecutor{}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetRemote, URL: "https://example.invalid"}, ac)
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("expected SKIPPED for a remote target, got %s", res.Status)
	}
	if fe.calls != 0 {
		t.Fatalf("must never sandbox-execute against a remote target")
	}
}

func TestAnalyzeSkipsUnsupportedKind(t *testing.T) {
	a := New()
	fe := &fakeExecutor{}
	ac := &analyzer.AnalysisContext{Runtime: fe}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStatic, Path: "/tmp/x.json"}, ac)
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("expected SKIPPED for a static target, got %s", res.Status)
	}
}

func TestAnalyzeSkipsWithoutRunnableCommand(t *testing.T) {
	a := New()
	fe := &fakeExecutor{}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}

	for _, tgt := range []model.Target{
		{Kind: model.TargetStdio, Command: ""},
		{Kind: model.TargetStdio, Command: "relative/path"},
	} {
		res := a.Analyze(context.Background(), tgt, ac)
		if res.Status != model.AnalyzerSkipped {
			t.Fatalf("target %+v: expected SKIPPED, got %s", tgt, res.Status)
		}
	}
}

func TestAnalyzeSkipsInterpretedCommands(t *testing.T) {
	a := New()
	for _, command := range []string{
		"/usr/bin/python3", "/usr/bin/python3.11", "/usr/local/bin/node",
		"/usr/bin/npx", "/bin/bash", "/usr/bin/ruby", "/usr/bin/php",
	} {
		fe := &fakeExecutor{}
		ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
		res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)
		if res.Status != model.AnalyzerSkipped {
			t.Fatalf("command %q: expected SKIPPED, got %s", command, res.Status)
		}
		if len(res.Warnings) == 0 {
			t.Fatalf("command %q: expected a skip reason", command)
		}
		if fe.calls != 0 {
			t.Fatalf("command %q: must never attempt to sandbox an interpreter", command)
		}
	}
}

// TestAnalyzeRunsCompiledCommands is the negative control: an ordinary
// compiled binary's basename must never trip the interpreter check
func TestAnalyzeRunsCompiledCommands(t *testing.T) {
	a := New()
	for _, base := range []string{"mcp-server", "server-bin", "redis-server"} {
		command := staticCommand(t, base)
		fe := &fakeExecutor{}
		ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
		res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)
		if res.Status == model.AnalyzerSkipped {
			t.Fatalf("command %q: must not be mistaken for an interpreter or an unrunnable binary (warnings: %v)", command, res.Warnings)
		}
		if fe.calls == 0 {
			t.Fatalf("command %q: expected the sandbox to actually run", command)
		}
	}
}

func TestAnalyzeSendsConfiguredTimeoutOnEveryRequest(t *testing.T) {
	command := staticCommand(t, "mcp-server")

	var got []time.Duration
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		got = append(got, req.Timeout)
		return analyzer.RuntimeResult{Started: true, Answered: true}
	}}
	a := New()
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
	a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)
	if len(got) == 0 {
		t.Fatal("expected the sandbox to actually run")
	}
	for _, d := range got {
		if d != 0 {
			t.Fatalf("RuntimeRequest.Timeout = %v with no Analyzer.Timeout configured, want 0 (let the executor's own default apply)", d)
		}
	}

	got = nil
	fe2 := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		got = append(got, req.Timeout)
		return analyzer.RuntimeResult{Started: true, Answered: true}
	}}
	a2 := &Analyzer{Timeout: 7 * time.Second}
	ac2 := &analyzer.AnalysisContext{Runtime: fe2, Snapshot: snapshotWith(pathTool())}
	a2.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac2)
	if len(got) == 0 {
		t.Fatal("expected the sandbox to actually run")
	}
	for _, d := range got {
		if d != 7*time.Second {
			t.Fatalf("RuntimeRequest.Timeout = %v, want the configured 7s", d)
		}
	}
}

func TestDynamicLinkLimitation(t *testing.T) {
	if reason, limited := dynamicLinkLimitation(staticCommand(t, "static")); limited {
		t.Fatalf("a statically linked fixture must not be limited, got reason %q", reason)
	}

	bin := testutil.DynamicSystemBinary(t)
	reason, limited := dynamicLinkLimitation(bin)
	if !limited {
		t.Fatalf("expected %q to be reported as dynamically linked", bin)
	}
	if !strings.Contains(reason, "dynamically linked") {
		t.Fatalf("expected the reason to mention dynamic linking, got %q", reason)
	}

	reason, limited = dynamicLinkLimitation(filepath.Join(t.TempDir(), "does-not-exist"))
	if !limited {
		t.Fatalf("expected a missing file to be treated as unrunnable rather than assumed safe")
	}
	if reason == "" {
		t.Fatalf("expected a reason for the unreadable file")
	}
}

func TestAnalyzeSkipsDynamicallyLinkedEntrypoint(t *testing.T) {
	a := New()
	fe := &fakeExecutor{}
	command := testutil.DynamicSystemBinary(t)
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("expected SKIPPED, got %s", res.Status)
	}
	if len(res.Warnings) == 0 || !strings.Contains(res.Warnings[0], "dynamically linked") {
		t.Fatalf("expected a skip reason mentioning dynamic linking, got %v", res.Warnings)
	}
	if fe.calls != 0 {
		t.Fatalf("must never attempt to sandbox a dynamically linked entrypoint")
	}
}

func TestAnalyzeSkipsWhenNoCandidates(t *testing.T) {
	a := New()
	fe := &fakeExecutor{}
	ac := &analyzer.AnalysisContext{Runtime: fe} // no Snapshot, no Artifacts
	command := staticCommand(t, "no-candidates")
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("expected SKIPPED with nothing to confirm, got %s", res.Status)
	}
	if fe.calls != 0 {
		t.Fatalf("must never sandbox-execute with no candidates")
	}
}

func TestAnalyzeConfirmsCanaryHit(t *testing.T) {
	a := New()
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		// The canary the traversal payload actually aimed at: a hit on
		// some other canary is exposure, not proof this payload worked
		id := ""
		for _, c := range req.Canaries {
			if c.Path != "" {
				id = c.ID
				break
			}
		}
		return analyzer.RuntimeResult{
			Started:      true,
			Answered:     true,
			Observations: []analyzer.Observation{{Kind: "canary_hit", CanaryID: id, Detail: "canary value appeared in output"}},
		}
	}}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
	command := staticCommand(t, "canary-hit")
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("expected COMPLETED, got %s", res.Status)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected at least one finding from a canary_hit observation")
	}
	found := false
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding: %v", err)
		}
		if f.EvidenceLevel != model.EvidenceConfirmed {
			t.Fatalf("expected CONFIRMED evidence, got %s", f.EvidenceLevel)
		}
		if f.RuleID == "runtime.path_traversal_confirmed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a path_traversal_confirmed finding among %+v", res.Findings)
	}
}

func TestAnalyzeNoFindingWithoutObservation(t *testing.T) {
	a := New()
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		return analyzer.RuntimeResult{Started: true, Answered: true} // no observations at all
	}}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
	command := staticCommand(t, "no-observation")
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("expected COMPLETED, got %s", res.Status)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected zero findings with no observation, got %+v", res.Findings)
	}
	if res.Coverage.CapabilitiesAnalyzed == 0 {
		t.Fatalf("a clean run must still count as analyzed, not skipped")
	}
	if gaps := res.Coverage.Gaps(); len(gaps) != 0 {
		t.Fatalf("coverage does not add up: %v", gaps)
	}
}

func TestAnalyzeIgnoresMereReflection(t *testing.T) {
	a := New()
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {

		return analyzer.RuntimeResult{Started: true, Answered: true, Stdout: "error: bad path " + req.Arguments["path"].(string)}
	}}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
	command := staticCommand(t, "reflection")
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("expected COMPLETED, got %s (must actually run to prove reflection is ignored)", res.Status)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("mere reflection in stdout must not produce a finding, got %+v", res.Findings)
	}
}

func TestAnalyzeSandboxErrorBecomesError(t *testing.T) {
	a := New()
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		return analyzer.RuntimeResult{Err: errors.New("docker: container failed to start")}
	}}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
	command := staticCommand(t, "sandbox-error")
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

	if res.Status != model.AnalyzerFailed {
		t.Fatalf("expected ERROR status when the sandbox itself fails, got %s", res.Status)
	}
	if len(res.Errors) == 0 {
		t.Fatalf("expected an error message")
	}
}

// TestAnalyzePartialWhenSchemaUnfuzzable exercises the "3 of 11, PARTIAL"
// shape: one tool with a fuzzable schema, one without, and both accounted
// for in coverage
func TestAnalyzePartialWhenSchemaUnfuzzable(t *testing.T) {
	a := New()
	fe := &fakeExecutor{}
	unfuzzable := model.ToolInfo{
		Name: "toggle",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"enabled": map[string]any{"type": "boolean"}},
		},
	}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: &model.Snapshot{Tools: []model.ToolInfo{pathTool(), unfuzzable}}}
	command := staticCommand(t, "partial")
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

	if res.Status != model.AnalyzerPartial {
		t.Fatalf("expected PARTIAL, got %s (skip reasons: %v)", res.Status, res.Coverage.SkipReasons)
	}
	if res.Coverage.CapabilitiesAnalyzed != 1 || res.Coverage.CapabilitiesSkipped != 1 {
		t.Fatalf("expected 1 analyzed and 1 skipped, got %+v", res.Coverage)
	}
	if len(res.Coverage.SkipReasons) == 0 {
		t.Fatalf("skip must carry a reason")
	}
	if gaps := res.Coverage.Gaps(); len(gaps) != 0 {
		t.Fatalf("coverage does not add up: %v", gaps)
	}
}

func TestPredictableCandidateOrdering(t *testing.T) {
	ac := &analyzer.AnalysisContext{Snapshot: &model.Snapshot{Tools: []model.ToolInfo{
		{Name: "get_time", Description: "returns the current time"},
		{Name: "run_shell_command", Description: "executes a shell command"},
	}}}
	cands := discoverCandidates(ac)
	if len(cands) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(cands))
	}
	if cands[0].tool.Name != "run_shell_command" {
		t.Fatalf("expected the command-shaped tool to be prioritized first, got %+v", cands)
	}
}

func numberTool() model.ToolInfo {
	return model.ToolInfo{
		Name:        "set_limit",
		Description: "sets a numeric limit",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"limit": map[string]any{"type": "number"}},
			"required":   []any{"limit"},
		},
	}
}

// A started run that times out still left its payload unexamined. It must not increment analyzed
// coverage or allow a hanging target to aggregate to SAFE.
func TestAnalyzeTimedOutRunIsNotCountedAsAnalyzed(t *testing.T) {
	a := New()
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		return analyzer.RuntimeResult{Started: true, Answered: true, TimedOut: true, ExitCode: -1}
	}}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(numberTool())}
	command := staticCommand(t, "timed-out")
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

	if res.Status == model.AnalyzerCompleted {
		t.Fatalf("a timed-out run must never report COMPLETED, got %s (coverage: %+v)", res.Status, res.Coverage)
	}
	if res.Coverage.CapabilitiesAnalyzed != 0 {
		t.Fatalf("a capability whose only run timed out must not count as analyzed, got %+v", res.Coverage)
	}
	if res.Coverage.CapabilitiesSkipped == 0 {
		t.Fatalf("expected the timed-out capability to be accounted as skipped, got %+v", res.Coverage)
	}
	if len(res.Coverage.SkipReasons) == 0 {
		t.Fatalf("expected a skip reason explaining the timeout")
	}

	scan := &model.ScanResult{Analyzers: []model.AnalyzerResult{res}}
	scan.Analyzers[0].Required = true
	scan.Aggregate(model.SeverityLow)
	if scan.Verdict == model.VerdictSafe {
		t.Fatalf("a scan with a timed-out sandbox run must never aggregate to SAFE, got status=%s verdict=%s reasons=%v",
			scan.Status, scan.Verdict, scan.VerdictReasons)
	}
}

func TestAnalyzeOneGoodCaseThenATimeoutDoesNotCountAsAnalyzed(t *testing.T) {
	a := New()
	calls := 0
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		calls++
		if calls == 1 {
			return analyzer.RuntimeResult{Started: true, Answered: true}
		}
		return analyzer.RuntimeResult{Started: true, Answered: true, TimedOut: true}
	}}
	// pathTool's string property is fuzzed with several payload classes, so
	// this reliably produces more than one case for the same capability
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
	command := staticCommand(t, "mixed-outcome")
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

	if calls < 2 {
		t.Fatalf("expected at least 2 fuzz cases for a fuzzable string property, got %d", calls)
	}
	if res.Coverage.CapabilitiesAnalyzed != 0 {
		t.Fatalf("one good case followed by one timeout must not count the capability as analyzed, got %+v", res.Coverage)
	}
	if res.Coverage.CapabilitiesSkipped == 0 {
		t.Fatalf("expected the capability to be accounted as skipped instead, got %+v", res.Coverage)
	}
}

func TestAnalyzeExecutorContractFailureBecomesError(t *testing.T) {
	a := New()
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		return analyzer.RuntimeResult{} // Started false, Err nil, TimedOut false
	}}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(numberTool())}
	command := staticCommand(t, "contract-violation")
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

	if res.Status != model.AnalyzerFailed {
		t.Fatalf("expected ERROR when the executor reports neither Started nor Err, got %s", res.Status)
	}
	if len(res.Errors) == 0 {
		t.Fatalf("expected an error message explaining the contract violation")
	}
	if res.Coverage.CapabilitiesAnalyzed != 0 {
		t.Fatalf("must not count as analyzed when the executor never actually ran anything, got %+v", res.Coverage)
	}

	scan := &model.ScanResult{Analyzers: []model.AnalyzerResult{res}}
	scan.Aggregate(model.SeverityLow)
	if scan.Verdict == model.VerdictSafe {
		t.Fatalf("must never aggregate to SAFE, got status=%s verdict=%s", scan.Status, scan.Verdict)
	}
}

// External kills and crashes can report Started with no executor error. Unless an observation
// already confirmed behavior, those exits cannot count as completed analysis.
func TestAnalyzeKilledRunIsNotCountedAsAnalyzed(t *testing.T) {
	for _, exit := range []int{137, 139, -1} {
		t.Run(fmt.Sprint(exit), func(t *testing.T) {
			fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
				return analyzer.RuntimeResult{
					Started:  true,
					Answered: true,
					ExitCode: exit,
					Observations: []analyzer.Observation{{
						Kind:   "process_exec",
						Detail: "sandbox entrypoint executed, exit_code=" + strconv.Itoa(exit),
					}},
				}
			}}
			ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(numberTool())}
			command := staticCommand(t, "killed")
			res := New().Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

			if res.Status == model.AnalyzerCompleted {
				t.Fatalf("a killed run must never report COMPLETED, got %s (coverage: %+v)", res.Status, res.Coverage)
			}
			if res.Coverage.CapabilitiesAnalyzed != 0 {
				t.Fatalf("a capability whose only run was killed must not count as analyzed, got %+v", res.Coverage)
			}
			if res.Coverage.CapabilitiesSkipped == 0 || len(res.Coverage.SkipReasons) == 0 {
				t.Fatalf("expected the killed capability accounted as skipped with a reason, got %+v", res.Coverage)
			}
			if !strings.Contains(res.Coverage.SkipReasons[0], strconv.Itoa(exit)) {
				t.Fatalf("expected the skip reason to name the exit, got %q", res.Coverage.SkipReasons[0])
			}

			scan := &model.ScanResult{Analyzers: []model.AnalyzerResult{res}}
			scan.Analyzers[0].Required = true
			scan.Aggregate(model.SeverityLow)
			if scan.Verdict == model.VerdictSafe {
				t.Fatalf("a scan whose only sandbox run was killed must never aggregate to SAFE, got status=%s verdict=%s reasons=%v",
					scan.Status, scan.Verdict, scan.VerdictReasons)
			}
		})
	}
}

func TestAnalyzeKilledRunThatConfirmedSomethingStillCounts(t *testing.T) {
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		return analyzer.RuntimeResult{
			Started:  true,
			Answered: true,
			ExitCode: 139,
			Observations: []analyzer.Observation{
				{Kind: "process_exec", Detail: "sandbox entrypoint executed, exit_code=139"},
				{Kind: "canary_hit", CanaryID: "c1", Detail: "canary value (file) appeared in sandbox output"},
			},
		}
	}}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(numberTool())}
	command := staticCommand(t, "killed-but-confirmed")
	res := New().Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

	if len(res.Findings) == 0 {
		t.Fatalf("expected the canary hit to still produce a finding, got %+v", res)
	}
	if res.Coverage.CapabilitiesAnalyzed != 1 {
		t.Fatalf("a run that confirmed something was analyzed, got %+v", res.Coverage)
	}
}

func TestAnalyzeUnansweredRunIsNotCountedAsAnalyzed(t *testing.T) {
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		return analyzer.RuntimeResult{
			Started:  true,
			Answered: false,
			ExitCode: 1,
			Stderr:   "config not found",
		}
	}}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(numberTool())}
	command := staticCommand(t, "never-answered")
	res := New().Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

	if res.Status == model.AnalyzerCompleted {
		t.Fatalf("a run the target never answered must not report COMPLETED, got %s", res.Status)
	}
	if res.Coverage.CapabilitiesAnalyzed != 0 || res.Coverage.CapabilitiesSkipped != 1 {
		t.Fatalf("want 0 analyzed and 1 skipped, got %+v", res.Coverage)
	}
	if len(res.Coverage.SkipReasons) == 0 || !strings.Contains(res.Coverage.SkipReasons[0], "tools/call response") {
		t.Fatalf("expected a skip reason naming the unanswered call, got %+v", res.Coverage.SkipReasons)
	}
}

func TestAnalyzeUnaimedCanaryHitIsExposureNotTheRunningClass(t *testing.T) {
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		return analyzer.RuntimeResult{
			Started:  true,
			Answered: true,
			Observations: []analyzer.Observation{
				{Kind: "canary_hit", CanaryID: "env-1", Detail: "canary value (env) appeared in sandbox output"},
			},
		}
	}}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(model.ToolInfo{
		Name:        "describe",
		Description: "describes a thing",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"what": map[string]any{"type": "string"}},
			"required":   []any{"what"},
		},
	})}
	command := staticCommand(t, "env-printer")
	res := New().Analyze(context.Background(), model.Target{Kind: model.TargetStdio, Command: command}, ac)

	if len(res.Findings) != 1 {
		t.Fatalf("one leaky tool is one fact about that tool, want 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].RuleID != exposureRuleID {
		t.Fatalf("rule = %s, want %s: no payload aimed at that canary", res.Findings[0].RuleID, exposureRuleID)
	}
}

// Cancellation after the first fuzz case leaves the analyzer result PARTIAL
func TestAnalyzeCutOffAfterTheFirstCaseIsPartial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fe := &fakeExecutor{run: func(req analyzer.RuntimeRequest) analyzer.RuntimeResult {
		cancel()
		return analyzer.RuntimeResult{Started: true, Answered: true}
	}}
	ac := &analyzer.AnalysisContext{Runtime: fe, Snapshot: snapshotWith(pathTool())}
	res := New().Analyze(ctx, model.Target{Kind: model.TargetStdio, Command: staticCommand(t, "cut-off")}, ac)
	if fe.calls != 1 {
		t.Fatalf("calls = %d, want the run to stop after the first case", fe.calls)
	}
	if res.Status != model.AnalyzerPartial {
		t.Fatalf("status = %s, want PARTIAL after 1 of several cases", res.Status)
	}
}
