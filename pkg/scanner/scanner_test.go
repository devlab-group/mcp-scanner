package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

type fake struct {
	name string
	fn   func(context.Context) model.AnalyzerResult
}

func (f fake) Name() string { return f.name }
func (f fake) Analyze(ctx context.Context, _ model.Target, _ *analyzer.AnalysisContext) model.AnalyzerResult {
	return f.fn(ctx)
}

// okResult is a healthy analyzer's result: completed, and reporting that it
// actually examined something. A zero Coverage is itself a gap.
func okResult(name string) model.AnalyzerResult {
	return model.AnalyzerResult{
		Analyzer: name, Status: model.AnalyzerCompleted,
		Coverage: model.Coverage{FilesDiscovered: 1, FilesParsed: 1},
	}
}

func srcTarget() model.Target { return model.Target{Kind: model.TargetSource, Path: "."} }

func newScanner(as ...analyzer.Analyzer) *Scanner {
	reg := analyzer.NewRegistry()
	for _, a := range as {
		reg.Register(a)
	}
	return New(reg, nil, nil)
}

func TestPanicBecomesErrorNotSafe(t *testing.T) {
	s := newScanner(fake{"boom", func(context.Context) model.AnalyzerResult { panic("kaboom") }})
	res, err := s.Scan(context.Background(), srcTarget(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != model.VerdictUnknown || res.Status != model.StatusError {
		t.Fatalf("got %s/%s, want ERROR/UNKNOWN", res.Status, res.Verdict)
	}
}

func TestEmptyResultBecomesError(t *testing.T) {
	s := newScanner(fake{"lazy", func(context.Context) model.AnalyzerResult { return model.AnalyzerResult{} }})
	res, _ := s.Scan(context.Background(), srcTarget(), Options{})
	// A zero result is a broken analyzer, not a valid skipped result
	if res.Status != model.StatusError || res.Verdict != model.VerdictUnknown {
		t.Fatalf("an analyzer returning a zero result produced %s/%s", res.Status, res.Verdict)
	}
}

func TestAnalyzerTimeoutDowngradesToPartial(t *testing.T) {
	s := newScanner(fake{"slow", func(ctx context.Context) model.AnalyzerResult {
		<-ctx.Done()
		// The analyzer claims success despite being cancelled; the scanner
		// must not believe it
		return okResult("slow")
	}})
	res, _ := s.Scan(context.Background(), srcTarget(), Options{AnalyzerTimeout: 20 * time.Millisecond})
	if res.Status != model.StatusPartial || res.Verdict != model.VerdictUnknown {
		t.Fatalf("got %s/%s, want PARTIAL/UNKNOWN", res.Status, res.Verdict)
	}
}

func TestUnknownAnalyzerIsAnError(t *testing.T) {
	s := newScanner(fake{"real", func(context.Context) model.AnalyzerResult {
		return okResult("real")
	}})
	if _, err := s.Scan(context.Background(), srcTarget(), Options{Analyzers: []string{"nope"}}); err == nil {
		t.Fatal("asking for an analyzer that is not in the build must fail loudly")
	}
}

type failingPreparer struct{}

func (failingPreparer) Prepare(context.Context, model.Target) (*analyzer.AnalysisContext, func(), error) {
	return nil, nil, errors.New("connection refused")
}

func TestDiscoveryFailureFailsEveryAnalyzer(t *testing.T) {
	reg := analyzer.NewRegistry()
	reg.Register(fake{"proto", func(context.Context) model.AnalyzerResult {
		t.Error("analyzer ran despite discovery failing")
		return model.AnalyzerResult{Analyzer: "proto", Status: model.AnalyzerCompleted}
	}})
	s := New(reg, failingPreparer{}, nil)
	res, _ := s.Scan(context.Background(), model.Target{Kind: model.TargetRemote, URL: "http://127.0.0.1:1/mcp"}, Options{})
	if res.Status != model.StatusError || res.Verdict != model.VerdictUnknown {
		t.Fatalf("got %s/%s, want ERROR/UNKNOWN", res.Status, res.Verdict)
	}
}

type kindLimited struct{ fake }

func (kindLimited) AppliesTo(k model.TargetKind) bool { return k == model.TargetRemote }

func TestDiscoveryFailureStillListsInapplicableAnalyzers(t *testing.T) {
	reg := analyzer.NewRegistry()
	reg.Register(fake{"proto", func(context.Context) model.AnalyzerResult {
		t.Error("analyzer ran despite discovery failing")
		return model.AnalyzerResult{Analyzer: "proto", Status: model.AnalyzerCompleted}
	}})
	reg.Register(kindLimited{fake{"remote-only", func(context.Context) model.AnalyzerResult {
		t.Error("remote-only analyzer ran despite discovery failing")
		return model.AnalyzerResult{}
	}}})
	s := New(reg, failingPreparer{}, nil)
	res, _ := s.Scan(context.Background(), srcTarget(), Options{Analyzers: []string{"proto", "remote-only"}})
	if res.Status != model.StatusError || res.Verdict != model.VerdictUnknown {
		t.Fatalf("got %s/%s, want ERROR/UNKNOWN", res.Status, res.Verdict)
	}

	byName := map[string]model.AnalyzerResult{}
	for _, a := range res.Analyzers {
		byName[a.Analyzer] = a
	}
	if a, ok := byName["proto"]; !ok || a.Status != model.AnalyzerFailed || !a.Required {
		t.Fatalf("proto = %+v, want present, ERROR and required", a)
	}
	if a, ok := byName["remote-only"]; !ok || a.Status != model.AnalyzerSkipped || !a.Required {
		t.Fatalf("remote-only = %+v, want present, SKIPPED and required", a)
	}
}

func TestNothingApplicableAnalyzersStayRequiredWhenNamed(t *testing.T) {
	s := newScanner(kindLimited{fake{"remote-only", func(context.Context) model.AnalyzerResult {
		t.Error("remote-only analyzer ran against a source target")
		return model.AnalyzerResult{}
	}}})
	res, _ := s.Scan(context.Background(), srcTarget(), Options{Analyzers: []string{"remote-only"}})
	if res.Status != model.StatusSkipped {
		t.Fatalf("status = %s, want SKIPPED", res.Status)
	}
	if len(res.Analyzers) != 1 || res.Analyzers[0].Analyzer != "remote-only" || !res.Analyzers[0].Required {
		t.Fatalf("Analyzers = %+v, want [remote-only] required", res.Analyzers)
	}
}

func TestInapplicableAnalyzersAreNotRun(t *testing.T) {
	s := newScanner(kindLimited{fake{"remote-only", func(context.Context) model.AnalyzerResult {
		t.Error("remote-only analyzer ran against a source target")
		return model.AnalyzerResult{}
	}}})
	res, _ := s.Scan(context.Background(), srcTarget(), Options{})
	if res.Status != model.StatusSkipped {
		t.Fatalf("status = %s, want SKIPPED", res.Status)
	}
}

func TestToolCallAllowlist(t *testing.T) {
	ac := &analyzer.AnalysisContext{Probes: analyzer.ProbeSafe, AllowedToolCalls: []string{"read_file"}}
	if ac.ToolCallAllowed("read_file") {
		t.Fatal("tool calls must stay off until the probe level allows them")
	}
	ac.Probes = analyzer.ProbeToolCalls
	if !ac.ToolCallAllowed("read_file") {
		t.Fatal("allowlisted tool was refused at tool-calls level")
	}
	if ac.ToolCallAllowed("rm_rf") {
		t.Fatal("a tool outside the allowlist was permitted")
	}
}

func skipping(name string) analyzer.Analyzer {
	return fake{name, func(context.Context) model.AnalyzerResult {
		return model.Skipped(name, "no api key configured")
	}}
}

func TestUnconfiguredAnalyzerDoesNotBlockDefaultScan(t *testing.T) {
	s := newScanner(
		fake{"real", func(context.Context) model.AnalyzerResult {
			return okResult("real")
		}},
		skipping("llm"),
	)
	res, _ := s.Scan(context.Background(), srcTarget(), Options{})
	if res.Status != model.StatusCompleted || res.Verdict != model.VerdictSafe {
		t.Fatalf("got %s/%s, want COMPLETED/SAFE (%v)", res.Status, res.Verdict, res.VerdictReasons)
	}
	// It still has to be visible
	var found bool
	for _, a := range res.Analyzers {
		if a.Analyzer == "llm" && a.Status == model.AnalyzerSkipped {
			found = true
		}
	}
	if !found {
		t.Fatal("the skipped analyzer disappeared from the result")
	}
	if len(res.Warnings) == 0 {
		t.Fatal("a skipped analyzer should still be warned about")
	}
}

// Asking for an analyzer by name and not getting it is a different situation:
// the operator wanted that answer
func TestNamedAnalyzerThatSkipsBlocksTheScan(t *testing.T) {
	s := newScanner(
		fake{"real", func(context.Context) model.AnalyzerResult {
			return okResult("real")
		}},
		skipping("llm"),
	)
	res, _ := s.Scan(context.Background(), srcTarget(), Options{Analyzers: []string{"real", "llm"}})
	if res.Status != model.StatusPartial || res.Verdict != model.VerdictUnknown {
		t.Fatalf("got %s/%s, want PARTIAL/UNKNOWN", res.Status, res.Verdict)
	}
}

// A failure is never excused, named or not
func TestUnnamedAnalyzerFailureStillBlocks(t *testing.T) {
	s := newScanner(
		fake{"real", func(context.Context) model.AnalyzerResult {
			return okResult("real")
		}},
		fake{"llm", func(context.Context) model.AnalyzerResult {
			return model.Errorf("llm", "network", "provider timed out")
		}},
	)
	res, _ := s.Scan(context.Background(), srcTarget(), Options{})
	if res.Status != model.StatusError || res.Verdict != model.VerdictUnknown {
		t.Fatalf("got %s/%s, want ERROR/UNKNOWN", res.Status, res.Verdict)
	}
}

func TestNamedButInapplicableAnalyzerIsReportedAndRequired(t *testing.T) {
	s := newScanner(
		fake{"works", func(context.Context) model.AnalyzerResult { return okResult("works") }},
		kindLimited{fake{"remote-only", func(context.Context) model.AnalyzerResult {
			t.Error("a remote-only analyzer ran against a source target")
			return model.AnalyzerResult{}
		}}},
	)
	res, err := s.Scan(context.Background(), srcTarget(), Options{
		Analyzers: []string{"works", "remote-only"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var found *model.AnalyzerResult
	for i := range res.Analyzers {
		if res.Analyzers[i].Analyzer == "remote-only" {
			found = &res.Analyzers[i]
		}
	}
	if found == nil {
		t.Fatalf("the named analyzer is missing from the result entirely: %+v", res.Analyzers)
	}
	if found.Status != model.AnalyzerSkipped {
		t.Fatalf("status = %s, want SKIPPED", found.Status)
	}
	if !found.Required {
		t.Fatal("an analyzer the operator named must be required even when it cannot run")
	}
	if res.Status != model.StatusPartial || res.Verdict != model.VerdictUnknown {
		t.Fatalf("got %s/%s, want PARTIAL/UNKNOWN (%v)", res.Status, res.Verdict, res.VerdictReasons)
	}
}

// An analyzer picked up by the default selection that does not apply is still
// recorded, but it excuses itself and does not downgrade the scan
func TestUnnamedInapplicableAnalyzerDoesNotBlock(t *testing.T) {
	s := newScanner(
		fake{"works", func(context.Context) model.AnalyzerResult { return okResult("works") }},
		kindLimited{fake{"remote-only", func(context.Context) model.AnalyzerResult {
			return model.AnalyzerResult{}
		}}},
	)
	res, _ := s.Scan(context.Background(), srcTarget(), Options{})
	if res.Status != model.StatusCompleted || res.Verdict != model.VerdictSafe {
		t.Fatalf("got %s/%s, want COMPLETED/SAFE (%v)", res.Status, res.Verdict, res.VerdictReasons)
	}
	var seen bool
	for _, a := range res.Analyzers {
		if a.Analyzer == "remote-only" && a.Status == model.AnalyzerSkipped {
			seen = true
		}
	}
	if !seen {
		t.Fatal("the inapplicable analyzer should still be visible in the report")
	}
}

func TestApplyBaselineFillsInAnEmptyReason(t *testing.T) {
	results := []model.AnalyzerResult{{
		Findings: []model.Finding{{ID: "known", RuleID: "r", Analyzer: "a", Title: "t", Severity: model.SeverityHigh}},
	}}
	applyBaseline(results, map[string]string{"known": ""}, "")
	f := results[0].Findings[0]
	if !f.Suppressed {
		t.Fatal("expected the finding to be suppressed")
	}
	if strings.TrimSpace(f.SuppressionReason) == "" {
		t.Fatal("expected a non-empty SuppressionReason, got an empty one - it would serialize as if no reason were recorded")
	}
}

func TestNewScanIDRefusesWhenRandFails(t *testing.T) {
	old := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("entropy source unavailable") }
	defer func() { randRead = old }()

	if id, err := newScanID(); err == nil {
		t.Fatalf("expected an error when the entropy source fails, got id %q", id)
	}
}

// A scan that cannot get a scan id must fail outright rather than silently
// scanning under a clock-derived id
func TestScanRefusesWhenScanIDCannotBeGenerated(t *testing.T) {
	old := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("entropy source unavailable") }
	defer func() { randRead = old }()

	sc := New(nil, nil, nil)
	if _, err := sc.Scan(context.Background(), model.Target{Kind: model.TargetSource, Path: "."}, Options{}); err == nil {
		t.Fatal("expected Scan to refuse when it cannot generate a scan id")
	}
}

func TestDeadlineIsNotExcusedBySelfExcusing(t *testing.T) {
	for _, status := range []model.AnalyzerStatus{model.AnalyzerSkipped, model.AnalyzerUnavailable} {
		t.Run(string(status), func(t *testing.T) {
			slow := fake{"slow", func(ctx context.Context) model.AnalyzerResult {
				<-ctx.Done()
				return model.AnalyzerResult{Analyzer: "slow", Status: status, Warnings: []string{"excusing itself"}}
			}}
			quick := fake{"quick", func(context.Context) model.AnalyzerResult { return okResult("quick") }}
			s := newScanner(slow, quick)

			res, err := s.Scan(context.Background(), srcTarget(), Options{AnalyzerTimeout: 20 * time.Millisecond})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if res.Status == model.StatusCompleted || res.Verdict == model.VerdictSafe {
				t.Fatalf("a scan cut off by its own deadline must not read as complete or safe, got status=%s verdict=%s reasons=%v",
					res.Status, res.Verdict, res.VerdictReasons)
			}
			for _, a := range res.Analyzers {
				if a.Analyzer != "slow" {
					continue
				}
				if a.Status != model.AnalyzerPartial {
					t.Fatalf("slow analyzer status = %s, want PARTIAL: it was cut off, it did not opt out", a.Status)
				}
				if !a.Required {
					t.Fatal("an analyzer the deadline cut off must stay required; excusing it excuses the deadline")
				}
			}
		})
	}
}

// Required analyzers cannot excuse themselves, even under default selection
func TestRequiredAnalyzerCannotExcuseItself(t *testing.T) {
	s := newScanner(
		fake{"real", func(context.Context) model.AnalyzerResult { return okResult("real") }},
		fake{"sandbox", func(context.Context) model.AnalyzerResult {
			return model.Unavailable("sandbox", "docker is not running")
		}},
	)

	res, err := s.Scan(context.Background(), srcTarget(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != model.VerdictSafe {
		t.Fatalf("control: an unrequested analyzer that is unavailable should be excused, got %s/%s (%v)", res.Status, res.Verdict, res.VerdictReasons)
	}

	res, err = s.Scan(context.Background(), srcTarget(), Options{Required: []string{"sandbox"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != model.VerdictUnknown {
		t.Fatalf("a required analyzer that was unavailable gave %s/%s (%v)", res.Status, res.Verdict, res.VerdictReasons)
	}
}

// A baseline accepts a finding on the target it was accepted for and nowhere else
func TestBaselineAppliesOnlyToItsOwnTarget(t *testing.T) {
	s := newScanner(fake{"rules", func(context.Context) model.AnalyzerResult {
		r := okResult("rules")
		r.Findings = []model.Finding{{
			RuleID: "rules.demo", Category: "demo", Title: "same finding everywhere",
			Severity: model.SeverityHigh, Confidence: 0.9, EvidenceLevel: model.EvidenceStatic,
			Evidence: []model.Evidence{{Level: model.EvidenceStatic, Description: "matched"}},
		}}
		return r
	}})
	a := model.Target{Kind: model.TargetSource, Path: ".", Name: "server-a"}
	b := model.Target{Kind: model.TargetSource, Path: ".", Name: "server-b"}
	opts := Options{BlockingSeverity: model.SeverityHigh}

	first, err := s.Scan(context.Background(), a, opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.Verdict != model.VerdictUnsafe || len(first.Findings) != 1 {
		t.Fatalf("control: want one blocking finding, got %s with %d finding(s)", first.Verdict, len(first.Findings))
	}
	opts.Baseline = map[string]string{first.Findings[0].ID: "accepted for server-a"}

	onA, err := s.Scan(context.Background(), a, opts)
	if err != nil {
		t.Fatal(err)
	}
	if onA.Verdict != model.VerdictSafe {
		t.Fatalf("the baselined finding still blocks the target it was accepted for: %s (%v)", onA.Verdict, onA.VerdictReasons)
	}

	onB, err := s.Scan(context.Background(), b, opts)
	if err != nil {
		t.Fatal(err)
	}
	if onB.Verdict != model.VerdictUnsafe {
		t.Fatalf("server-a's baseline suppressed the same finding on server-b: %s (%v)", onB.Verdict, onB.VerdictReasons)
	}
}

// best_effort overrides required selection, so that analyzer's error cannot decide the verdict
func TestBestEffortAnalyzerErrorDoesNotBlockTheVerdict(t *testing.T) {
	s := newScanner(
		fake{"real", func(context.Context) model.AnalyzerResult { return okResult("real") }},
		fake{"flaky", func(context.Context) model.AnalyzerResult {
			return model.Errorf("flaky", "provider", "upstream service unavailable")
		}},
	)
	res, err := s.Scan(context.Background(), srcTarget(), Options{
		Analyzers: []string{"real", "flaky"}, BestEffort: []string{"flaky"}, Required: []string{"flaky"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != model.StatusCompleted || res.Verdict != model.VerdictSafe {
		t.Fatalf("got %s/%s, want the best-effort error not to decide the scan (%v)", res.Status, res.Verdict, res.VerdictReasons)
	}
}
