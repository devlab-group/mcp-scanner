//go:build !yara

package yara

import (
	"context"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func TestDisabledAnalyzerReportsUnavailable(t *testing.T) {
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStatic, Path: "x"}, &analyzer.AnalysisContext{
		Snapshot: &model.Snapshot{Instructions: "hello"},
	})
	if res.Status != model.AnalyzerUnavailable {
		t.Fatalf("status = %s, want UNAVAILABLE", res.Status)
	}
	if len(res.Errors) == 0 || res.Errors[0].Kind != "unavailable" {
		t.Fatalf("expected an %q error explaining the missing build tag, got %v", "unavailable", res.Errors)
	}
	if res.Errors[0].Message == "" {
		t.Fatal("unavailable error has no explanation")
	}
}

func TestUnavailableIsVisibleInAggregateResult(t *testing.T) {
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStatic, Path: "x"}, &analyzer.AnalysisContext{
		Snapshot: &model.Snapshot{Instructions: "hello"},
	})

	scan := &model.ScanResult{Analyzers: []model.AnalyzerResult{
		// Real coverage, so the only thing that can downgrade this scan is yara being unavailable
		{Analyzer: "other", Status: model.AnalyzerCompleted, Required: true,
			Coverage: model.Coverage{CapabilitiesDiscovered: 1, CapabilitiesAnalyzed: 1}},
		func() model.AnalyzerResult { res.Required = true; return res }(),
	}}
	scan.Aggregate(model.SeverityLow)

	if scan.Verdict != model.VerdictUnknown {
		t.Fatalf("verdict = %s, want UNKNOWN with a required analyzer UNAVAILABLE", scan.Verdict)
	}
	if scan.Status == model.StatusCompleted {
		t.Fatalf("status = COMPLETED, want it downgraded")
	}
	found := false
	for _, reason := range scan.VerdictReasons {
		if strings.Contains(reason, "yara") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no reason names yara as the cause of the downgrade: %v", scan.VerdictReasons)
	}
}
