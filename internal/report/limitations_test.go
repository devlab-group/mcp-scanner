package report

import (
	"context"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// fakeLimitedAnalyzer is a Describer with a declared limitation, standing in
// for a real analyzer such as promptdefense without pulling in internal/app
type fakeLimitedAnalyzer struct{ name string }

func (f fakeLimitedAnalyzer) Name() string { return f.name }
func (f fakeLimitedAnalyzer) Analyze(context.Context, model.Target, *analyzer.AnalysisContext) model.AnalyzerResult {
	return model.AnalyzerResult{Analyzer: f.name, Status: model.AnalyzerCompleted}
}
func (f fakeLimitedAnalyzer) Describe() analyzer.Description {
	return analyzer.Description{Name: f.name, Limitations: []string{"pattern matching can miss a paraphrase"}}
}

// fakeQuietAnalyzer is a Describer with nothing to disclose
type fakeQuietAnalyzer struct{ name string }

func (f fakeQuietAnalyzer) Name() string { return f.name }
func (f fakeQuietAnalyzer) Analyze(context.Context, model.Target, *analyzer.AnalysisContext) model.AnalyzerResult {
	return model.AnalyzerResult{Analyzer: f.name, Status: model.AnalyzerCompleted}
}
func (f fakeQuietAnalyzer) Describe() analyzer.Description {
	return analyzer.Description{Name: f.name}
}

func init() {
	// Unique names so this never collides with a real analyzer or another
	// test registering into the same process-wide registry
	analyzer.Register(fakeLimitedAnalyzer{name: "report-test-limited"})
	analyzer.Register(fakeQuietAnalyzer{name: "report-test-quiet"})
}

func TestLimitationsNoteNamesAnalyzersWithDeclaredLimitations(t *testing.T) {
	res := &model.ScanResult{Analyzers: []model.AnalyzerResult{
		{Analyzer: "report-test-limited", Status: model.AnalyzerCompleted},
		{Analyzer: "report-test-quiet", Status: model.AnalyzerCompleted},
	}}
	note := LimitationsNote(res)
	if !strings.Contains(note, "report-test-limited") {
		t.Fatalf("note %q does not name the analyzer with a declared limitation", note)
	}
	if strings.Contains(note, "report-test-quiet") {
		t.Fatalf("note %q names an analyzer with nothing to disclose", note)
	}
}

func TestLimitationsNoteEmptyWithNoLimitations(t *testing.T) {
	res := &model.ScanResult{Analyzers: []model.AnalyzerResult{
		{Analyzer: "report-test-quiet", Status: model.AnalyzerCompleted},
	}}
	if note := LimitationsNote(res); note != "" {
		t.Fatalf("want empty note, got %q", note)
	}
}

func TestLimitationsNoteIgnoresSkippedAnalyzers(t *testing.T) {
	res := &model.ScanResult{Analyzers: []model.AnalyzerResult{
		{Analyzer: "report-test-limited", Status: model.AnalyzerSkipped},
	}}
	if note := LimitationsNote(res); note != "" {
		t.Fatalf("want empty note for a skipped analyzer, got %q", note)
	}
}

func TestLimitationsNoteUnknownAnalyzerName(t *testing.T) {
	res := &model.ScanResult{Analyzers: []model.AnalyzerResult{
		{Analyzer: "does-not-exist", Status: model.AnalyzerCompleted},
	}}
	if note := LimitationsNote(res); note != "" {
		t.Fatalf("want empty note for an unregistered analyzer name, got %q", note)
	}
}
