package taint_test

import (
	"context"
	"sync"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/analyzers/behavioral"
	"github.com/devlab-group/mcp-scanner/internal/analyzers/taint"
	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func TestConcurrentAnalyzers_SharedArtifactsUnderRace(t *testing.T) {
	dir := "../../../testdata/source/discovery/go" // 8 files, several real registrations
	target := model.Target{Kind: model.TargetSource, Path: dir}
	ac := &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()}

	analyzers := []analyzer.Analyzer{
		&source.Analyzer{},
		&taint.Analyzer{},
		&behavioral.Analyzer{},
	}

	var wg sync.WaitGroup
	results := make([]model.AnalyzerResult, len(analyzers))
	for i, a := range analyzers {
		wg.Add(1)
		go func(i int, a analyzer.Analyzer) {
			defer wg.Done()
			results[i] = a.Analyze(context.Background(), target, ac)
		}(i, a)
	}
	wg.Wait()

	for i, res := range results {
		if res.Status != model.AnalyzerCompleted {
			t.Errorf("%s: status = %s, errors: %+v", analyzers[i].Name(), res.Status, res.Errors)
		}
		if res.Coverage.FilesDiscovered == 0 {
			t.Errorf("%s: want files discovered regardless of which analyzer built the graph, got %+v", analyzers[i].Name(), res.Coverage)
		}
	}
}
