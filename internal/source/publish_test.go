package source

import (
	"context"
	"testing"

	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// A graph without its walk coverage hides excluded or failed files from consumers. Publishing the
// coverage before the graph lets later consumers reuse both, although the two Set calls are not
// atomic.
func TestAnalyzePublishesWalkCoverageWithTheGraph(t *testing.T) {
	ac := &analyzer.AnalysisContext{Artifacts: analyzer.NewArtifacts()}
	target := model.Target{Kind: model.TargetSource, Path: "../../testdata/source/discovery/go"}

	if res := (&Analyzer{}).Analyze(context.Background(), target, ac); res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, errors: %+v", res.Status, res.Errors)
	}
	if _, ok := analyzer.Get[*graph.Graph](ac.Artifacts, ArtifactKey); !ok {
		t.Fatal("no graph was published")
	}
	cov, ok := analyzer.Get[model.Coverage](ac.Artifacts, WalkCoverageKey)
	if !ok {
		t.Fatal("the graph was published without its walk coverage, so a consumer reusing it sees an empty tree")
	}
	if cov.FilesDiscovered == 0 {
		t.Errorf("published walk coverage counts no files: %+v", cov)
	}
}

// Publish stores nothing when there is nowhere to put it or no graph to
// share, so a caller needs no guard of its own
func TestPublishIgnoresNothingToPublish(t *testing.T) {
	Publish(nil, nil, model.Coverage{})

	arts := analyzer.NewArtifacts()
	Publish(arts, nil, model.Coverage{FilesDiscovered: 3})
	if _, ok := analyzer.Get[model.Coverage](arts, WalkCoverageKey); ok {
		t.Error("coverage was published for a graph that does not exist")
	}
}
