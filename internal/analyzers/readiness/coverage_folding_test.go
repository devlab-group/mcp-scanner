package readiness

import (
	"context"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Source and package targets both include coverage from the source walk
func TestAnalyze_FoldsWalkCoverageOnSourceAndPackageTargets(t *testing.T) {
	for _, kind := range []model.TargetKind{model.TargetSource, model.TargetPackage} {
		artifacts := analyzer.NewArtifacts()
		artifacts.Set(source.WalkCoverageKey, model.Coverage{
			FilesDiscovered: 6,
			FilesParsed:     5,
			FilesSkipped:    1,
			SkipReasons:     []string{"handlers/ excluded by .scannerignore"},
		})
		res := (&Analyzer{}).Analyze(context.Background(), model.Target{Kind: kind, Path: "x"}, &analyzer.AnalysisContext{
			Snapshot:  &model.Snapshot{Tools: []model.ToolInfo{{Name: "safe_tool", Description: "Does something ordinary."}}},
			Artifacts: artifacts,
		})
		if res.Coverage.FilesDiscovered != 6 || res.Coverage.FilesParsed != 5 || res.Coverage.FilesSkipped != 1 {
			t.Errorf("%s: coverage = %+v, want the walk's file counters folded in", kind, res.Coverage)
		}
		found := false
		for _, r := range res.Coverage.SkipReasons {
			if strings.Contains(r, ".scannerignore") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: skip reasons = %v, want the walk's reason folded in", kind, res.Coverage.SkipReasons)
		}
	}
}

func TestAnalyze_FoldsCapabilityTruncation(t *testing.T) {
	res := (&Analyzer{}).Analyze(context.Background(), model.Target{Kind: model.TargetRemote, Path: "x"}, &analyzer.AnalysisContext{
		Snapshot: &model.Snapshot{
			Tools:     []model.ToolInfo{{Name: "safe_tool", Description: "Does something ordinary."}},
			Truncated: []model.Truncation{{Method: "tools/list", Read: 1, Unknown: true, Reason: "server returned a pagination cursor it had already returned"}},
		},
	})
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatalf("truncated discovery did not produce a coverage gap: %+v", res.Coverage)
	}
}

func TestAnalyze_NoWalkCoverageOnRemoteTarget(t *testing.T) {
	artifacts := analyzer.NewArtifacts()
	artifacts.Set(source.WalkCoverageKey, model.Coverage{FilesDiscovered: 6, FilesParsed: 5})
	res := (&Analyzer{}).Analyze(context.Background(), model.Target{Kind: model.TargetRemote, Path: "x"}, &analyzer.AnalysisContext{
		Snapshot:  &model.Snapshot{Tools: []model.ToolInfo{{Name: "get_weather", Description: "Fetches the forecast."}}},
		Artifacts: artifacts,
	})
	if res.Coverage.FilesDiscovered != 0 || res.Coverage.FilesParsed != 0 {
		t.Errorf("coverage = %+v, want no file-level counters on a remote target", res.Coverage)
	}
}
