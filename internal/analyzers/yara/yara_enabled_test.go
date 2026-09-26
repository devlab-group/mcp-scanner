//go:build yara

package yara

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// Run the fixture corpus through YARA and validate each expected result
func TestRuleCorpusThroughTheEngine(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "rules", "yara", "cases")
	paths, err := filepath.Glob(filepath.Join(root, "*", "*.yaml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no yara cases under %s: %v", root, err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var c caseFile
			if err := yaml.Unmarshal(data, &c); err != nil {
				t.Fatal(err)
			}
			snap := &model.Snapshot{}
			for _, tool := range c.Snapshot.Tools {
				snap.Tools = append(snap.Tools, model.ToolInfo{Name: tool.Name, Description: tool.Description})
			}
			res := (&Analyzer{}).Analyze(context.Background(), model.Target{Kind: model.TargetStatic}, &analyzer.AnalysisContext{Snapshot: snap})
			if res.Status != model.AnalyzerCompleted {
				t.Fatalf("status = %s, errors %v", res.Status, res.Errors)
			}
			fired := false
			for _, f := range res.Findings {
				if err := f.Validate(); err != nil {
					t.Errorf("invalid finding %s: %v", f.RuleID, err)
				}
				if f.EvidenceLevel != model.EvidenceStatic {
					t.Errorf("%s: evidence level %s, want STATIC", f.RuleID, f.EvidenceLevel)
				}
				if f.RuleID == c.Rule {
					fired = true
				}
			}
			if fired != c.ExpectFire {
				t.Fatalf("%s fired = %v, want %v (%s)", c.Rule, fired, c.ExpectFire, c.Note)
			}
		})
	}
}

// A source tree has no resource body to scan until runtime. An unfetched live body exists but
// remains unread, so it is a coverage limit.
func TestUnfetchedResourceBodyDependsOnTargetKind(t *testing.T) {
	snap := &model.Snapshot{
		Tools:     []model.ToolInfo{{Name: "t", Description: "Lists files."}},
		Resources: []model.ResourceInfo{{URI: "notes://today", Name: "today", Description: "Notes."}},
	}
	src := (&Analyzer{}).Analyze(context.Background(), model.Target{Kind: model.TargetSource}, &analyzer.AnalysisContext{Snapshot: snap})
	if gaps := src.Coverage.Gaps(); len(gaps) != 0 {
		t.Errorf("source tree: a body that does not exist was reported as a gap: %v", gaps)
	}
	live := (&Analyzer{}).Analyze(context.Background(), model.Target{Kind: model.TargetRemote}, &analyzer.AnalysisContext{Snapshot: snap})
	if len(live.Coverage.Gaps()) == 0 {
		t.Errorf("live target: an unfetched body left no gap: %+v", live.Coverage)
	}
}
