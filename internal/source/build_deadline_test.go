package source

import (
	"context"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A deadline leaves unread files as a limit, not an explained skip. Ten checks pass inventory
// and stop parsing partway through the fixture.
func TestBuild_DeadlineMidParseIsALimit(t *testing.T) {
	_, cov, err := Build(&testutil.CancelAfter{Context: context.Background(), Limit: 10}, "../../testdata/source/discovery/go")
	if err != nil {
		t.Fatal(err)
	}
	if cov.FilesParsed == 0 || cov.FilesParsed == cov.FilesDiscovered {
		t.Fatalf("the deadline did not land part way through: %+v", cov)
	}
	if !hasSubstring(cov.LimitsHit, "scan deadline reached") {
		t.Fatalf("the unparsed files are not a limit: %+v", cov)
	}
	for _, r := range cov.SkipReasons {
		if strings.Contains(r, "scan deadline") {
			t.Errorf("the deadline is also recorded as a skip reason, which explains the gap away: %q", r)
		}
	}
	if len(cov.Gaps()) == 0 {
		t.Fatalf("a tree cut short by the deadline reports no gap: %+v", cov)
	}
}

// An analyzer cut off partway through its files cannot report COMPLETED
func TestAnalyze_CutOffPartWayIsPartial(t *testing.T) {
	dir := "../../testdata/source/discovery/go"
	ctx := &testutil.CancelAfter{Context: context.Background(), Limit: 10}
	res := (&Analyzer{}).Analyze(ctx, model.Target{Kind: model.TargetSource, Path: dir},
		&analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()})
	if res.Status != model.AnalyzerPartial {
		t.Fatalf("status = %s, want PARTIAL (errors %v)", res.Status, res.Errors)
	}
}
