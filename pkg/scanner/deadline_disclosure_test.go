package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// An analyzer that was already PARTIAL for another limit - taint on a large tree - carried no
// trace of the deadline, so a report never said its results were cut off by time
func TestDeadlineIsReportedForAnAlreadyPartialAnalyzer(t *testing.T) {
	slow := fake{"slow", func(ctx context.Context) model.AnalyzerResult {
		<-ctx.Done()
		return model.AnalyzerResult{Analyzer: "slow", Status: model.AnalyzerPartial,
			Coverage: model.Coverage{LimitsHit: []string{"some other limit"}}}
	}}
	quick := fake{"quick", func(context.Context) model.AnalyzerResult { return okResult("quick") }}
	res, err := newScanner(slow, quick).Scan(context.Background(), srcTarget(), Options{AnalyzerTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	inLimits := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "analyzer deadline") {
			inLimits = true
		}
	}
	if !inLimits {
		t.Fatalf("coverage limits do not mention the deadline: %v", res.Coverage.LimitsHit)
	}
	for _, a := range res.Analyzers {
		if a.Analyzer == "slow" && !strings.Contains(strings.Join(a.Warnings, ";"), "deadline") {
			t.Fatalf("slow analyzer warnings do not mention the deadline: %v", a.Warnings)
		}
	}
}
