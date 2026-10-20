package report

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func TestCoverageOverstatesCapabilities(t *testing.T) {
	analyzers := []model.AnalyzerResult{
		{Analyzer: "source", Status: model.AnalyzerCompleted, Coverage: model.Coverage{
			CapabilitiesDiscovered: 2, CapabilitiesAnalyzed: 2,
		}},
		{Analyzer: "taint", Status: model.AnalyzerCompleted, Coverage: model.Coverage{
			CapabilitiesDiscovered: 2, CapabilitiesAnalyzed: 1,
		}},
	}
	merged := model.Coverage{CapabilitiesDiscovered: 2, CapabilitiesAnalyzed: 2}
	if !CoverageOverstatesCapabilities(merged, analyzers) {
		t.Error("a merged count crediting more analysis than taint performed went unflagged")
	}
	if CoverageIsMerged(merged) {
		t.Error("the arithmetic here is consistent, so the impossible-population check cannot be what catches this")
	}

	agreed := []model.AnalyzerResult{
		{Analyzer: "source", Status: model.AnalyzerCompleted, Coverage: model.Coverage{
			CapabilitiesDiscovered: 2, CapabilitiesAnalyzed: 2,
		}},
		{Analyzer: "taint", Status: model.AnalyzerCompleted, Coverage: model.Coverage{
			CapabilitiesDiscovered: 2, CapabilitiesAnalyzed: 2,
		}},
	}
	if CoverageOverstatesCapabilities(merged, agreed) {
		t.Error("every analyzer reached every capability; the caveat would be noise")
	}

	excused := append(agreed, model.AnalyzerResult{
		Analyzer: "runtime", Status: model.AnalyzerSkipped,
	})
	if CoverageOverstatesCapabilities(merged, excused) {
		t.Error("a self-excused analyzer's empty coverage was read as disagreement")
	}
}
