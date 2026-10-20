package report

import "github.com/devlab-group/mcp-scanner/pkg/model"

// AnalyzerGaps returns deduplicated gaps for completed or partial analyzers. Failed, skipped,
// and unavailable analyzers are omitted; their status conveys the missing analysis instead.
func AnalyzerGaps(analyzers []model.AnalyzerResult) []string {
	var gaps []string
	seen := map[string]bool{}
	for _, a := range analyzers {
		// Reports show gaps from completed and partial analyzers. Verdict aggregation evaluates
		// coverage only for completed required analyzers; PARTIAL is already inconclusive by status.
		if a.Status != model.AnalyzerCompleted && a.Status != model.AnalyzerPartial {
			continue
		}
		for _, g := range a.Coverage.Gaps() {
			line := a.Analyzer + ": " + g
			if seen[line] {
				continue
			}
			seen[line] = true
			gaps = append(gaps, line)
		}
	}
	return gaps
}

// CoverageIsMerged reports counters that cannot describe one population. Scan-level coverage
// takes maxima from analyzers, so its fields may summarize different underlying sets.
func CoverageIsMerged(c model.Coverage) bool {
	return c.FilesDiscovered-c.FilesParsed-c.FilesFailed-c.FilesSkipped < 0 ||
		c.CapabilitiesDiscovered-c.CapabilitiesAnalyzed-c.CapabilitiesSkipped < 0
}

// CoverageOverstatesCapabilities detects a merged summary that credits more analysis than at
// least one analyzer performed. This catches plausible-looking arithmetic that still hides an
// individual analyzer's gap.
func CoverageOverstatesCapabilities(c model.Coverage, analyzers []model.AnalyzerResult) bool {
	for _, a := range analyzers {
		if a.Status != model.AnalyzerCompleted && a.Status != model.AnalyzerPartial {
			continue
		}
		if a.Coverage.CapabilitiesDiscovered > 0 && a.Coverage.CapabilitiesAnalyzed < c.CapabilitiesAnalyzed {
			return true
		}
	}
	return false
}
