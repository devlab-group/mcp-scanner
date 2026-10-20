package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// LimitationsNote names the analyzers behind this verdict that have declared limitations,
// so a clean verdict comes with a pointer to what it does not cover instead of standing on
// its own. `mcp-scanner analyzers` already prints the full Describe().Limitations text for
// every analyzer; this reads the same source and names which of them apply here, without
// repeating their content into every report.
func LimitationsNote(res *model.ScanResult) string {
	var names []string
	for _, a := range res.Analyzers {
		// Same filter as AnalyzerGaps: SKIPPED and UNAVAILABLE analyzers
		// excused themselves and contributed nothing, so their limitations
		// are not limitations on this verdict
		if a.Status != model.AnalyzerCompleted && a.Status != model.AnalyzerPartial {
			continue
		}
		impl, ok := analyzer.Default.Get(a.Analyzer)
		if !ok {
			continue
		}
		d, ok := impl.(analyzer.Describer)
		if !ok {
			continue
		}
		if len(d.Describe().Limitations) > 0 {
			names = append(names, a.Analyzer)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return fmt.Sprintf("note: %s ran with declared limitations - run `mcp-scanner analyzers` to see what each does not cover",
		strings.Join(names, ", "))
}
