package report

import (
	"fmt"

	"github.com/revinand/mcp-scanner/pkg/model"
)

// ContributionNote summarizes how many of the analyzers listed for this scan actually
// completed and so contributed to the verdict, out of the total
func ContributionNote(res *model.ScanResult) string {
	completed, total := 0, len(res.Analyzers)
	for _, a := range res.Analyzers {
		if a.Status == model.AnalyzerCompleted {
			completed++
		}
	}
	return fmt.Sprintf("%d of %d analyzers contributed to this verdict", completed, total)
}
