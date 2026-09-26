//go:build !yara

package yara

import (
	"context"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

var _ analyzer.Analyzer = (*Analyzer)(nil)

// Analyze reports UNAVAILABLE because this build has no YARA engine linked in. A scan becomes
// UNKNOWN when it requires YARA instead of treating the missing analyzer as a clean pass.
func (a *Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	return model.Unavailable(analyzerName, "built without the \"yara\" tag; rebuild with -tags yara and the github.com/hillu/go-yara/v4 dependency to enable signature scanning")
}
