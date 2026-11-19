package promptdefense

import (
	"context"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A source-tree snapshot carries no input schema. An unknown parameter count is not zero
// parameters, so only the absolute limit applies to it; a schema that is present and has at
// most one parameter keeps the lower limit.
func TestOversizedDescription_UnknownSchemaUsesTheAbsoluteLimit(t *testing.T) {
	desc := strings.Repeat("Explains each option of the report in detail. ", 18) // about 850 characters
	for _, tc := range []struct {
		name   string
		schema map[string]any
		want   bool
	}{
		{"schema not visible", nil, false},
		{"schema with no parameters", map[string]any{"type": "object", "properties": map[string]any{}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := New().Analyze(context.Background(), model.Target{Kind: model.TargetStatic, Path: "x"},
				&analyzer.AnalysisContext{Snapshot: &model.Snapshot{Tools: []model.ToolInfo{{Name: "report", Description: desc, InputSchema: tc.schema}}}})
			got := false
			for _, f := range res.Findings {
				if f.RuleID == "promptdefense.oversized-description" {
					got = true
				}
			}
			if got != tc.want {
				t.Fatalf("oversized-description fired = %v, want %v", got, tc.want)
			}
		})
	}
}
