package analyzer

import (
	"context"
	"testing"

	"github.com/revinand/mcp-scanner/pkg/model"
)

type named string

func (n named) Name() string { return string(n) }
func (n named) Analyze(context.Context, model.Target, *AnalysisContext) model.AnalyzerResult {
	return model.AnalyzerResult{}
}

// Duplicate names make results ambiguous, and an empty name cannot be selected, so both panic
func TestRegisterRefusesAmbiguousNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(r *Registry)
	}{
		{"duplicate", func(r *Registry) { r.Register(named("taint")); r.Register(named("taint")) }},
		{"empty", func(r *Registry) { r.Register(named("")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Register did not panic")
				}
			}()
			tc.setup(NewRegistry())
		})
	}
}
