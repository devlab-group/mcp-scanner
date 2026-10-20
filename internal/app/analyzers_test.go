package app

import (
	"slices"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

// Pin the public analyzer names exposed by the default build. cisco and virustotal compile but
// are not registered.
func TestDefaultBuildRegistersTheDocumentedAnalyzers(t *testing.T) {
	want := []string{"auth", "behavioral", "llm", "promptdefense", "protocol", "readiness", "runtime", "source", "supplychain", "taint", "yara"}
	got := slices.Sorted(slices.Values(analyzer.Default.Names()))
	if !slices.Equal(got, want) {
		t.Fatalf("registered analyzers = %v, want %v", got, want)
	}
}
