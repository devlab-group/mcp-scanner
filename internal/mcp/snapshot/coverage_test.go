package snapshot

import (
	"testing"

	"github.com/revinand/mcp-scanner/pkg/model"
)

func TestCapabilityCoverageReportsABodyCutAtThePerItemCap(t *testing.T) {
	snap := &model.Snapshot{
		Resources: []model.ResourceInfo{
			{URI: "file:///notes.md", Name: "notes", Fetched: true, Content: "front of it", ContentTruncated: true},
			{URI: "file:///ok.md", Name: "ok", Fetched: true, Content: "all of it"},
		},
		Prompts: []model.PromptInfo{
			{Name: "greet", Rendered: true, Text: "front of it", TextTruncated: true},
		},
	}

	cov := CapabilityCoverage(snap)
	if len(cov.LimitsHit) != 2 {
		t.Fatalf("want a limit for the cut resource and the cut prompt, got %v", cov.LimitsHit)
	}
	// Whatever the arithmetic does, a limit is a gap unconditionally
	cov.CapabilitiesAnalyzed = cov.CapabilitiesDiscovered
	if len(cov.Gaps()) == 0 {
		t.Fatal("a body the scanner cut short reported no gap, so the scan stays clean over what it did not read")
	}

	clean := CapabilityCoverage(&model.Snapshot{
		Resources: []model.ResourceInfo{{URI: "file:///ok.md", Fetched: true, Content: "all of it"}},
	})
	if len(clean.LimitsHit) != 0 {
		t.Fatalf("a body that was read whole must not report a limit: %v", clean.LimitsHit)
	}
}
