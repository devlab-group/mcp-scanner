package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// docs/result-schema.md documents findings as an array; a scan with none used to serialize null
func TestAggregate_NoFindingsIsAnEmptyArray(t *testing.T) {
	r := ScanResult{Analyzers: []AnalyzerResult{{Analyzer: "source", Status: AnalyzerCompleted}}}
	r.Aggregate(SeverityHigh)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"findings":[]`) {
		t.Fatalf("findings not an empty array: %s", b)
	}
}
