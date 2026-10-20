package policy

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		in      string
		want    model.Severity
		wantErr bool
	}{
		{"none", "", false},
		{"NONE", "", false},
		{"high", model.SeverityHigh, false},
		{"critical", model.SeverityCritical, false},
		{"hgih", "", true},
		{"", "", true},
	}
	for _, tc := range tests {
		got, err := ParseFailOn(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ParseFailOn(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if err == nil && got != tc.want {
			t.Errorf("ParseFailOn(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The gate is off, not set to some severity, for "none"
	sev, _ := ParseFailOn(FailOnNone)
	if sev.Valid() {
		t.Errorf("ParseFailOn(none) = %q, want a severity that turns the gate off", sev)
	}
}
