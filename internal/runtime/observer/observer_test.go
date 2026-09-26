package observer

import (
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
)

func TestObserveProcessExec(t *testing.T) {
	obs := Observe(Input{Started: true, ExitCode: 0})
	if !hasKind(obs, "process_exec") {
		t.Fatalf("expected process_exec observation, got %+v", obs)
	}
}

func TestObserveCanaryHit(t *testing.T) {
	obs := Observe(Input{
		Started: true,
		Stdout:  "here is the file: canary-db-deadbeef",
		Canaries: []analyzer.Canary{
			{ID: "db_password-abcd-0", Kind: "db_password", Value: "canary-db-deadbeef"},
			{ID: "aws_key-abcd-1", Kind: "aws_key", Value: "not-present-in-output"},
		},
	})
	hits := kindsOf(obs, "canary_hit")
	if len(hits) != 1 {
		t.Fatalf("expected exactly one canary_hit, got %d: %+v", len(hits), obs)
	}
	if hits[0].CanaryID != "db_password-abcd-0" {
		t.Fatalf("wrong canary attributed: %+v", hits[0])
	}
}

func TestObserveCanaryHitPastMaxCapture(t *testing.T) {
	padding := strings.Repeat("x", MaxCapture+1000)
	obs := Observe(Input{
		Started: true,
		Stdout:  padding + "canary-db-deadbeef",
		Canaries: []analyzer.Canary{
			{ID: "db_password-abcd-0", Kind: "db_password", Value: "canary-db-deadbeef"},
		},
	})
	if !hasKind(obs, "canary_hit") {
		t.Fatalf("canary past MaxCapture bytes must still be found, got %+v", obs)
	}
}

func TestObserveNoFalseCanaryHit(t *testing.T) {
	obs := Observe(Input{
		Started: true,
		Stdout:  "nothing interesting here",
		Canaries: []analyzer.Canary{
			{ID: "x", Kind: "api_token", Value: "sk-canary-deadbeef"},
		},
	})
	if hasKind(obs, "canary_hit") {
		t.Fatalf("unexpected canary_hit with no matching content: %+v", obs)
	}
}

func TestObserveSelfReportedMarkers(t *testing.T) {
	obs := Observe(Input{
		Started: true,
		Stdout:  "MCP-OBS:file_read:/sandbox/home/.aws/credentials\nMCP-OBS:process_exec:echo pwned\nMCP-OBS:bogus_kind:ignored\n",
	})
	if !hasKind(obs, "file_read") {
		t.Fatalf("expected file_read from self-report, got %+v", obs)
	}
	for _, o := range obs {
		if o.Kind == "bogus_kind" {
			t.Fatalf("unrecognized self-reported kind must be dropped: %+v", obs)
		}
	}
}

func TestSanitizeBoundsAndEscapes(t *testing.T) {
	long := strings.Repeat("a", 100)
	got := Sanitize(long, 10)
	if len(got) <= 10 {
		t.Fatalf("expected truncation marker appended, got %q", got)
	}
	esc := Sanitize("bell\x07here", 100)
	if strings.ContainsRune(esc, 0x07) {
		t.Fatalf("control character not escaped: %q", esc)
	}
}

func hasKind(obs []analyzer.Observation, kind string) bool {
	return len(kindsOf(obs, kind)) > 0
}

func kindsOf(obs []analyzer.Observation, kind string) []analyzer.Observation {
	var out []analyzer.Observation
	for _, o := range obs {
		if o.Kind == kind {
			out = append(out, o)
		}
	}
	return out
}
