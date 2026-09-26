package report

import (
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/internal/policy"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func unsafeResult() *model.ScanResult {
	return &model.ScanResult{Status: model.StatusCompleted, Verdict: model.VerdictUnsafe}
}

func TestGateNoteExplainsPassingDespiteUnsafe(t *testing.T) {
	decision := policy.Decision{Pass: true, ExitCode: policy.ExitOK, Reason: "no finding reached the HIGH threshold"}
	note := GateNote(unsafeResult(), &decision)
	if !strings.Contains(note, "UNSAFE") || !strings.Contains(note, "HIGH threshold") {
		t.Fatalf("gate note does not explain the pass: %q", note)
	}
}

func TestGateNoteExplainsFailingWithUnsafe(t *testing.T) {
	decision := policy.Decision{Pass: false, ExitCode: policy.ExitPolicyFail, Reason: "HIGH finding \"x\" (r) is at or above the --fail-on threshold HIGH"}
	note := GateNote(unsafeResult(), &decision)
	if !strings.Contains(note, "UNSAFE") || !strings.Contains(note, "exits 2") {
		t.Fatalf("gate note does not explain the failure: %q", note)
	}
}

func TestGateNoteEmptyWhenSafe(t *testing.T) {
	decision := policy.Decision{Pass: true, ExitCode: policy.ExitOK, Reason: "no severity gate configured"}
	safe := &model.ScanResult{Status: model.StatusCompleted, Verdict: model.VerdictSafe}
	if note := GateNote(safe, &decision); note != "" {
		t.Fatalf("expected no gate note for a SAFE verdict, got %q", note)
	}
}

func TestGateNoteEmptyWhenNoDecision(t *testing.T) {
	if note := GateNote(unsafeResult(), nil); note != "" {
		t.Fatalf("expected no gate note with a nil decision, got %q", note)
	}
}

func TestGateNoteExplainsAToleratedIncompleteScan(t *testing.T) {
	res := &model.ScanResult{Status: model.StatusPartial, Verdict: model.VerdictUnknown}
	note := GateNote(res, &policy.Decision{Pass: true, Reason: "incomplete scan tolerated by policy"})
	if note == "" {
		t.Fatal("an incomplete scan that exits 0 explained nothing")
	}
	if !strings.Contains(note, "PARTIAL") || !strings.Contains(note, "tolerated") {
		t.Errorf("note = %q, want the status and the reason it passed", note)
	}

	// A completed scan with a verdict that is not UNSAFE has nothing to
	// explain: the exit code and the verdict already agree
	clean := &model.ScanResult{Status: model.StatusCompleted, Verdict: model.VerdictSafe}
	if note := GateNote(clean, &policy.Decision{Pass: true, Reason: "no finding reached the threshold"}); note != "" {
		t.Errorf("note = %q, want none for a clean completed scan", note)
	}

	// An incomplete scan that does not pass needs no note either - the
	// non-zero exit is not the thing that looks contradictory
	if note := GateNote(res, &policy.Decision{Pass: false, Reason: "incomplete", ExitCode: 3}); note != "" {
		t.Errorf("note = %q, want none when the scan already fails the gate", note)
	}
}
