package table

import (
	"bytes"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/internal/policy"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func result(status model.ScanStatus, verdict model.Verdict) *model.ScanResult {
	return &model.ScanResult{
		ScanID: "scan_1", Status: status, Verdict: verdict,
		Target: model.Target{Kind: model.TargetSource, Path: "."},
	}
}

func TestSafeAndUnsafeBannersAreDistinct(t *testing.T) {
	var safeBuf, unsafeBuf bytes.Buffer
	Write(&safeBuf, result(model.StatusCompleted, model.VerdictSafe), nil)
	Write(&unsafeBuf, result(model.StatusCompleted, model.VerdictUnsafe), nil)
	if safeBuf.String() == unsafeBuf.String() {
		t.Fatal("SAFE and UNSAFE produced identical output")
	}
	if !strings.Contains(safeBuf.String(), "SAFE") {
		t.Fatal("SAFE result does not mention SAFE")
	}
	if !strings.Contains(unsafeBuf.String(), "UNSAFE") {
		t.Fatal("UNSAFE result does not mention UNSAFE")
	}
}

func TestPartialLooksNothingLikeSafe(t *testing.T) {
	var safeBuf, partialBuf bytes.Buffer
	Write(&safeBuf, result(model.StatusCompleted, model.VerdictSafe), nil)
	r := result(model.StatusPartial, model.VerdictUnknown)
	r.VerdictReasons = []string{"required analyzer \"protocol\" finished as PARTIAL"}
	Write(&partialBuf, r, nil)

	safeLines := strings.Split(strings.TrimSpace(safeBuf.String()), "\n")
	if len(safeLines) == 0 || !strings.Contains(safeLines[0], "STATUS: COMPLETED") {
		t.Fatalf("SAFE banner unexpected: %q", safeBuf.String())
	}
	if !strings.Contains(partialBuf.String(), "DID NOT COMPLETE") {
		t.Fatal("PARTIAL output must clearly say the scan did not complete")
	}
	if strings.HasPrefix(strings.TrimSpace(partialBuf.String()), "STATUS: COMPLETED") {
		t.Fatal("PARTIAL result rendered the same clean single-line banner as a COMPLETED scan")
	}
}

func TestHostileFindingContentCannotRepaintTerminal(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictUnsafe)
	r.Findings = []model.Finding{{
		RuleID: "r1", Title: "clear\x1b[2Jscreen", Severity: model.SeverityHigh,
		Confidence: 0.5, EvidenceLevel: model.EvidenceHeuristic,
		File: "\x1b]0;pwned\x07evil.go", Analyzer: "test",
		Evidence: []model.Evidence{{Level: model.EvidenceHeuristic}},
	}}
	var buf bytes.Buffer
	if err := Write(&buf, r, nil); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Fatalf("a raw ESC byte from a finding reached table output: %q", buf.String())
	}
}

func TestHostileFilenameCannotSpoofDisplayViaBidi(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictUnsafe)
	r.Findings = []model.Finding{{
		RuleID: "r1", Title: "t", Severity: model.SeverityHigh, Confidence: 0.5,
		EvidenceLevel: model.EvidenceHeuristic,
		File:          "gpj.‮og.evil.go",
		Analyzer:      "test",
		Evidence:      []model.Evidence{{Level: model.EvidenceHeuristic}},
	}}
	var buf bytes.Buffer
	if err := Write(&buf, r, nil); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(buf.String(), 0x202e) {
		t.Fatalf("a raw bidi override reached table output: %q", buf.String())
	}
	if !strings.Contains(buf.String(), `\u202e`) {
		t.Fatalf("expected an escaped \\u202e marker in the file column: %q", buf.String())
	}
}

func TestHostileFilenameCannotForgeTableRow(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictUnsafe)
	r.Findings = []model.Finding{{
		RuleID: "r1", Title: "t", Severity: model.SeverityHigh, Confidence: 0.5,
		EvidenceLevel: model.EvidenceHeuristic,
		File:          "evil.go\nINFO\tfake.rule\t\"no issues found\"",
		Analyzer:      "test",
		Evidence:      []model.Evidence{{Level: model.EvidenceHeuristic}},
	}}
	var buf bytes.Buffer
	if err := Write(&buf, r, nil); err != nil {
		t.Fatal(err)
	}

	for line := range strings.SplitSeq(buf.String(), "\n") {
		if strings.Contains(line, "fake.rule") && !strings.Contains(line, "r1") {
			t.Fatalf("a forged row reached table output on its own line: %q", line)
		}
	}
	if !strings.Contains(buf.String(), `\x0a`) || !strings.Contains(buf.String(), `\x09`) {
		t.Fatalf("expected the embedded newline/tab to show up escaped, not acted on: %q", buf.String())
	}
}

func TestContributionNoteIsPresent(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictSafe)
	r.Analyzers = []model.AnalyzerResult{
		{Analyzer: "a", Status: model.AnalyzerCompleted},
		{Analyzer: "b", Status: model.AnalyzerSkipped},
		{Analyzer: "c", Status: model.AnalyzerCompleted},
	}
	var buf bytes.Buffer
	Write(&buf, r, nil)
	if !strings.Contains(buf.String(), "2 of 3 analyzers contributed to this verdict") {
		t.Fatalf("expected a contribution note, got: %s", buf.String())
	}
}

func TestGateNoteAppearsForUnsafeWithPassingPolicy(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictUnsafe)
	decision := policy.Decision{Pass: true, ExitCode: policy.ExitOK, Reason: "no finding reached the HIGH threshold"}
	var buf bytes.Buffer
	Write(&buf, r, &decision)
	if !strings.Contains(buf.String(), "UNSAFE") || !strings.Contains(buf.String(), "still exits 0") {
		t.Fatalf("expected a gate note explaining the pass, got: %s", buf.String())
	}
}

func TestWarningsAndGapsAreSanitized(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictSafe)
	r.Warnings = []string{"warn\x1b[2J"}

	r.Analyzers = []model.AnalyzerResult{{
		Analyzer: "source",
		Status:   model.AnalyzerCompleted,
		Coverage: model.Coverage{FilesDiscovered: 5, FilesFailed: 5, LimitsHit: []string{"limit\x1b[2J"}},
	}}
	r.Coverage = model.Coverage{FilesDiscovered: 5, FilesFailed: 5}
	var buf bytes.Buffer
	Write(&buf, r, nil)
	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Fatal("a raw ESC byte in a warning/coverage gap reached table output")
	}
	if !strings.Contains(buf.String(), "gap:") {
		t.Fatal("expected a coverage gap to be rendered")
	}
}

func TestCoverageLineSaysWhenItIsAMergedSummary(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictSafe)
	r.Coverage = model.Coverage{FilesDiscovered: 1, FilesParsed: 1, FilesSkipped: 1}
	var buf bytes.Buffer
	Write(&buf, r, nil)
	if !strings.Contains(buf.String(), "not one population") {
		t.Errorf("a merged coverage line must say it is one:\n%s", buf.String())
	}

	consistent := result(model.StatusCompleted, model.VerdictSafe)
	consistent.Coverage = model.Coverage{FilesDiscovered: 2, FilesParsed: 1, FilesSkipped: 1}
	buf.Reset()
	Write(&buf, consistent, nil)
	if strings.Contains(buf.String(), "not one population") {
		t.Errorf("a record that adds up must not be labelled:\n%s", buf.String())
	}
}

// Every non-COMPLETED status shows the incomplete banner and its reason
func TestEveryIncompleteStatusShowsItsReasons(t *testing.T) {
	const reason = `required analyzer "protocol" did not finish`
	for _, status := range []model.ScanStatus{model.StatusPartial, model.StatusError, model.StatusSkipped} {
		r := result(status, model.VerdictUnknown)
		r.VerdictReasons = []string{reason}
		var buf bytes.Buffer
		if err := Write(&buf, r, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "DID NOT COMPLETE") {
			t.Errorf("%s: no incomplete banner in %q", status, buf.String())
		}
		if !strings.Contains(buf.String(), reason) {
			t.Errorf("%s: the verdict reason is not printed", status)
		}
	}
}

// Sanitize target-controlled text in reasons, warnings, and target names
func TestReasonsWarningsAndTargetAreSanitized(t *testing.T) {
	r := result(model.StatusPartial, model.VerdictUnknown)
	r.Target = model.Target{Kind: model.TargetStatic, Name: "server\x1b]0;pwned\x07"}
	r.VerdictReasons = []string{"analyzer said \x1b[2J"}
	r.Warnings = []string{"warning \x1b[31mred"}
	var buf bytes.Buffer
	if err := Write(&buf, r, nil); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Fatalf("a raw ESC byte reached table output: %q", buf.String())
	}
}
