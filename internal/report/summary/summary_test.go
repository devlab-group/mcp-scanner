package summary

import (
	"bytes"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func result(status model.ScanStatus, verdict model.Verdict) *model.ScanResult {
	return &model.ScanResult{Target: model.Target{Kind: model.TargetSource, Path: "."}, Status: status, Verdict: verdict}
}

func TestSafeAndPartialAreVisuallyDistinct(t *testing.T) {
	var safeBuf, partialBuf bytes.Buffer
	Write(&safeBuf, result(model.StatusCompleted, model.VerdictSafe), nil)
	Write(&partialBuf, result(model.StatusPartial, model.VerdictUnknown), nil)

	if strings.Contains(safeBuf.String(), "INCOMPLETE") {
		t.Fatal("a clean SAFE scan must not carry the incomplete marker")
	}
	if !strings.Contains(partialBuf.String(), "INCOMPLETE") {
		t.Fatal("a PARTIAL scan must carry a clearly different marker than SAFE")
	}
}

func TestFindingCountsAndTopFindingsCap(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictUnsafe)
	for range 8 {
		r.Findings = append(r.Findings, model.Finding{
			RuleID: "r", Title: "t", Severity: model.SeverityHigh, Confidence: 0.5,
			EvidenceLevel: model.EvidenceHeuristic, Analyzer: "test",
			Evidence: []model.Evidence{{Level: model.EvidenceHeuristic}},
		})
	}
	var buf bytes.Buffer
	Write(&buf, r, nil)
	out := buf.String()
	if !strings.Contains(out, "8 high") {
		t.Fatalf("expected the true count (8 high) in the summary, got: %s", out)
	}
	if !strings.Contains(out, "and 3 more") {
		t.Fatalf("expected the overflow past maxTopFindings to be noted, got: %s", out)
	}
}

func TestContributionNoteIsPresent(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictSafe)
	r.Analyzers = []model.AnalyzerResult{
		{Analyzer: "a", Status: model.AnalyzerCompleted},
		{Analyzer: "b", Status: model.AnalyzerSkipped},
		{Analyzer: "c", Status: model.AnalyzerUnavailable},
	}
	var buf bytes.Buffer
	Write(&buf, r, nil)
	if !strings.Contains(buf.String(), "1 of 3 analyzers contributed to this verdict") {
		t.Fatalf("expected a contribution note, got: %s", buf.String())
	}
}

func TestHostileContentIsSanitized(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictUnsafe)
	r.Findings = []model.Finding{{
		RuleID: "r1", Title: "clear\x1b[2Jscreen", Severity: model.SeverityHigh, Confidence: 0.5,
		EvidenceLevel: model.EvidenceHeuristic, File: "evil\x1b[0m.go", Analyzer: "test",
		Evidence: []model.Evidence{{Level: model.EvidenceHeuristic}},
	}}
	var buf bytes.Buffer
	Write(&buf, r, nil)
	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Fatalf("a raw ESC byte reached summary output: %q", buf.String())
	}
}

func TestSuppressedFindingsDoNotOutrankLiveOnesInTopFindings(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictUnsafe)
	r.Findings = []model.Finding{
		{
			RuleID: "suppressed-high", Title: "t", Severity: model.SeverityHigh, Confidence: 0.9,
			EvidenceLevel: model.EvidenceHeuristic, Analyzer: "test", Suppressed: true, SuppressionReason: "accepted",
			Evidence: []model.Evidence{{Level: model.EvidenceHeuristic}},
		},
		{
			RuleID: "live-medium", Title: "t", Severity: model.SeverityMedium, Confidence: 0.9,
			EvidenceLevel: model.EvidenceHeuristic, Analyzer: "test",
			Evidence: []model.Evidence{{Level: model.EvidenceHeuristic}},
		},
	}
	var buf bytes.Buffer
	Write(&buf, r, nil)
	out := buf.String()

	if !strings.Contains(out, "0 critical, 0 high, 1 medium") {
		t.Fatalf("expected the count line to exclude the suppressed HIGH, got: %s", out)
	}
	live := strings.Index(out, "live-medium")
	suppressed := strings.Index(out, "suppressed-high")
	if live == -1 || suppressed == -1 {
		t.Fatalf("expected both findings listed, got: %s", out)
	}
	if live > suppressed {
		t.Fatalf("a suppressed finding was listed ahead of a live one: %s", out)
	}
	if !strings.Contains(out, "[HIGH (suppressed)] suppressed-high") {
		t.Fatalf("expected the suppressed finding labeled the way the table writer labels it, got: %s", out)
	}
}

func TestCoverageGapsSurviveTheScanLevelMerge(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictSafe)
	r.Analyzers = []model.AnalyzerResult{
		{
			Analyzer: "a", Status: model.AnalyzerCompleted,
			Coverage: model.Coverage{FilesDiscovered: 2, FilesParsed: 0, FilesSkipped: 2, SkipReasons: []string{"unsupported format"}},
		},
		{
			Analyzer: "b", Status: model.AnalyzerCompleted,
			Coverage: model.Coverage{FilesDiscovered: 1, FilesParsed: 1},
		},
	}
	r.Coverage.Merge(r.Analyzers[0].Coverage)
	r.Coverage.Merge(r.Analyzers[1].Coverage)

	if len(r.Coverage.Gaps()) != 0 {
		t.Fatalf("test setup is wrong: expected the merged record to hide the gap, got %v", r.Coverage.Gaps())
	}

	var buf bytes.Buffer
	Write(&buf, r, nil)
	out := buf.String()
	if !strings.Contains(out, "coverage gaps:") {
		t.Fatalf("analyzer %q parsed zero of the files it discovered - that must surface even though the merged scan-level Coverage hides it, got: %s", "a", out)
	}
	if !strings.Contains(out, "a: no file was parsed successfully") {
		t.Fatalf("expected the gap attributed to analyzer %q, got: %s", "a", out)
	}
}

// An UNSAFE verdict that still exits 0 (a LOW finding under a
// HIGH --fail-on) must say so next to the verdict
func TestGateNoteAppearsForUnsafeWithPassingPolicy(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictUnsafe)
	decision := policy.Decision{Pass: true, ExitCode: policy.ExitOK, Reason: "no finding reached the HIGH threshold"}
	var buf bytes.Buffer
	Write(&buf, r, &decision)
	if !strings.Contains(buf.String(), "UNSAFE") || !strings.Contains(buf.String(), "still exits 0") {
		t.Fatalf("expected a gate note explaining the pass, got: %s", buf.String())
	}
}

func TestWarningsAreShownRightAfterTheVerdict(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictSafe)
	r.Warnings = []string{"every analyzer that ran was best-effort, so no analyzer's result was required for this verdict"}
	var buf bytes.Buffer
	Write(&buf, r, nil)
	out := buf.String()

	if !strings.Contains(out, "warnings:") || !strings.Contains(out, "best-effort") {
		t.Fatalf("expected the scan-level warning to appear, got: %s", out)
	}
	verdictAt := strings.Index(out, "verdict: SAFE")
	warningsAt := strings.Index(out, "warnings:")
	findingsAt := strings.Index(out, "findings:")
	if verdictAt == -1 || warningsAt == -1 || findingsAt == -1 {
		t.Fatalf("missing an expected section, got: %s", out)
	}
	if !(verdictAt < warningsAt && warningsAt < findingsAt) {
		t.Fatalf("warnings must sit between the verdict and the rest of the summary, got: %s", out)
	}
}

func TestNoWarningsPrintsNoWarningsSection(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictSafe)
	var buf bytes.Buffer
	Write(&buf, r, nil)
	if strings.Contains(buf.String(), "warnings:") {
		t.Fatalf("expected no warnings section when there are none, got: %s", buf.String())
	}
}

func TestAnalyzerGapsExcludesExcusedAnalyzers(t *testing.T) {
	r := result(model.StatusCompleted, model.VerdictSafe)
	r.Analyzers = []model.AnalyzerResult{
		{Analyzer: "source", Status: model.AnalyzerCompleted, Coverage: model.Coverage{FilesDiscovered: 1, FilesParsed: 1}},
		{Analyzer: "yara", Status: model.AnalyzerUnavailable},
		{Analyzer: "llm", Status: model.AnalyzerSkipped},
	}
	var buf bytes.Buffer
	Write(&buf, r, nil)
	out := buf.String()
	if strings.Contains(out, "yara:") || strings.Contains(out, "llm:") {
		t.Fatalf("an excused analyzer must not contribute coverage gap noise, got: %s", out)
	}
	if strings.Contains(out, "coverage gaps:") {
		t.Fatalf("the only analyzer that ran had full coverage, expected no gaps section, got: %s", out)
	}
}

// A PARTIAL analyzer is not excused - it produced usable output but could
// not finish - so its own gaps still belong in the summary
func TestAnalyzerGapsIncludesAPartialAnalyzer(t *testing.T) {
	r := result(model.StatusPartial, model.VerdictUnknown)
	r.Analyzers = []model.AnalyzerResult{
		{Analyzer: "taint", Status: model.AnalyzerPartial, Required: true,
			Coverage: model.Coverage{FilesDiscovered: 2, FilesParsed: 1, FilesSkipped: 1}},
	}
	var buf bytes.Buffer
	Write(&buf, r, nil)
	out := buf.String()
	if !strings.Contains(out, "taint:") {
		t.Fatalf("a PARTIAL analyzer's own gaps must still be shown, got: %s", out)
	}
}

// Every non-COMPLETED status shows the incomplete marker and its reason
func TestEveryIncompleteStatusShowsItsReasons(t *testing.T) {
	const reason = `required analyzer "protocol" did not finish`
	for _, status := range []model.ScanStatus{model.StatusPartial, model.StatusError, model.StatusSkipped} {
		r := result(status, model.VerdictUnknown)
		r.VerdictReasons = []string{reason}
		var buf bytes.Buffer
		if err := Write(&buf, r, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "INCOMPLETE") {
			t.Errorf("%s: no incomplete marker in %q", status, buf.String())
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
		t.Fatalf("a raw ESC byte reached summary output: %q", buf.String())
	}
}
