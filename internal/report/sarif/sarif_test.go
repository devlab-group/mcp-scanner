package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/pkg/model"
)

func finding(rule string, sev model.Severity, file string, line int) model.Finding {
	return model.Finding{
		RuleID: rule, Category: "test_category", Title: "title " + rule,
		Severity: sev, Confidence: 0.8, EvidenceLevel: model.EvidenceStatic,
		File: file, Line: line, Description: "description for " + rule,
		Analyzer: "test",
		Evidence: []model.Evidence{{Level: model.EvidenceStatic, Description: "e"}},
	}
}

func sampleResult() *model.ScanResult {
	r := &model.ScanResult{
		ScanID: "scan_1", Status: model.StatusCompleted, Verdict: model.VerdictUnsafe,
		Findings: []model.Finding{
			finding("rule.a", model.SeverityCritical, "a.go", 10),
			finding("rule.b", model.SeverityMedium, "b.go", 0),
			finding("rule.a", model.SeverityCritical, "c.go", 5), // same rule again, must not duplicate in driver.rules
		},
	}
	return r
}

// A loose decode shape for structural checks, since we cannot pull in a
// SARIF schema validator without adding a dependency
type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID         string `json:"id"`
					Properties struct {
						SecuritySeverity string   `json:"security-severity"`
						Tags             []string `json:"tags"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Level     string `json:"level"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Properties          struct {
				SecuritySeverity string `json:"security-severity"`
			} `json:"properties"`
			Suppressions []struct {
				Kind          string `json:"kind"`
				Status        string `json:"status"`
				Justification string `json:"justification"`
			} `json:"suppressions"`
		} `json:"results"`
		Invocations []struct {
			ExecutionSuccessful        bool `json:"executionSuccessful"`
			ToolExecutionNotifications []struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		Properties struct {
			Status  string `json:"mcpScannerStatus"`
			Verdict string `json:"mcpScannerVerdict"`
		} `json:"properties"`
	} `json:"runs"`
}

func TestOutputIsStructurallyValidSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}

	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output did not parse as JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", doc.Version)
	}
	if doc.Schema == "" {
		t.Fatal("missing $schema")
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != toolName {
		t.Fatalf("driver name = %q, want %q", run.Tool.Driver.Name, toolName)
	}

	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("got %d rules, want 2 (rule.a must be declared once despite two findings): %+v", len(run.Tool.Driver.Rules), run.Tool.Driver.Rules)
	}
	if len(run.Results) != 3 {
		t.Fatalf("got %d results, want 3 (one per finding)", len(run.Results))
	}

	allowedLevels := map[string]bool{"error": true, "warning": true, "note": true, "none": true}
	for _, r := range run.Results {
		if !allowedLevels[r.Level] {
			t.Fatalf("result has an invalid SARIF level %q", r.Level)
		}
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("ruleIndex %d out of bounds for %d rules", r.RuleIndex, len(run.Tool.Driver.Rules))
		}
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Fatalf("ruleIndex %d does not point at ruleId %q", r.RuleIndex, r.RuleID)
		}
		if r.Properties.SecuritySeverity == "" {
			t.Fatal("result missing security-severity property")
		}
	}

	foundCritical, foundMedium := false, false
	for _, r := range run.Results {
		switch r.RuleID {
		case "rule.a":
			foundCritical = true
			if r.Level != "error" {
				t.Fatalf("CRITICAL finding level = %q, want error", r.Level)
			}
			if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.Region.StartLine == 0 {
				t.Fatal("expected a location with a line number for rule.a")
			}
		case "rule.b":
			foundMedium = true
			if r.Level != "warning" {
				t.Fatalf("MEDIUM finding level = %q, want warning", r.Level)
			}
			if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "b.go" {
				t.Fatal("expected a file-only location for rule.b")
			}
		}
	}
	if !foundCritical || !foundMedium {
		t.Fatal("did not find both expected results")
	}
}

func TestHostileContentIsSanitized(t *testing.T) {
	r := &model.ScanResult{Findings: []model.Finding{
		{RuleID: "rule.hostile", Category: "x", Title: "clear\x1b[2Jscreen", Severity: model.SeverityHigh,
			Confidence: 0.5, EvidenceLevel: model.EvidenceHeuristic, File: "f.go",
			Description: "desc\x1b[2J", Analyzer: "test", Evidence: []model.Evidence{{Level: model.EvidenceHeuristic}}},
	}}
	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Fatal("a raw ESC byte from finding content reached the SARIF output")
	}
}

func TestMultiLineDescriptionIsPreserved(t *testing.T) {
	r := &model.ScanResult{Findings: []model.Finding{
		{RuleID: "rule.a", Category: "x", Title: "t", Severity: model.SeverityHigh,
			Confidence: 0.5, EvidenceLevel: model.EvidenceHeuristic, File: "f.go",
			Description: "line one\nline two\nline three", Analyzer: "test",
			Evidence: []model.Evidence{{Level: model.EvidenceHeuristic}}},
	}}
	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	msg := doc.Runs[0].Results[0].Message.Text
	if !strings.Contains(msg, "line one\nline two\nline three") {
		t.Fatalf("multi-line description was not preserved: %q", msg)
	}
}

func TestWriteManyProducesOneRunPerResult(t *testing.T) {
	a := sampleResult()
	a.ScanID = "scan_a"
	b := &model.ScanResult{ScanID: "scan_b", Status: model.StatusCompleted, Verdict: model.VerdictSafe}

	var buf bytes.Buffer
	if err := WriteMany(&buf, []*model.ScanResult{a, b}); err != nil {
		t.Fatal(err)
	}

	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output did not parse as JSON: %v", err)
	}
	if len(doc.Runs) != 2 {
		t.Fatalf("got %d runs, want 2 (one per target)", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 3 {
		t.Fatalf("first run has %d results, want 3", len(doc.Runs[0].Results))
	}
	if len(doc.Runs[1].Results) != 0 {
		t.Fatalf("second run (no findings) has %d results, want 0", len(doc.Runs[1].Results))
	}
}

func TestResultsCarryDistinctPartialFingerprints(t *testing.T) {
	a := finding("rule.a", model.SeverityHigh, "server.py", 11)
	b := finding("rule.a", model.SeverityHigh, "server.py", 18)
	a.EnsureID("")
	b.EnsureID("")
	r := &model.ScanResult{Findings: []model.Finding{a, b}}

	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("got %d results, want 2", len(doc.Runs[0].Results))
	}
	fp0 := doc.Runs[0].Results[0].PartialFingerprints["mcpScannerFindingId"]
	fp1 := doc.Runs[0].Results[1].PartialFingerprints["mcpScannerFindingId"]
	if fp0 == "" || fp1 == "" {
		t.Fatalf("expected both results to carry a partialFingerprints entry, got %q and %q", fp0, fp1)
	}
	if fp0 == fp1 {
		t.Fatalf("two findings differing only by line got the same fingerprint: %q", fp0)
	}
}

func TestSuppressedFindingCarriesASuppressionsEntry(t *testing.T) {
	live := finding("taint.command_injection", model.SeverityHigh, "a.go", 1)
	suppressed := finding("taint.path_traversal", model.SeverityHigh, "b.go", 2)
	suppressed.Suppressed = true
	suppressed.SuppressionReason = "accepted: known safe pattern"

	r := &model.ScanResult{Findings: []model.Finding{live, suppressed}}
	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}

	var gotLive, gotSuppressed bool
	for _, res := range doc.Runs[0].Results {
		switch res.RuleID {
		case "taint.command_injection":
			gotLive = true
			if len(res.Suppressions) != 0 {
				t.Fatalf("live finding must not carry a suppressions entry: %+v", res.Suppressions)
			}
		case "taint.path_traversal":
			gotSuppressed = true
			if len(res.Suppressions) != 1 {
				t.Fatalf("suppressed finding must carry exactly one suppressions entry, got %+v", res.Suppressions)
			}
			sup := res.Suppressions[0]
			if sup.Kind != "external" {
				t.Fatalf("kind = %q, want external: the suppression came from a baseline, not source", sup.Kind)
			}
			if sup.Status != "accepted" {
				t.Fatalf("status = %q, want accepted", sup.Status)
			}
			if !strings.Contains(sup.Justification, "known safe pattern") {
				t.Fatalf("justification = %q, want the baseline reason", sup.Justification)
			}
		}
	}
	if !gotLive || !gotSuppressed {
		t.Fatal("did not find both expected results")
	}
}

func TestScanWarningsBecomeToolExecutionNotifications(t *testing.T) {
	r := &model.ScanResult{Status: model.StatusCompleted, Warnings: []string{
		"every analyzer that ran was best-effort, so no analyzer's result was required for this verdict",
	}}
	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("got %d invocations, want 1", len(doc.Runs[0].Invocations))
	}
	inv := doc.Runs[0].Invocations[0]
	if !inv.ExecutionSuccessful {
		t.Fatal("executionSuccessful must be true: the scan completed, and a warning does not change that")
	}
	if len(inv.ToolExecutionNotifications) != 1 {
		t.Fatalf("got %d notifications, want 1", len(inv.ToolExecutionNotifications))
	}
	if !strings.Contains(inv.ToolExecutionNotifications[0].Message.Text, "best-effort") {
		t.Fatalf("notification text = %q, want the warning text", inv.ToolExecutionNotifications[0].Message.Text)
	}
}

func TestEveryRunCarriesAnInvocation(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("got %d invocations, want 1", len(doc.Runs[0].Invocations))
	}
	if !doc.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("executionSuccessful = false for a COMPLETED scan")
	}
}

func TestExecutionSuccessfulTracksScanStatus(t *testing.T) {
	for _, tc := range []struct {
		status model.ScanStatus
		want   bool
	}{
		{model.StatusCompleted, true},
		{model.StatusError, false},
		{model.StatusPartial, false},
		{model.StatusSkipped, false},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			var buf bytes.Buffer
			r := &model.ScanResult{Status: tc.status, Verdict: model.VerdictUnknown}
			if err := Write(&buf, r); err != nil {
				t.Fatal(err)
			}
			var doc sarifDoc
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Runs[0].Invocations) != 1 {
				t.Fatalf("got %d invocations, want 1", len(doc.Runs[0].Invocations))
			}
			if got := doc.Runs[0].Invocations[0].ExecutionSuccessful; got != tc.want {
				t.Fatalf("executionSuccessful = %v for status %s, want %v", got, tc.status, tc.want)
			}
		})
	}
}

func TestVerdictReasonsReachTheDocument(t *testing.T) {
	r := &model.ScanResult{
		Status:  model.StatusError,
		Verdict: model.VerdictUnknown,
		VerdictReasons: []string{
			`required analyzer "auth" failed`,
			"source: 3 of 40 files were not parsed",
		},
		Warnings: []string{`best-effort analyzer "llm" finished as SKIPPED`},
	}
	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, n := range doc.Runs[0].Invocations[0].ToolExecutionNotifications {
		texts = append(texts, n.Message.Text)
	}
	joined := strings.Join(texts, "\n")
	for _, want := range []string{`required analyzer "auth" failed`, "3 of 40 files", `best-effort analyzer "llm"`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("notifications = %q, want one containing %q", joined, want)
		}
	}
	if doc.Runs[0].Properties.Status != string(model.StatusError) {
		t.Fatalf("run properties status = %q, want %q", doc.Runs[0].Properties.Status, model.StatusError)
	}
	if doc.Runs[0].Properties.Verdict != string(model.VerdictUnknown) {
		t.Fatalf("run properties verdict = %q, want %q", doc.Runs[0].Properties.Verdict, model.VerdictUnknown)
	}
}

// Verdict reasons are built from analyzer names and coverage gaps, and a
// coverage gap can quote a path that came out of the scanned target
func TestVerdictReasonsAreSanitized(t *testing.T) {
	r := &model.ScanResult{
		Status:         model.StatusPartial,
		VerdictReasons: []string{"source: skipped \x1b[31mevil\x1b[0m\u0007.go"},
	}
	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(buf.String(), "\x1b\a") {
		t.Fatalf("control characters survived into the document: %q", buf.String())
	}
}

func TestWriteManyWithNoResultsWritesEmptyRuns(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMany(&buf, nil); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output did not parse as JSON: %v", err)
	}
	if doc.Runs == nil || len(doc.Runs) != 0 {
		t.Fatalf("runs = %v, want an empty array", doc.Runs)
	}
}

func TestRuleIDAndCategoryAreSanitized(t *testing.T) {
	f := finding("rule.hostile\x1b[2J", model.SeverityHigh, "f.go", 1)
	f.Category = "cat\x1b[2J"
	var buf bytes.Buffer
	if err := Write(&buf, &model.ScanResult{Findings: []model.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Fatalf("a raw ESC byte from a rule id or category reached the SARIF output: %s", buf.String())
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	rule := doc.Runs[0].Tool.Driver.Rules[0]
	if strings.ContainsRune(rule.ID, 0x1b) {
		t.Fatalf("rule id not sanitized: %q", rule.ID)
	}
	if rule.ID != doc.Runs[0].Results[0].RuleID {
		t.Fatalf("the rules table id %q and the result ruleId %q must stay the same string", rule.ID, doc.Runs[0].Results[0].RuleID)
	}
	if len(rule.Properties.Tags) != 1 || strings.Contains(rule.Properties.Tags[0], "\x1b") {
		t.Fatalf("category tag not sanitized: %#v", rule.Properties.Tags)
	}
}

func TestEmptyRuleIDGetsAPlaceholderID(t *testing.T) {
	f := finding("rule.a", model.SeverityHigh, "a.go", 1)
	bad := finding("", model.SeverityLow, "b.go", 2)
	var buf bytes.Buffer
	if err := Write(&buf, &model.ScanResult{Findings: []model.Finding{f, bad}}); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		if r.ID == "" {
			t.Fatalf("a rule was emitted with an empty id, which is not valid SARIF: %s", buf.String())
		}
	}
	var ids []string
	for _, r := range doc.Runs[0].Results {
		ids = append(ids, r.RuleID)
		if r.RuleID == "" {
			t.Fatalf("a result was emitted with an empty ruleId: %s", buf.String())
		}
	}
	if len(ids) != 2 || ids[1] != "mcp-scanner.invalid-finding" {
		t.Fatalf("expected the invalid finding to carry the placeholder id, got %v", ids)
	}
}
