package json

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func sampleResult() *model.ScanResult {
	r := &model.ScanResult{
		SchemaVersion:  model.SchemaVersion,
		ScanID:         "scan_deadbeef",
		ScannerVersion: "test",
		Target:         model.Target{Kind: model.TargetRemote, Name: "example", URL: "https://example.com/mcp"},
		Status:         model.StatusCompleted,
		Verdict:        model.VerdictUnsafe,
		VerdictReasons: []string{"HIGH finding \"bad tool\" from protocol", "another reason"},
		Coverage: model.Coverage{
			FilesDiscovered: 10, FilesParsed: 8, FilesFailed: 1, FilesSkipped: 1,
			SkipReasons:            []string{"1 file in an unsupported language"},
			CapabilitiesDiscovered: 5, CapabilitiesAnalyzed: 5,
		},
		Analyzers: []model.AnalyzerResult{{
			Analyzer: "protocol",
			Status:   model.AnalyzerCompleted,
			Required: true,
			Findings: []model.Finding{{
				RuleID:        "protocol.unsafe_tool",
				Category:      "tool_poisoning",
				Title:         "bad tool",
				Severity:      model.SeverityHigh,
				Confidence:    0.87,
				EvidenceLevel: model.EvidenceStatic,
				File:          "server.go",
				Line:          42,
				Tool:          "delete_all",
				Description:   "a tool description that hides an instruction",
				Remediation:   "remove the hidden instruction",
				Analyzer:      "protocol",
				Taxonomy:      []model.TaxonomyReference{{Scheme: "CWE", ID: "CWE-77", URL: "https://cwe.mitre.org/data/definitions/77.html"}},
				Suppressed:    true, SuppressionReason: "accepted risk for now",
				Evidence: []model.Evidence{{
					Level:       model.EvidenceStatic,
					Kind:        "yara_match",
					Description: "matched rule X",
					File:        "server.go",
					Line:        42,
					Snippet:     "os.exec(...)",
					Path: []model.FlowStep{
						{Kind: "source", Symbol: "input", File: "a.go", Line: 1, Resolved: true},
						{Kind: "sink", Symbol: "exec", File: "b.go", Line: 2, Resolved: true},
					},
					Data: map[string]any{"score": 0.9},
				}},
			}},
			Warnings: []string{"a warning"},
			Errors:   []model.AnalyzerError{{Kind: "network", Message: "flaky", Fatal: false}},
			Coverage: model.Coverage{FilesDiscovered: 10, FilesParsed: 8, FilesFailed: 1, FilesSkipped: 1, SkipReasons: []string{"1 file in an unsupported language"}},
		}},
		Snapshot: &model.Snapshot{
			SchemaVersion: "1.0.0",
			ServerName:    "evil-server",
			Tools:         []model.ToolInfo{{Name: "delete_all", Description: "deletes everything"}},
			Transport:     model.TransportInfo{Kind: "stdio"},
		},
		StartedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 1, 1, 0, 0, 5, 0, time.UTC),
		Duration:   5 * time.Second,
		Warnings:   []string{"top-level warning"},
	}
	r.Findings = r.Analyzers[0].Findings
	return r
}

func TestRoundTripIsLossless(t *testing.T) {
	original := sampleResult()

	var buf bytes.Buffer
	if err := Write(&buf, original); err != nil {
		t.Fatal(err)
	}

	var got model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("round-tripped JSON did not parse: %v", err)
	}

	wantTargetJSON, _ := json.Marshal(original.Target)
	gotTargetJSON, _ := json.Marshal(got.Target)
	if !bytes.Equal(wantTargetJSON, gotTargetJSON) {
		t.Fatalf("target mismatch:\nwant %s\ngot  %s", wantTargetJSON, gotTargetJSON)
	}

	checks := []struct {
		name      string
		want, got any
	}{
		{"findings", original.Findings, got.Findings},
		{"analyzers", original.Analyzers, got.Analyzers},
		{"coverage", original.Coverage, got.Coverage},
		{"verdict_reasons", original.VerdictReasons, got.VerdictReasons},
		{"status", original.Status, got.Status},
		{"verdict", original.Verdict, got.Verdict},
		{"snapshot", original.Snapshot, got.Snapshot},
		{"warnings", original.Warnings, got.Warnings},
		{"scan_id", original.ScanID, got.ScanID},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.want, c.got) {
			t.Fatalf("%s not preserved by the round trip:\nwant %#v\ngot  %#v", c.name, c.want, c.got)
		}
	}

	ev := got.Findings[0].Evidence[0]
	if ev.Snippet != "os.exec(...)" || len(ev.Path) != 2 || ev.Data["score"] != 0.9 {
		t.Fatalf("evidence detail lost: %+v", ev)
	}
	if !got.Findings[0].Suppressed || got.Findings[0].SuppressionReason == "" {
		t.Fatal("suppression state lost")
	}
}

func TestSecretFieldsAreNeverSerialized(t *testing.T) {
	r := sampleResult()
	r.Target.Headers = map[string]string{"Authorization": "Bearer super-secret-token"}
	r.Target.Env = map[string]string{"API_KEY": "another-secret"}

	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("super-secret-token")) || bytes.Contains(buf.Bytes(), []byte("another-secret")) {
		t.Fatal("a secret from Target.Headers/Env leaked into the JSON report")
	}
}

func TestSecretsInURLsNeverReachTheReport(t *testing.T) {
	const password = "hunter2"
	const queryToken = "s3cr3t-token"
	target := model.Target{
		Kind: model.TargetRemote,
		Name: "example",
		URL:  "http://alice:" + password + "@127.0.0.1/mcp?api_key=" + queryToken,
	}

	r := sampleResult()
	r.Target = target
	r.Snapshot.Transport = model.TransportInfo{Kind: "streamable-http", Endpoint: target.RedactedURL()}

	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte(password)) {
		t.Fatalf("userinfo password leaked into the report:\n%s", buf.String())
	}
	if bytes.Contains(buf.Bytes(), []byte(queryToken)) {
		t.Fatalf("query token leaked into the report:\n%s", buf.String())
	}
}

func TestWriteManyProducesATopLevelArray(t *testing.T) {
	a := sampleResult()
	b := sampleResult()
	b.ScanID = "scan_other"

	var buf bytes.Buffer
	if err := WriteMany(&buf, []*model.ScanResult{a, b}); err != nil {
		t.Fatal(err)
	}

	var got []model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output did not parse as a JSON array: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}
	if got[0].ScanID != a.ScanID || got[1].ScanID != b.ScanID {
		t.Fatalf("scan ids = %q, %q, want %q, %q", got[0].ScanID, got[1].ScanID, a.ScanID, b.ScanID)
	}
}

func TestWriteManyWithNoResultsWritesEmptyArray(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMany(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(buf.String()); got != "[]" {
		t.Fatalf("output = %q, want an empty array", got)
	}
}

func TestHostileContentIsSanitized(t *testing.T) {

	bidiOverride := string(rune(0x202e))
	zeroWidth := string(rune(0x200b))
	dangerous := bidiOverride + zeroWidth

	r := sampleResult()
	r.Findings[0].Title = "evil" + bidiOverride + "tool" + zeroWidth
	r.Findings[0].Evidence[0].Data = map[string]any{"note" + bidiOverride: "payload" + zeroWidth}

	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(buf.String(), dangerous) {
		t.Fatalf("a raw bidi override or zero-width character reached the JSON output:\n%s", buf.String())
	}

	var got model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got.Findings[0].Title, dangerous) {
		t.Fatalf("the dangerous character survived a full decode: %q", got.Findings[0].Title)
	}
	for k, v := range got.Findings[0].Evidence[0].Data {
		if strings.ContainsAny(k, dangerous) {
			t.Fatalf("a Data map key still carries a dangerous character after decode: %q", k)
		}
		if s, ok := v.(string); ok && strings.ContainsAny(s, dangerous) {
			t.Fatalf("a Data map value still carries a dangerous character after decode: %q", s)
		}
	}
}

func TestNumbersKeepTheirLiteralPrecision(t *testing.T) {
	r := sampleResult()
	r.Duration = time.Duration(9007199254740993) // 2^53 + 1, first int64 a float64 cannot represent exactly

	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	var got model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Duration != r.Duration {
		t.Fatalf("duration_ns = %d, want %d (exact)", got.Duration, r.Duration)
	}
}
