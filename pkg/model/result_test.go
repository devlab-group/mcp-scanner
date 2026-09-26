package model

import (
	"strings"
	"testing"
)

func ev() []Evidence {
	return []Evidence{{Level: EvidenceStatic, Description: "test evidence"}}
}

func finding(sev Severity) Finding {
	return Finding{
		RuleID: "test.rule", Category: "test", Title: "test finding",
		Severity: sev, Confidence: 0.9, EvidenceLevel: EvidenceStatic,
		Description: "d", Evidence: ev(), Analyzer: "test",
	}
}

func completed(name string, fs ...Finding) AnalyzerResult {
	return AnalyzerResult{
		Analyzer: name, Status: AnalyzerCompleted, Required: true, Findings: fs,
		Coverage: Coverage{
			CapabilitiesDiscovered: 1,
			CapabilitiesAnalyzed:   1,
		},
	}
}

// The rule the whole project exists for: a required analyzer that failed must
// never leave the scan looking clean
func TestFailedRequiredAnalyzerCannotBeSafe(t *testing.T) {
	for _, st := range []AnalyzerStatus{AnalyzerFailed, AnalyzerPartial, AnalyzerSkipped, AnalyzerUnavailable} {
		r := ScanResult{Analyzers: []AnalyzerResult{
			completed("ok"),
			{Analyzer: "broken", Status: st, Required: true},
		}}
		r.Aggregate(SeverityLow)
		if r.Verdict != VerdictUnknown {
			t.Fatalf("%s: verdict = %s, want UNKNOWN", st, r.Verdict)
		}
		if r.Status == StatusCompleted {
			t.Fatalf("%s: status = COMPLETED, want ERROR or PARTIAL", st)
		}
		if len(r.VerdictReasons) == 0 {
			t.Fatalf("%s: no reason recorded for the downgrade", st)
		}
	}
}

func TestFatalErrorOnCompletedAnalyzerCannotBeSafe(t *testing.T) {
	a := completed("src")
	a.Errors = []AnalyzerError{{Kind: "internal", Message: "walk aborted partway through", Fatal: true}}
	r := ScanResult{Analyzers: []AnalyzerResult{a}}
	r.Aggregate(SeverityLow)
	if r.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %s, want UNKNOWN", r.Verdict)
	}
	if r.Status == StatusCompleted {
		t.Fatalf("status = COMPLETED, want ERROR or PARTIAL")
	}
}

// A non-fatal error is documented as visible but survivable: it should not
// change the verdict, but it must not vanish either
func TestNonFatalErrorOnRequiredAnalyzerSurfacesAsWarning(t *testing.T) {
	a := completed("src")
	a.Errors = []AnalyzerError{{Kind: "network", Message: "one lookup timed out", Fatal: false}}
	r := ScanResult{Analyzers: []AnalyzerResult{a}}
	r.Aggregate(SeverityLow)
	if r.Status != StatusCompleted || r.Verdict != VerdictSafe {
		t.Fatalf("got %s/%s, want COMPLETED/SAFE (%v)", r.Status, r.Verdict, r.VerdictReasons)
	}
	found := false
	for _, w := range r.Warnings {
		if strings.Contains(w, "src") && strings.Contains(w, "one lookup timed out") {
			found = true
		}
	}
	if !found {
		t.Fatalf("non-fatal error did not surface as a warning: %v", r.Warnings)
	}
}

func TestStatusMatrix(t *testing.T) {
	tests := []struct {
		name        string
		analyzers   []AnalyzerResult
		wantStatus  ScanStatus
		wantVerdict Verdict
	}{
		{"clean", []AnalyzerResult{completed("a"), completed("b")}, StatusCompleted, VerdictSafe},
		{"finding", []AnalyzerResult{completed("a", finding(SeverityHigh))}, StatusCompleted, VerdictUnsafe},
		{"error wins over partial", []AnalyzerResult{
			{Analyzer: "a", Status: AnalyzerPartial, Required: true},
			{Analyzer: "b", Status: AnalyzerFailed, Required: true},
		}, StatusError, VerdictUnknown},
		{"nothing ran", []AnalyzerResult{{Analyzer: "a", Status: AnalyzerSkipped, Required: false}}, StatusSkipped, VerdictUnknown},
		{"best-effort failure does not block", []AnalyzerResult{
			completed("a"),
			{Analyzer: "llm", Status: AnalyzerFailed, Required: false},
		}, StatusCompleted, VerdictSafe},
		{"missing status is an error", []AnalyzerResult{{Analyzer: "a", Required: true}}, StatusError, VerdictUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := ScanResult{Analyzers: tc.analyzers}
			r.Aggregate(SeverityLow)
			if r.Status != tc.wantStatus || r.Verdict != tc.wantVerdict {
				t.Fatalf("got %s/%s, want %s/%s (%v)", r.Status, r.Verdict, tc.wantStatus, tc.wantVerdict, r.VerdictReasons)
			}
		})
	}
}

func TestCoverageGapDowngradesScan(t *testing.T) {
	a := completed("src")
	a.Coverage = Coverage{FilesDiscovered: 10, FilesParsed: 7, FilesFailed: 3}
	r := ScanResult{Analyzers: []AnalyzerResult{a}}
	r.Aggregate(SeverityLow)
	if r.Status != StatusPartial || r.Verdict != VerdictUnknown {
		t.Fatalf("got %s/%s, want PARTIAL/UNKNOWN", r.Status, r.Verdict)
	}
}

func TestExplainedSkipKeepsScanComplete(t *testing.T) {
	a := completed("src")
	a.Coverage = Coverage{
		FilesDiscovered: 10, FilesParsed: 8, FilesSkipped: 2,
		SkipReasons: []string{"2 files in an unsupported language (kotlin)"},
	}
	r := ScanResult{Analyzers: []AnalyzerResult{a}}
	r.Aggregate(SeverityLow)
	if r.Status != StatusCompleted || r.Verdict != VerdictSafe {
		t.Fatalf("got %s/%s, want COMPLETED/SAFE (%v)", r.Status, r.Verdict, r.VerdictReasons)
	}
}

func TestBlockingSeverityThreshold(t *testing.T) {
	r := ScanResult{Analyzers: []AnalyzerResult{completed("a", finding(SeverityLow))}}
	r.Aggregate(SeverityHigh)
	if r.Verdict != VerdictSafe {
		t.Fatalf("low finding under a HIGH threshold: verdict = %s, want SAFE", r.Verdict)
	}
	r.Aggregate(SeverityLow)
	if r.Verdict != VerdictUnsafe {
		t.Fatalf("low finding under a LOW threshold: verdict = %s, want UNSAFE", r.Verdict)
	}
}

func TestSuppressedFindingDoesNotBlock(t *testing.T) {
	f := finding(SeverityCritical)
	f.Suppressed = true
	r := ScanResult{Analyzers: []AnalyzerResult{completed("a", f)}}
	r.Aggregate(SeverityLow)
	if r.Verdict != VerdictSafe {
		t.Fatalf("verdict = %s, want SAFE", r.Verdict)
	}
	if len(r.Findings) != 1 {
		t.Fatal("a suppressed finding must stay in the report")
	}
}

func TestFingerprintDistinguishesTwoFindingsInOneFile(t *testing.T) {
	a, b := finding(SeverityHigh), finding(SeverityHigh)
	a.File, b.File = "server.py", "server.py"
	a.Line, b.Line = 11, 18
	if a.Fingerprint("") == b.Fingerprint("") {
		t.Fatal("two findings at different lines in the same file share an ID")
	}
}

// The same finding, scanned twice, is still the same finding
func TestFingerprintIsStableForTheSameFinding(t *testing.T) {
	a, b := finding(SeverityHigh), finding(SeverityHigh)
	a.File, b.File = "server.py", "server.py"
	a.Line, b.Line = 11, 11
	if a.Fingerprint("") != b.Fingerprint("") {
		t.Fatal("the same finding produced two different IDs")
	}
}

func TestFindingValidation(t *testing.T) {
	if err := finding(SeverityHigh).Validate(); err != nil {
		t.Fatalf("valid finding rejected: %v", err)
	}
	cases := map[string]func(*Finding){
		"no evidence":            func(f *Finding) { f.Evidence = nil },
		"no rule id":             func(f *Finding) { f.RuleID = "" },
		"no analyzer":            func(f *Finding) { f.Analyzer = "" },
		"no title":               func(f *Finding) { f.Title = "" },
		"lowercase severity":     func(f *Finding) { f.Severity = "high" },
		"unknown evidence level": func(f *Finding) { f.EvidenceLevel = "HUNCH" },
		"confidence above 1":     func(f *Finding) { f.Confidence = 1.5 },
		"negative confidence":    func(f *Finding) { f.Confidence = -0.1 },
	}
	for name, spoil := range cases {
		bad := finding(SeverityHigh)
		spoil(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An unrecognized severity must not rank below every blocking threshold and pass as safe
func TestUnrecognizedSeverityCannotPassAsSafe(t *testing.T) {
	bad := finding(SeverityHigh)
	bad.Severity = "high"
	r := ScanResult{Analyzers: []AnalyzerResult{completed("sloppy", bad)}}
	r.Aggregate(SeverityLow)
	if r.Verdict == VerdictSafe {
		t.Fatalf("a finding with severity %q aggregated to SAFE", bad.Severity)
	}
}

func TestSortFindingsIsDeterministic(t *testing.T) {
	fs := []Finding{finding(SeverityLow), finding(SeverityCritical), finding(SeverityMedium)}
	for i := range fs {
		fs[i].RuleID = string(fs[i].Severity)
		fs[i].EnsureID("")
	}
	SortFindings(fs)
	if fs[0].Severity != SeverityCritical || fs[2].Severity != SeverityLow {
		t.Fatalf("unexpected order: %v %v %v", fs[0].Severity, fs[1].Severity, fs[2].Severity)
	}
}

func TestScanCoverageDoesNotDoubleCountTheSameTarget(t *testing.T) {
	cov := Coverage{
		FilesDiscovered: 40, FilesParsed: 40,
		CapabilitiesDiscovered: 12, CapabilitiesAnalyzed: 12,
	}
	a, b, c := completed("source"), completed("taint"), completed("behavioral")
	a.Coverage, b.Coverage, c.Coverage = cov, cov, cov

	r := ScanResult{Analyzers: []AnalyzerResult{a, b, c}}
	r.Aggregate(SeverityLow)

	if r.Coverage.FilesDiscovered != 40 || r.Coverage.CapabilitiesDiscovered != 12 {
		t.Fatalf("coverage inflated: %d files, %d capabilities", r.Coverage.FilesDiscovered, r.Coverage.CapabilitiesDiscovered)
	}
	if r.Status != StatusCompleted {
		t.Fatalf("status = %s, want COMPLETED", r.Status)
	}
}

// A merge must not paper over an analyzer that saw less than the others: its
// own gap still downgrades the scan
func TestMergeStillLetsAPerAnalyzerGapDowngrade(t *testing.T) {
	full := completed("source")
	full.Coverage = Coverage{FilesDiscovered: 40, FilesParsed: 40}
	partial := completed("taint")
	partial.Coverage = Coverage{FilesDiscovered: 40, FilesParsed: 10, FilesFailed: 30}

	r := ScanResult{Analyzers: []AnalyzerResult{full, partial}}
	r.Aggregate(SeverityLow)
	if r.Status != StatusPartial || r.Verdict != VerdictUnknown {
		t.Fatalf("got %s/%s, want PARTIAL/UNKNOWN", r.Status, r.Verdict)
	}
}

// A scan that excluded its way down to nothing parsed is a scan that saw
// nothing, however neatly the counters add up
func TestParsedNothingIsAGap(t *testing.T) {
	cases := []struct {
		name string
		cov  Coverage
	}{
		{"everything skipped with a reason", Coverage{
			FilesDiscovered: 412, FilesSkipped: 412,
			SkipReasons: []string{"412 files under dist/"},
		}},
		{"one skipped directory", Coverage{
			FilesSkipped: 1, SkipReasons: []string{"skipped dist"},
		}},
		{"everything failed", Coverage{FilesDiscovered: 3, FilesFailed: 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := completed("source")
			a.Coverage = tc.cov
			r := ScanResult{Analyzers: []AnalyzerResult{a}}
			r.Aggregate(SeverityLow)
			if r.Status != StatusPartial || r.Verdict != VerdictUnknown {
				t.Fatalf("got %s/%s, want PARTIAL/UNKNOWN (%v)", r.Status, r.Verdict, r.VerdictReasons)
			}
		})
	}
}

// Balanced counters do not erase unexplained coverage gaps
func TestUnexplainedCoverageIsAGap(t *testing.T) {
	cases := []struct {
		name string
		cov  Coverage
	}{
		{"40 of 50 files parsed, 10 unexplained", Coverage{FilesDiscovered: 50, FilesParsed: 40}},
		{"every capability skipped with a reason", Coverage{
			CapabilitiesDiscovered: 3, CapabilitiesSkipped: 3,
			SkipReasons: []string{"handler not found"},
		}},
		{"a capability skipped without a reason", Coverage{
			CapabilitiesDiscovered: 3, CapabilitiesAnalyzed: 2, CapabilitiesSkipped: 1,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := completed("source")
			a.Coverage = tc.cov
			r := ScanResult{Analyzers: []AnalyzerResult{a}}
			r.Aggregate(SeverityLow)
			if r.Status != StatusPartial || r.Verdict != VerdictUnknown {
				t.Fatalf("got %s/%s, want PARTIAL/UNKNOWN (%v)", r.Status, r.Verdict, r.VerdictReasons)
			}
		})
	}
}

func TestAnalyzerWithNoFileCoverageIsUnaffected(t *testing.T) {
	a := completed("promptdefense")
	a.Coverage = Coverage{CapabilitiesDiscovered: 4, CapabilitiesAnalyzed: 4}
	r := ScanResult{Analyzers: []AnalyzerResult{a}}
	r.Aggregate(SeverityLow)
	if r.Status != StatusCompleted || r.Verdict != VerdictSafe {
		t.Fatalf("got %s/%s, want COMPLETED/SAFE (%v)", r.Status, r.Verdict, r.VerdictReasons)
	}
}

func TestInvalidFindingFailsItsAnalyzer(t *testing.T) {
	bad := finding(SeverityHigh)
	bad.Evidence = nil
	r := ScanResult{Analyzers: []AnalyzerResult{completed("sloppy", bad)}}
	r.Aggregate(SeverityLow)

	if r.Status != StatusError || r.Verdict != VerdictUnknown {
		t.Fatalf("got %s/%s, want ERROR/UNKNOWN", r.Status, r.Verdict)
	}
	if len(r.Findings) != 1 {
		t.Fatal("the malformed finding was dropped instead of reported")
	}
	if len(r.Analyzers[0].Errors) == 0 {
		t.Fatal("no error was recorded against the analyzer that produced it")
	}
}

func TestAnalyzerReportingNoCoverageIsAGap(t *testing.T) {
	r := ScanResult{Analyzers: []AnalyzerResult{
		{Analyzer: "looked-at-nothing", Status: AnalyzerCompleted, Required: true},
	}}
	r.Aggregate(SeverityLow)
	if r.Status != StatusPartial || r.Verdict != VerdictUnknown {
		t.Fatalf("got %s/%s, want PARTIAL/UNKNOWN (%v)", r.Status, r.Verdict, r.VerdictReasons)
	}
}

// An analyzer that genuinely has nothing to examine says so, and the scanner
// excuses a skip rather than counting it as complete coverage
func TestSkippedAnalyzerIsNotJudgedOnCoverage(t *testing.T) {
	r := ScanResult{Analyzers: []AnalyzerResult{
		completed("real"),
		Skipped("llm", "no api key configured"),
	}}
	r.Aggregate(SeverityLow)
	if r.Status != StatusCompleted || r.Verdict != VerdictSafe {
		t.Fatalf("got %s/%s, want COMPLETED/SAFE (%v)", r.Status, r.Verdict, r.VerdictReasons)
	}
}

func TestAllBestEffortIsWarnedAbout(t *testing.T) {
	a, b := completed("a"), completed("b")
	a.Required, b.Required = false, false
	r := ScanResult{Analyzers: []AnalyzerResult{a, b}}
	r.Aggregate(SeverityLow)

	if r.Status != StatusCompleted || r.Verdict != VerdictSafe {
		t.Fatalf("got %s/%s, want COMPLETED/SAFE", r.Status, r.Verdict)
	}
	var warned bool
	for _, w := range r.Warnings {
		if strings.Contains(w, "best-effort") && strings.Contains(w, "required") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("no warning that nothing was required: %v", r.Warnings)
	}
}

func TestInvalidFindingFromBestEffortAnalyzerDoesNotDecideTheVerdict(t *testing.T) {
	bad := finding(SeverityCritical)
	bad.Evidence = nil

	ok := completed("real")
	sloppy := completed("sloppy", bad)
	sloppy.Required = false

	r := ScanResult{Analyzers: []AnalyzerResult{ok, sloppy}}
	r.Aggregate(SeverityLow)

	if r.Verdict != VerdictSafe {
		t.Fatalf("verdict = %s, want SAFE: a malformed finding decided it (%v)", r.Verdict, r.VerdictReasons)
	}
	if len(r.Findings) != 1 || !r.Findings[0].Suppressed {
		t.Fatalf("the malformed finding must stay in the report, marked: %+v", r.Findings)
	}
	if len(r.Warnings) == 0 {
		t.Fatal("no warning named the analyzer that produced it")
	}
}

func TestEveryAnalyzerFailedIsNotCompleted(t *testing.T) {
	r := &ScanResult{Analyzers: []AnalyzerResult{
		{Analyzer: "a", Status: AnalyzerFailed, Required: false,
			Errors: []AnalyzerError{{Kind: "config", Message: "rules_dir does not exist", Fatal: true}}},
		{Analyzer: "b", Status: AnalyzerFailed, Required: false,
			Errors: []AnalyzerError{{Kind: "provider", Message: "500 from the model provider", Fatal: true}}},
	}}
	r.Aggregate(SeverityHigh)

	if r.Status == StatusCompleted {
		t.Errorf("status = %s, want anything but COMPLETED: zero analyzers completed", r.Status)
	}
	if r.Verdict != VerdictUnknown {
		t.Errorf("verdict = %s, want UNKNOWN", r.Verdict)
	}
}

func TestSelfExcusedAnalyzerIsNotCalledBestEffort(t *testing.T) {
	r := ScanResult{Analyzers: []AnalyzerResult{
		completed("source"),
		{Analyzer: "yara", Status: AnalyzerUnavailable, Required: false},
		{Analyzer: "llm", Status: AnalyzerSkipped, Required: false},
		{Analyzer: "runtime", Status: AnalyzerFailed, Required: false},
	}}
	r.Aggregate(SeverityLow)

	joined := strings.Join(r.Warnings, "\n")
	for _, name := range []string{`"yara"`, `"llm"`} {
		if !strings.Contains(joined, "analyzer "+name+" did not run") {
			t.Errorf("no plain did-not-run line for %s: %v", name, r.Warnings)
		}
	}
	for _, w := range r.Warnings {
		if strings.Contains(w, "best-effort") && !strings.Contains(w, `"runtime"`) {
			t.Errorf("self-excused analyzer described as best-effort: %q", w)
		}
	}
	if !strings.Contains(joined, `best-effort analyzer "runtime" finished as ERROR`) {
		t.Errorf("the analyzer the operator did name in best_effort lost its line: %v", r.Warnings)
	}
}

func TestFingerprintSeparatesTheSameFindingOnDifferentTargets(t *testing.T) {
	f := finding(SeverityCritical)
	f.File, f.Tool = "tool/search/description", "search"

	a := Target{Kind: TargetRemote, URL: "https://a.example/mcp"}
	b := Target{Kind: TargetRemote, URL: "https://b.example/mcp"}
	if f.Fingerprint(FingerprintScope(a)) == f.Fingerprint(FingerprintScope(b)) {
		t.Error("two remote servers declaring the same tool share an id")
	}
	// Two separately built targets describing the same server: this is what
	// a baseline depends on holding across runs
	againstA := Target{Kind: TargetRemote, URL: "https://a.example/mcp"}
	if f.Fingerprint(FingerprintScope(a)) != f.Fingerprint(FingerprintScope(againstA)) {
		t.Error("the same finding on the same server produced two different ids")
	}

	one := Target{Kind: TargetStdio, Command: "node", Args: []string{"notes-server.js"}}
	two := Target{Kind: TargetStdio, Command: "node", Args: []string{"weather-server.js"}}
	if f.Fingerprint(FingerprintScope(one)) == f.Fingerprint(FingerprintScope(two)) {
		t.Error("two stdio servers launched by the same command share an id")
	}

	here := Target{Kind: TargetStatic, Path: "/home/dev/captures/notes.json"}
	ci := Target{Kind: TargetStatic, Path: "/build/artifacts/notes.json"}
	if f.Fingerprint(FingerprintScope(here)) != f.Fingerprint(FingerprintScope(ci)) {
		t.Error("the same capture scanned from two directories produced two different ids")
	}
	weather := Target{Kind: TargetStatic, Path: "/home/dev/captures/weather.json"}
	if f.Fingerprint(FingerprintScope(here)) == f.Fingerprint(FingerprintScope(weather)) {
		t.Error("two different captures share an id")
	}
}

func TestFingerprintIsPortableAcrossSourceCheckouts(t *testing.T) {
	f := finding(SeverityHigh)
	f.File, f.Line = "src/server.py", 42

	dev := Target{Kind: TargetSource, Path: "/home/dev/repo"}
	ci := Target{Kind: TargetSource, Path: "/build/workspace/repo"}
	if f.Fingerprint(FingerprintScope(dev)) != f.Fingerprint(FingerprintScope(ci)) {
		t.Fatal("the same tree scanned from two checkout paths produced two different ids")
	}
}
