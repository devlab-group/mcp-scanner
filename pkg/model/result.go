package model

import (
	"fmt"
	"time"
)

// SchemaVersion is the version of the serialized result model. Bump it when a consumer
// would have to change to read the output. A change to finding identity also requires a bump
// because existing suppression baselines will no longer match.
const SchemaVersion = "1.0.0"

// AnalyzerStatus is how an analyzer run ended
type AnalyzerStatus string

const (
	// AnalyzerCompleted means the analyzer ran to the end and its coverage adds up
	AnalyzerCompleted AnalyzerStatus = "COMPLETED"
	// AnalyzerPartial means it produced usable output but could not finish everything
	AnalyzerPartial AnalyzerStatus = "PARTIAL"
	// AnalyzerFailed means it failed. Its findings, if any, are not trustworthy as a complete set
	AnalyzerFailed AnalyzerStatus = "ERROR"
	// AnalyzerSkipped means it was not applicable or was turned off
	AnalyzerSkipped AnalyzerStatus = "SKIPPED"
	// AnalyzerUnavailable means it is not present in this build (for example a
	// YARA-free build). Distinct from SKIPPED so a missing build tag is visible.
	AnalyzerUnavailable AnalyzerStatus = "UNAVAILABLE"
)

// ScanStatus is how the whole scan ended
type ScanStatus string

const (
	StatusCompleted ScanStatus = "COMPLETED"
	StatusPartial   ScanStatus = "PARTIAL"
	StatusError     ScanStatus = "ERROR"
	StatusSkipped   ScanStatus = "SKIPPED"
)

// Verdict is the security answer. It is only meaningful together with ScanStatus
type Verdict string

const (
	VerdictSafe    Verdict = "SAFE"
	VerdictUnsafe  Verdict = "UNSAFE"
	VerdictUnknown Verdict = "UNKNOWN"
)

// AnalyzerError is a failure an analyzer wants to report without pretending
// it did not happen
type AnalyzerError struct {
	Kind    string `json:"kind"` // config | network | timeout | parse | internal | policy | unavailable
	Message string `json:"message"`
	// Fatal marks an error that invalidates the analyzer's whole result
	Fatal bool `json:"fatal"`
}

func (e AnalyzerError) Error() string { return e.Kind + ": " + e.Message }

// AnalyzerResult is what every analyzer returns. There is no way to return
// "nothing happened" implicitly: Status is required and an empty status is
// treated as an error by the aggregator.
type AnalyzerResult struct {
	Analyzer string         `json:"analyzer"`
	Status   AnalyzerStatus `json:"status"`
	// Required analyzers gate the verdict. An enabled analyzer is required
	// unless policy explicitly marks it best-effort.
	Required bool `json:"required"`

	Findings []Finding       `json:"findings,omitempty"`
	Warnings []string        `json:"warnings,omitempty"`
	Errors   []AnalyzerError `json:"errors,omitempty"`
	Coverage Coverage        `json:"coverage"`

	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Duration   time.Duration `json:"duration_ns"`
}

// Errorf builds a failed AnalyzerResult. Analyzers should use it instead of
// returning an empty result, which would read as success.
func Errorf(name, kind string, format string, args ...any) AnalyzerResult {
	return AnalyzerResult{
		Analyzer: name,
		Status:   AnalyzerFailed,
		Required: true,
		Errors:   []AnalyzerError{{Kind: kind, Message: fmt.Sprintf(format, args...), Fatal: true}},
	}
}

// Skipped builds a SKIPPED result with a mandatory reason
func Skipped(name, reason string) AnalyzerResult {
	return AnalyzerResult{
		Analyzer: name,
		Status:   AnalyzerSkipped,
		Warnings: []string{reason},
	}
}

// Unavailable builds an UNAVAILABLE result, for analyzers compiled out or
// missing a required external dependency
func Unavailable(name, reason string) AnalyzerResult {
	return AnalyzerResult{
		Analyzer: name,
		Status:   AnalyzerUnavailable,
		Errors:   []AnalyzerError{{Kind: "unavailable", Message: reason}},
	}
}

// ScanResult is the complete, serializable outcome of scanning one target
type ScanResult struct {
	SchemaVersion  string `json:"schema_version"`
	ScanID         string `json:"scan_id"`
	ScannerVersion string `json:"scanner_version,omitempty"`

	Target Target `json:"target"`

	Status         ScanStatus `json:"status"`
	Verdict        Verdict    `json:"verdict"`
	VerdictReasons []string   `json:"verdict_reasons,omitempty"`

	Findings  []Finding        `json:"findings"`
	Analyzers []AnalyzerResult `json:"analyzers"`
	Coverage  Coverage         `json:"coverage"`

	Snapshot *Snapshot `json:"snapshot,omitempty"`

	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Duration   time.Duration `json:"duration_ns"`

	Warnings []string `json:"warnings,omitempty"`
}

// DefaultBlockingSeverity is the lowest severity that makes a completed scan UNSAFE
const DefaultBlockingSeverity = SeverityLow

// Aggregate is the only place that decides a verdict. In order: no analyzer ran ->
// SKIPPED/UNKNOWN; a required error -> ERROR/UNKNOWN; a required incomplete result or coverage
// gap -> PARTIAL/UNKNOWN; every attempted analyzer failed -> SKIPPED/UNKNOWN; a blocking finding
// -> COMPLETED/UNSAFE; otherwise -> COMPLETED/SAFE.
func (r *ScanResult) Aggregate(blocking Severity) {
	if r.SchemaVersion == "" {
		r.SchemaVersion = SchemaVersion
	}
	if !blocking.Valid() {
		blocking = DefaultBlockingSeverity
	}

	r.Findings = nil
	r.Coverage = Coverage{}
	// Warnings is rebuilt with the rest. Appending here made a second call
	// on the same result duplicate everything, which is exactly what a
	// caller re-aggregating after applying a baseline would do.
	r.Warnings = nil

	var reasons []string
	worstStatus := StatusCompleted
	ran := 0
	produced := 0
	required := 0

	// One scope for the whole result: every finding here came from this
	// target, and the scope is what keeps its id from matching a finding on
	// somebody else's server
	scope := FingerprintScope(r.Target)

	for i := range r.Analyzers {
		a := &r.Analyzers[i]
		for j := range a.Findings {
			a.Findings[j].EnsureID(scope)
			if a.Findings[j].Analyzer == "" {
				a.Findings[j].Analyzer = a.Analyzer
			}
			// A finding without evidence or a severity is the analyzer's
			// bug, and it is reported as one. Dropping it here would hide
			// both the finding and the bug; keeping it and failing the
			// analyzer keeps the scan honest in the fail-closed direction.
			if err := a.Findings[j].Validate(); err != nil {
				a.Status = AnalyzerFailed
				a.Errors = append(a.Errors, AnalyzerError{
					Kind:    "internal",
					Message: "analyzer produced an invalid finding: " + err.Error(),
					Fatal:   true,
				})
				// A best-effort analyzer's status change is swallowed below,
				// so say it here too. Otherwise a malformed finding sits in
				// the report looking like every other one.
				r.Warnings = append(r.Warnings,
					fmt.Sprintf("analyzer %q produced an invalid finding: %v", a.Analyzer, err))
				// Keep it visible but suppress it so unvalidated severity or evidence cannot affect the
				// verdict. The warning above preserves the analyzer bug for review.
				a.Findings[j].Suppressed = true
				a.Findings[j].SuppressionReason = "the analyzer that produced this finding reported it as malformed: " + err.Error()
			}
			r.Findings = append(r.Findings, a.Findings[j])
		}
		r.Coverage.Merge(a.Coverage)

		if a.Status == "" {
			a.Status = AnalyzerFailed
			a.Errors = append(a.Errors, AnalyzerError{
				Kind:    "internal",
				Message: "analyzer returned no status",
				Fatal:   true,
			})
		}

		// A fatal error invalidates the analyzer's reported status
		for _, e := range a.Errors {
			if e.Fatal {
				a.Status = AnalyzerFailed
				break
			}
		}

		// ran counts an analyzer that tried; produced counts one that came
		// back with an analysis. A scan where every analyzer errored has a
		// nonzero ran and nothing to stand a verdict on.
		switch a.Status {
		case AnalyzerCompleted, AnalyzerPartial:
			ran++
			produced++
		case AnalyzerFailed:
			ran++
		}
		if a.Required {
			required++
			// A non-fatal error is documented as visible but survivable. Make
			// that true: it does not change Status, but it must show up
			// somewhere, or "non-fatal" just means "unread".
			for _, e := range a.Errors {
				if !e.Fatal {
					r.Warnings = append(r.Warnings,
						fmt.Sprintf("required analyzer %q reported a non-fatal %s error: %s", a.Analyzer, e.Kind, e.Message))
				}
			}
		}
		if !a.Required {
			// Distinguish any non-required skip or unavailable result from an incomplete best-effort one
			switch {
			case a.Status == AnalyzerSkipped || a.Status == AnalyzerUnavailable:
				r.Warnings = append(r.Warnings,
					fmt.Sprintf("analyzer %q did not run: %s", a.Analyzer, a.Status))
			case a.Status != AnalyzerCompleted:
				r.Warnings = append(r.Warnings,
					fmt.Sprintf("best-effort analyzer %q finished as %s", a.Analyzer, a.Status))
			}
			continue
		}

		switch a.Status {
		case AnalyzerFailed:
			worstStatus = StatusError
			reasons = append(reasons, fmt.Sprintf("required analyzer %q failed", a.Analyzer))
		case AnalyzerPartial, AnalyzerSkipped, AnalyzerUnavailable:
			if worstStatus != StatusError {
				worstStatus = StatusPartial
			}
			reasons = append(reasons, fmt.Sprintf("required analyzer %q finished as %s", a.Analyzer, a.Status))
		case AnalyzerCompleted:
			for _, gap := range a.Coverage.Gaps() {
				if worstStatus != StatusError {
					worstStatus = StatusPartial
				}
				reasons = append(reasons, fmt.Sprintf("%s: %s", a.Analyzer, gap))
			}
		}
	}

	SortFindings(r.Findings)

	if ran == 0 {
		r.Status = StatusSkipped
		r.Verdict = VerdictUnknown
		r.VerdictReasons = append([]string{"no analyzer produced a result"}, reasons...)
		return
	}

	if worstStatus != StatusCompleted {
		r.Status = worstStatus
		r.Verdict = VerdictUnknown
		r.VerdictReasons = reasons
		return
	}

	// Best-effort excuses a failure from gating the verdict. It does not
	// turn a scan in which nothing was analyzed into a completed one.
	if produced == 0 {
		r.Status = StatusSkipped
		r.Verdict = VerdictUnknown
		r.VerdictReasons = append([]string{"every analyzer that ran failed"}, reasons...)
		return
	}

	// A verdict with nothing required behind it rests on analyzers whose
	// failure was declared not to matter. That is what best-effort means, so
	// it is allowed, but it is not what a reader assumes SAFE is standing on.
	if required == 0 {
		r.Warnings = append(r.Warnings,
			"every analyzer that ran was best-effort, so no analyzer's result was required for this verdict")
	}

	r.Status = StatusCompleted
	for _, f := range r.Findings {
		if f.Suppressed {
			continue
		}
		if f.Severity.AtLeast(blocking) {
			r.Verdict = VerdictUnsafe
			r.VerdictReasons = []string{
				fmt.Sprintf("%s finding %q from %s", f.Severity, f.Title, f.Analyzer),
			}
			return
		}
	}
	r.Verdict = VerdictSafe
	r.VerdictReasons = []string{"all required analyzers completed with full coverage and no blocking findings"}
}

// Counts returns the number of non-suppressed findings per severity
func (r *ScanResult) Counts() map[Severity]int {
	out := map[Severity]int{}
	for _, f := range r.Findings {
		if !f.Suppressed {
			out[f.Severity]++
		}
	}
	return out
}
