// Package summary writes a condensed, human-readable overview of a
// model.ScanResult: verdict, finding counts, coverage gaps and the most
// severe findings - not the full table internal/report/table produces
package summary

import (
	"fmt"
	"io"

	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/internal/report"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// maxTopFindings caps how many findings the summary lists individually;
// the count line above it always reflects the true total
const maxTopFindings = 5

// Write renders a short overview of result. As with the table writer,
// every string that could have come from the scanned target is passed
// through report.Sanitize first. decision, when not nil, adds a line
// explaining an UNSAFE verdict against the --fail-on gate - see
// report.GateNote. Pass nil where no policy.Decision is available.
func Write(w io.Writer, res *model.ScanResult, decision *policy.Decision) error {
	fmt.Fprintf(w, "mcp-scanner summary for %s\n", report.Sanitize(res.Target.Describe()))
	writeVerdictLine(w, res, decision)
	report.WriteWarnings(w, res)

	counts := res.Counts()
	fmt.Fprintf(w, "findings: %d critical, %d high, %d medium, %d low, %d info\n",
		counts[model.SeverityCritical], counts[model.SeverityHigh], counts[model.SeverityMedium],
		counts[model.SeverityLow], counts[model.SeverityInfo])

	if gaps := report.AnalyzerGaps(res.Analyzers); len(gaps) > 0 {
		fmt.Fprintln(w, "coverage gaps:")
		for _, gap := range gaps {
			fmt.Fprintf(w, "  - %s\n", report.Sanitize(gap))
		}
	}

	if len(res.Findings) > 0 {
		fmt.Fprintln(w, "top findings:")
		top := topFindings(res.Findings, maxTopFindings)
		for _, f := range top {
			loc := ""
			if f.File != "" {
				loc = " (" + report.Sanitize(f.File)
				if f.Line > 0 {
					loc += fmt.Sprintf(":%d", f.Line)
				}
				loc += ")"
			}
			sevLabel := string(f.Severity)
			if f.Suppressed {
				sevLabel += " (suppressed)"
			}
			fmt.Fprintf(w, "  [%s] %s: %s%s\n", sevLabel, report.Sanitize(f.RuleID), report.Sanitize(f.Title), loc)
		}
		if len(top) < len(res.Findings) {
			fmt.Fprintf(w, "  ... and %d more\n", len(res.Findings)-len(top))
		}
	}
	return nil
}

// topFindings picks up to n findings to print under the count line above, live findings
// first
func topFindings(fs []model.Finding, n int) []model.Finding {
	var live, suppressed []model.Finding
	for _, f := range fs {
		if f.Suppressed {
			suppressed = append(suppressed, f)
		} else {
			live = append(live, f)
		}
	}
	ordered := append(live, suppressed...)
	if len(ordered) > n {
		ordered = ordered[:n]
	}
	return ordered
}

func writeVerdictLine(w io.Writer, res *model.ScanResult, decision *policy.Decision) {
	if res.Status == model.StatusCompleted {
		fmt.Fprintf(w, "status: %s   verdict: %s\n", res.Status, res.Verdict)
		if note := report.GateNote(res, decision); note != "" {
			fmt.Fprintln(w, report.Sanitize(note))
		}
		fmt.Fprintln(w, report.ContributionNote(res))
		if note := report.LimitationsNote(res); note != "" {
			fmt.Fprintln(w, note)
		}
		return
	}
	// Shaped to stand out from the one-line COMPLETED case: PARTIAL,
	// ERROR and SKIPPED must never read like a clean SAFE result
	fmt.Fprintf(w, "*** SCAN INCOMPLETE *** status: %s   verdict: %s\n", res.Status, res.Verdict)
	if note := report.GateNote(res, decision); note != "" {
		fmt.Fprintln(w, report.Sanitize(note))
	}
	fmt.Fprintln(w, report.ContributionNote(res))
	for _, reason := range res.VerdictReasons {
		fmt.Fprintf(w, "    reason: %s\n", report.Sanitize(reason))
	}
}
