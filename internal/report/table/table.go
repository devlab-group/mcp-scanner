// Package table writes a model.ScanResult as a plain-text table for a
// terminal
package table

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/internal/report"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// maxCellWidth bounds a single table cell. This is a display limit, not a
// safety measure - report.Sanitize is what makes a cell's content inert;
// this just keeps a merely very long title or file name from making every
// row unreadable.
const maxCellWidth = 120

func cell(s string) string {
	s = report.Sanitize(s)
	r := []rune(s)
	if len(r) <= maxCellWidth {
		return s
	}
	return string(r[:maxCellWidth-1]) + "…"
}

// Write renders result as a status banner, a findings table, and a coverage/warnings
// footer. Every string that could have come from the scanned target is passed through
// report.Sanitize (via cell, for table rows) first, so a hostile tool description cannot
// repaint the terminal or forge rows with an embedded newline or tab.
func Write(w io.Writer, res *model.ScanResult, decision *policy.Decision) error {
	writeBanner(w, res, decision)

	fmt.Fprintf(w, "target: %s (%s)\n", report.Sanitize(res.Target.Describe()), res.Target.Kind)
	fmt.Fprintf(w, "scan:   %s   duration: %s\n\n", res.ScanID, res.Duration)

	if len(res.Findings) == 0 {
		fmt.Fprintln(w, "no findings")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SEVERITY\tRULE\tTITLE\tLOCATION\tANALYZER")
		for _, f := range res.Findings {
			loc := report.Sanitize(f.File)
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", loc, f.Line)
			}
			if loc == "" {
				loc = "-"
			}
			sevLabel := string(f.Severity)
			if f.Suppressed {
				sevLabel += " (suppressed)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
				sevLabel, cell(f.RuleID), cell(f.Title), cell(loc), cell(f.Analyzer))
		}
		tw.Flush()
	}

	fmt.Fprintln(w)
	writeCoverage(w, res)
	report.WriteWarnings(w, res)
	return nil
}

func writeBanner(w io.Writer, res *model.ScanResult, decision *policy.Decision) {
	if res.Status == model.StatusCompleted {
		fmt.Fprintf(w, "STATUS: %s   VERDICT: %s\n", res.Status, res.Verdict)
		if note := report.GateNote(res, decision); note != "" {
			fmt.Fprintln(w, report.Sanitize(note))
		}
		fmt.Fprintln(w, report.ContributionNote(res))
		if note := report.LimitationsNote(res); note != "" {
			fmt.Fprintln(w, note)
		}
		return
	}
	// A scan that did not cleanly complete gets a banner shaped
	// differently from the one-line SAFE/UNSAFE case, so PARTIAL/ERROR/
	// SKIPPED can never be mistaken for a clean result at a glance
	fmt.Fprintln(w, "############################################################")
	fmt.Fprintf(w, "# SCAN DID NOT COMPLETE - STATUS: %s   VERDICT: %s\n", res.Status, res.Verdict)
	fmt.Fprintln(w, "# This is not a clean result. See reasons below.")
	fmt.Fprintln(w, "############################################################")
	if note := report.GateNote(res, decision); note != "" {
		fmt.Fprintln(w, report.Sanitize(note))
	}
	fmt.Fprintln(w, report.ContributionNote(res))
	for _, reason := range res.VerdictReasons {
		fmt.Fprintf(w, "  - %s\n", report.Sanitize(reason))
	}
	fmt.Fprintln(w)
}

func writeCoverage(w io.Writer, res *model.ScanResult) {
	c := res.Coverage
	fmt.Fprintf(w, "coverage: files %d discovered, %d parsed, %d failed, %d skipped\n",
		c.FilesDiscovered, c.FilesParsed, c.FilesFailed, c.FilesSkipped)
	if c.CapabilitiesDiscovered > 0 {
		fmt.Fprintf(w, "          mcp capabilities %d discovered, %d analyzed, %d skipped\n",
			c.CapabilitiesDiscovered, c.CapabilitiesAnalyzed, c.CapabilitiesSkipped)
	}
	if report.CoverageIsMerged(c) || report.CoverageOverstatesCapabilities(c, res.Analyzers) {
		fmt.Fprintln(w, "          (highest count each analyzer reported, not one population: see per-analyzer coverage)")
	}
	for _, gap := range report.AnalyzerGaps(res.Analyzers) {
		fmt.Fprintf(w, "  gap: %s\n", report.Sanitize(gap))
	}
}
