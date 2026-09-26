package evals

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/pkg/scanner"
)

// Outcome is how one case turned out
type Outcome struct {
	Case   Case
	Result *model.ScanResult

	// Detected is whether the scan produced a qualifying finding
	Detected bool
	// Classification is TP, TN, FP, FN, or GAP for a case that pins a
	// blind spot rather than a detection
	Classification string
	// Problems lists why the case failed, empty when it passed
	Problems []string
}

// Run scans one case and judges it against its expectation
func Run(ctx context.Context, s *scanner.Scanner, c Case, opts scanner.Options) Outcome {
	out := Outcome{Case: c}

	opts.Analyzers = c.Analyzers
	opts.Root = c.Dir

	res, err := s.Scan(ctx, c.ScanTarget(), opts)
	if err != nil {
		out.Problems = append(out.Problems, "scan failed: "+err.Error())
		out.Classification = "ERROR"
		return out
	}
	out.Result = res

	wantStatus := c.Expected.Status
	if wantStatus == "" {
		wantStatus = model.StatusCompleted
	}
	if res.Status != wantStatus {
		out.Problems = append(out.Problems,
			fmt.Sprintf("status %s, expected %s (%s)", res.Status, wantStatus, strings.Join(res.VerdictReasons, "; ")))
	}

	matched := qualifying(res, c.Expected)
	out.Detected = len(matched) > 0

	// A case under vulnerable/ that expects a status instead of a finding holds a real
	// vulnerability this build cannot see, and pins that the scan says so rather than passing
	// over it. Scoring that as a true negative would read as "correctly found nothing" about a
	// file that does contain something, and would let the headline numbers improve by adding
	// blind spots.
	gapCase := c.Class == ClassVulnerable && !c.Expected.Vulnerable

	switch {
	case gapCase:
		out.Classification = "GAP"
		if out.Detected {
			out.Problems = append(out.Problems,
				"this case pins a blind spot and the scan now detects it: give it expected.vulnerable true and a minimum_severity, so it counts as a real detection")
		}
	case c.Expected.Vulnerable && out.Detected:
		out.Classification = "TP"
	case c.Expected.Vulnerable && !out.Detected:
		out.Classification = "FN"
		out.Problems = append(out.Problems, "expected a finding at or above "+string(c.Expected.MinimumSeverity)+", got none")
	case !c.Expected.Vulnerable && out.Detected:
		out.Classification = "FP"
		out.Problems = append(out.Problems, "unexpected finding: "+describe(matched))
	default:
		out.Classification = "TN"
	}

	for _, want := range c.Expected.Rules {
		if !hasRule(res, want) {
			out.Problems = append(out.Problems, "expected rule "+want+" did not fire")
		}
	}
	for _, forbidden := range c.Expected.ForbiddenRules {
		if hasRule(res, forbidden) {
			out.Problems = append(out.Problems, "forbidden rule "+forbidden+" fired again")
		}
	}
	return out
}

// qualifying returns the findings that satisfy the expectation's severity bar.
// A case that names specific rules only counts those, so an unrelated detector
// cannot paper over a regression in the one being tested.
func qualifying(res *model.ScanResult, exp Expectation) []model.Finding {
	var out []model.Finding
	bar := exp.MinimumSeverity
	if !bar.Valid() {
		bar = model.SeverityLow
	}
	for _, f := range res.Findings {
		if f.Suppressed || !f.Severity.AtLeast(bar) {
			continue
		}
		if len(exp.Rules) > 0 && !slices.Contains(exp.Rules, f.RuleID) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func hasRule(res *model.ScanResult, rule string) bool {
	for _, f := range res.Findings {
		if f.RuleID == rule && !f.Suppressed {
			return true
		}
	}
	return false
}

func describe(fs []model.Finding) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, fmt.Sprintf("%s %s (%s)", f.Severity, f.RuleID, f.Analyzer))
	}
	return strings.Join(parts, ", ")
}

// Metrics is the confusion matrix and its derived rates.
//
// Gaps sits outside the matrix on purpose: those cases hold a vulnerability
// the build cannot see and assert that the scan reports a gap instead of a
// clean result. Folding them into TN would let precision and recall rise by
// documenting more blind spots.
type Metrics struct {
	TP, TN, FP, FN int
	Gaps           int
}

func (m *Metrics) Add(classification string) {
	switch classification {
	case "TP":
		m.TP++
	case "TN":
		m.TN++
	case "FP":
		m.FP++
	case "FN":
		m.FN++
	case "GAP":
		m.Gaps++
	}
}

func (m Metrics) Precision() float64 { return ratio(m.TP, m.TP+m.FP) }
func (m Metrics) Recall() float64    { return ratio(m.TP, m.TP+m.FN) }

func (m Metrics) F1() float64 {
	p, r := m.Precision(), m.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func (m Metrics) String() string {
	out := fmt.Sprintf("TP=%d TN=%d FP=%d FN=%d precision=%.3f recall=%.3f f1=%.3f",
		m.TP, m.TN, m.FP, m.FN, m.Precision(), m.Recall(), m.F1())
	if m.Gaps > 0 {
		out += fmt.Sprintf(" (+%d case(s) pinning a known blind spot, outside the matrix)", m.Gaps)
	}
	return out
}

// Report aggregates outcomes overall and per category
type Report struct {
	Overall    Metrics
	ByCategory map[string]*Metrics
}

func NewReport() *Report { return &Report{ByCategory: map[string]*Metrics{}} }

func (r *Report) Add(o Outcome) {
	r.Overall.Add(o.Classification)
	m, ok := r.ByCategory[o.Case.Category]
	if !ok {
		m = &Metrics{}
		r.ByCategory[o.Case.Category] = m
	}
	m.Add(o.Classification)
}

func (r *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "overall: %s\n", r.Overall)
	cats := slices.Sorted(maps.Keys(r.ByCategory))
	for _, c := range cats {
		fmt.Fprintf(&b, "  %-24s %s\n", c, *r.ByCategory[c])
	}
	return b.String()
}
