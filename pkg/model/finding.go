package model

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// TaxonomyReference links a finding to an external classification so reports
// can be correlated with other tooling
type TaxonomyReference struct {
	Scheme string `json:"scheme"` // CWE | OWASP-LLM | MITRE-ATLAS | CVE | GHSA | OSV
	ID     string `json:"id"`
	URL    string `json:"url,omitempty"`
}

// Finding is a single security observation. Every field that explains *why*
// the scanner believes it is mandatory: Analyzer, EvidenceLevel and at least
// one Evidence entry. A finding without evidence is a rumour.
type Finding struct {
	ID       string `json:"id"`       // stable per-finding fingerprint
	RuleID   string `json:"rule_id"`  // the rule/check that fired
	Category string `json:"category"` // command_injection, tool_poisoning, ...
	Title    string `json:"title"`

	Severity      Severity      `json:"severity"`
	Confidence    float64       `json:"confidence"` // 0..1
	EvidenceLevel EvidenceLevel `json:"evidence_level"`

	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	Tool string `json:"tool,omitempty"` // MCP capability name, if capability-scoped

	Description string     `json:"description"`
	Remediation string     `json:"remediation,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`

	Analyzer string              `json:"analyzer"`
	Taxonomy []TaxonomyReference `json:"taxonomy,omitempty"`

	// Suppressed findings stay in the result but do not count towards the
	// verdict, so a baseline never makes evidence vanish
	Suppressed        bool   `json:"suppressed,omitempty"`
	SuppressionReason string `json:"suppression_reason,omitempty"`
}

// Fingerprint returns a stable per-target finding ID. Scope prevents one target's baseline from
// suppressing another; line separates findings in the same file and makes moved findings require
// review. This churn keeps a stale exception from silently covering a new location.
func (f Finding) Fingerprint(scope string) string {
	h := sha256.New()
	for _, part := range []string{scope, f.Analyzer, f.RuleID, f.Category, f.File, f.Tool, f.Title} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write([]byte(strconv.Itoa(f.Line)))
	return "f_" + hex.EncodeToString(h.Sum(nil))[:16]
}

// EnsureID fills in the fingerprint when the analyzer did not set an ID
func (f *Finding) EnsureID(scope string) {
	if f.ID == "" {
		f.ID = f.Fingerprint(scope)
	}
}

// FingerprintScope uses only operator-supplied identity, never target-declared text. Remote uses
// the redacted URL; stdio uses command and args; static uses the operator name or file basename;
// package uses ecosystem and name so exceptions survive a version bump. Source uses an explicit
// operator name when present. Without one, its scope is empty, so equal finding paths and lines can
// collide across source trees.
func FingerprintScope(t Target) string {
	switch t.Kind {
	case TargetRemote:
		return string(t.Kind) + "|" + t.RedactedURL()
	case TargetStdio:
		return string(t.Kind) + "|" + strings.Join(append([]string{t.Command}, t.Args...), " ")
	case TargetStatic:
		if t.Name != "" {
			return string(t.Kind) + "|" + t.Name
		}
		return string(t.Kind) + "|" + filepath.Base(t.Path)
	case TargetPackage:
		return string(t.Kind) + "|" + t.Ecosystem + ":" + t.Package
	default:
		if t.Name != "" {
			return string(t.Kind) + "|" + t.Name
		}
		return ""
	}
}

// Validate catches the mistakes that would let a finding through without the
// context a reader needs to act on it
func (f Finding) Validate() error {
	var missing []string
	if f.RuleID == "" {
		missing = append(missing, "rule_id")
	}
	if f.Analyzer == "" {
		missing = append(missing, "analyzer")
	}
	if f.Title == "" {
		missing = append(missing, "title")
	}
	if !f.Severity.Valid() {
		missing = append(missing, "severity")
	}
	if !f.EvidenceLevel.Valid() {
		missing = append(missing, "evidence_level")
	}
	if len(f.Evidence) == 0 {
		missing = append(missing, "evidence")
	}
	if f.Confidence < 0 || f.Confidence > 1 {
		missing = append(missing, "confidence(0..1)")
	}
	if len(missing) > 0 {
		return &ValidationError{What: "finding", Missing: missing, Ref: f.RuleID}
	}
	return nil
}

// ValidationError reports a contract violation by an analyzer
type ValidationError struct {
	What    string
	Missing []string
	Ref     string
}

func (e *ValidationError) Error() string {
	return e.What + " " + strconv.Quote(e.Ref) + " is missing: " + strings.Join(e.Missing, ", ")
}

// SortFindings orders findings most severe first, then by confidence,
// then by ID so reports and SARIF output are byte-stable across runs
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.EvidenceLevel.Rank() != b.EvidenceLevel.Rank() {
			return a.EvidenceLevel.Rank() > b.EvidenceLevel.Rank()
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return a.ID < b.ID
	})
}
