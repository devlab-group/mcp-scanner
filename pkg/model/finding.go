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

	// Triage says how far a reader can rely on the finding before checking it; TriageReason says
	// why it landed there. An analyzer may set it; Aggregate fills it in from severity and
	// evidence level otherwise.
	Triage       Triage `json:"triage,omitempty"`
	TriageReason string `json:"triage_reason,omitempty"`

	// SourceClass, Reachability and ReachableFrom describe a dataflow finding's origin: who
	// controls the value (mcp_input, external_content, environment), whether the function it
	// enters in is reachable from an MCP handler (yes, possible, no, unknown), and through which
	// capabilities
	SourceClass   string   `json:"source_class,omitempty"`
	Reachability  string   `json:"reachability,omitempty"`
	ReachableFrom []string `json:"reachable_from,omitempty"`

	// FindingKind separates a dangerous capability - a tool whose stated purpose is the risky
	// action, such as running caller-supplied SQL - from a vulnerability; empty means a
	// vulnerability. Capability names which one: process_execution, code_execution,
	// file_access, network_request, sql_execution.
	FindingKind FindingKind `json:"finding_kind,omitempty"`
	Capability  string      `json:"capability,omitempty"`
}

// FindingKind is what sort of risk a finding describes
type FindingKind string

// FindingDangerousCapability marks a tool that does the risky thing by design
const FindingDangerousCapability FindingKind = "dangerous_capability"

// Triage is the reliance a finding supports before a person checks it
type Triage string

const (
	// TriageConfirmed: running the target produced the predicted effect
	TriageConfirmed Triage = "confirmed"
	// TriagePotential: static evidence for a real issue; verify before acting on it
	TriagePotential Triage = "potential"
	// TriageNeedsReview: the impact would be high, but the evidence cannot tell a real issue from
	// a scanner artefact - an attacker may or may not control the input, or a pattern matched
	// prose. A person decides.
	TriageNeedsReview Triage = "needs_review"
	// TriageContext: low impact or not reachable from MCP input; useful background, not an issue
	TriageContext Triage = "context"
)

// DefaultTriage is the triage for a finding whose analyzer did not set one
func DefaultTriage(f Finding) (Triage, string) {
	switch {
	case f.EvidenceLevel == EvidenceConfirmed || f.EvidenceLevel == EvidenceDynamic:
		return TriageConfirmed, "observed while running the target"
	case f.Severity.Rank() <= SeverityLow.Rank():
		return TriageContext, "low severity"
	case f.Severity.AtLeast(SeverityHigh) && f.EvidenceLevel == EvidenceHeuristic:
		return TriageNeedsReview, "high severity from a heuristic match; the matched text may be ordinary prose"
	default:
		return TriagePotential, "static evidence; verify before acting on it"
	}
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
		// the key in a URL path stays part of the scope (it is hashed, never printed), so two
		// endpoints that differ only by it keep distinct IDs
		return string(t.Kind) + "|" + redactURL(t.URL, false)
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
