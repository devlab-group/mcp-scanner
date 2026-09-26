package promptdefense

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/revinand/mcp-scanner/pkg/model"
)

// Rule is one detection declared in a rules/prompt-defense/*.yaml file. The
// engine stays generic; everything that makes a rule precise (which phrases
// count, what nearby text clears it, what nearby text suppresses it) lives
// in data, so a false positive gets fixed by editing YAML, not Go.
type Rule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Category    string   `yaml:"category"`
	Severity    string   `yaml:"severity"`
	Evidence    string   `yaml:"evidence_level"`
	Confidence  float64  `yaml:"confidence,omitempty"`
	Description string   `yaml:"description"`
	Remediation string   `yaml:"remediation"`
	References  []string `yaml:"references,omitempty"`

	// Type selects the detector. "pattern" (the default) is the generic
	// regex engine in engine.go; the others name a one-off structural
	// check that regex alone cannot express: a character class scan
	// across the whole string, or a comparison between two different
	// snapshot fields (annotations vs description)
	Type string `yaml:"type,omitempty"`

	// Fields restricts which text units the rule looks at, e.g.
	// ["description"]. Empty means every unit, including names and
	// titles - the field a homoglyph or zero-width attack often hides in.
	Fields []string `yaml:"fields,omitempty"`

	Patterns       []string `yaml:"patterns,omitempty"`
	RequireContext []string `yaml:"require_context,omitempty"`
	// Negate regexes are checked against the whole window (see Proximity):
	// a match anywhere in it, before or after the pattern, suppresses the
	// finding
	Negate []string `yaml:"negate,omitempty"`
	// ContextIsPremise says the RequireContext list is the other half of what this rule claims,
	// not corroboration for it: credential-harvesting's handover verbs and exfiltration's send
	// verbs turn "this text names a credential" into "this text asks for one"
	ContextIsPremise bool `yaml:"context_is_premise,omitempty"`
	// NegateBefore regexes are only checked against the text before the pattern match
	NegateBefore []string `yaml:"negate_before,omitempty"`
	// Proximity further narrows the window negate/negateBefore/
	// require_context search to this many characters around the match. The
	// window never crosses a sentence boundary regardless of Proximity;
	// zero means the current sentence is the whole window.
	Proximity int `yaml:"proximity,omitempty"`

	// PromoteIfStructural names a structural detector; when it also
	// fires on the same unit, a pattern match is reported as STATIC
	// evidence instead of whatever evidence_level says
	PromoteIfStructural string `yaml:"promote_if_structural,omitempty"`

	// MaxLength and MaxLengthLowParams configure the
	// oversized_description detector. Zero means use its built-in
	// default.
	MaxLength          int `yaml:"max_length,omitempty"`
	MaxLengthLowParams int `yaml:"max_length_low_params,omitempty"`
}

// confidence resolves the declared confidence, or a sensible default keyed
// to how the evidence was obtained
func (r Rule) confidence() float64 {
	if r.Confidence > 0 {
		return r.Confidence
	}
	if strings.EqualFold(r.Evidence, string(model.EvidenceStatic)) {
		return 0.85
	}
	return 0.6
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// compiledRule pairs a Rule with its compiled regular expressions so a scan
// never recompiles them per capability
type compiledRule struct {
	Rule
	patterns       []*regexp.Regexp
	requireContext []*regexp.Regexp
	negate         []*regexp.Regexp
	negateBefore   []*regexp.Regexp
}

func compileRule(r Rule) (*compiledRule, error) {
	cr := &compiledRule{Rule: r}
	var err error
	if cr.patterns, err = compileAll(r.Patterns); err != nil {
		return nil, fmt.Errorf("rule %s: patterns: %w", r.ID, err)
	}
	if cr.requireContext, err = compileAll(r.RequireContext); err != nil {
		return nil, fmt.Errorf("rule %s: require_context: %w", r.ID, err)
	}
	if cr.negate, err = compileAll(r.Negate); err != nil {
		return nil, fmt.Errorf("rule %s: negate: %w", r.ID, err)
	}
	if cr.negateBefore, err = compileAll(r.NegateBefore); err != nil {
		return nil, fmt.Errorf("rule %s: negate_before: %w", r.ID, err)
	}
	return cr, nil
}

func compileAll(exprs []string) ([]*regexp.Regexp, error) {
	if len(exprs) == 0 {
		return nil, nil
	}
	out := make([]*regexp.Regexp, 0, len(exprs))
	for _, e := range exprs {
		re, err := regexp.Compile("(?i)" + e)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", e, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// knownStructuralTypes are the Type values engine.go knows how to dispatch,
// besides the default pattern engine
var knownStructuralTypes = map[string]bool{
	"hidden_chars":          true,
	"confusable_script":     true,
	"base64_blob":           true,
	"oversized_description": true,
	"conflicting_metadata":  true,
}

// LoadRules reads every *.yaml/*.yml file in dir and compiles the rules in it. A directory
// that does not exist, contains no rules, or fails to parse is an error: silently running
// with zero rules would look exactly like a clean scan, for the wrong reason.
func LoadRules(dir string) ([]*compiledRule, error) {
	return loadRulesFS(os.DirFS(dir), ".", "directory "+dir)
}

// loadEmbeddedRules reads the rule set baked into the binary at build time
// (see embed.go). This is what a relocated or `go install`-ed binary with
// no rules directory nearby falls back to.
func loadEmbeddedRules() ([]*compiledRule, error) {
	return loadRulesFS(embeddedRules, "rulesdata", "the embedded rule set")
}

// loadRulesFS is shared by both sources above: an on-disk directory and the
// embedded copy are both an fs.FS, so there is exactly one place that reads
// and validates YAML rule files regardless of where they came from
func loadRulesFS(fsys fs.FS, root, label string) ([]*compiledRule, error) {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch path.Ext(e.Name()) {
		case ".yaml", ".yml":
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no rule files (*.yaml) found in %s", label)
	}

	seen := map[string]string{}
	var rules []*compiledRule
	for _, name := range files {
		p := path.Join(root, name)
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("read rule file %s (%s): %w", name, label, err)
		}
		var rf ruleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return nil, fmt.Errorf("parse rule file %s (%s): %w", name, label, err)
		}
		for _, r := range rf.Rules {
			if err := validateRule(r); err != nil {
				return nil, fmt.Errorf("rule file %s (%s): %w", name, label, err)
			}
			if prev, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("rule id %q declared in both %s and %s (%s)", r.ID, prev, name, label)
			}
			seen[r.ID] = name
			cr, err := compileRule(r)
			if err != nil {
				return nil, fmt.Errorf("rule file %s (%s): %w", name, label, err)
			}
			rules = append(rules, cr)
		}
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules declared in %s", label)
	}
	return rules, nil
}

func validateRule(r Rule) error {
	var missing []string
	if r.ID == "" {
		missing = append(missing, "id")
	}
	if r.Title == "" {
		missing = append(missing, "title")
	}
	if !model.Severity(strings.ToUpper(r.Severity)).Valid() {
		missing = append(missing, "severity")
	}
	if !model.EvidenceLevel(strings.ToUpper(r.Evidence)).Valid() {
		missing = append(missing, "evidence_level")
	}
	if r.Description == "" {
		missing = append(missing, "description")
	}
	if r.Category == "" {
		missing = append(missing, "category")
	}
	if len(missing) > 0 {
		return fmt.Errorf("rule %s missing: %s", r.ID, strings.Join(missing, ", "))
	}

	switch r.Type {
	case "", "pattern":
		if len(r.Patterns) == 0 {
			return fmt.Errorf("rule %s: type pattern needs at least one pattern", r.ID)
		}
	default:
		if !knownStructuralTypes[r.Type] {
			return fmt.Errorf("rule %s: unknown type %q", r.ID, r.Type)
		}
	}
	return nil
}
