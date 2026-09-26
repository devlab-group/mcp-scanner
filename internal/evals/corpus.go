// Package evals runs the security benchmark corpus and scores the scanner
// against it. It is the regression net: a detector that stops firing on a
// known vulnerability, or starts firing on a case that was fixed, fails here
// before it reaches anyone.
package evals

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/revinand/mcp-scanner/pkg/model"
)

// Class is which part of the corpus a case belongs to
type Class string

const (
	// ClassVulnerable must produce a finding
	ClassVulnerable Class = "vulnerable"
	// ClassFixed is the repaired version of a vulnerable case and must be quiet
	ClassFixed Class = "fixed"
	// ClassBenign is ordinary code that must be quiet
	ClassBenign Class = "benign"
	// ClassHoldout is benign or vulnerable code kept out of rule tuning
	ClassHoldout Class = "holdout"
)

// Case is one corpus entry, loaded from case.yaml next to the fixture
type Case struct {
	ID       string `yaml:"id"`
	Category string `yaml:"category"`
	Class    Class  `yaml:"-"`
	Dir      string `yaml:"-"`

	// Notes explains what the case is testing. Required, because a corpus of
	// unlabelled fixtures rots into noise.
	Notes string `yaml:"notes"`

	Target CaseTarget `yaml:"target"`

	Expected Expectation `yaml:"expected"`

	// Analyzers restricts the scan. Empty means every applicable analyzer,
	// which is how cross-analyzer regressions get caught.
	Analyzers []string `yaml:"analyzers"`

	// Regression marks a case added because of a bug found in the field. These
	// are never removed and never allowed to fail.
	Regression bool `yaml:"regression"`
}

// CaseTarget describes what to scan, relative to the case directory
type CaseTarget struct {
	Kind model.TargetKind `yaml:"kind"`
	Path string           `yaml:"path"`
	URL  string           `yaml:"url"`
}

// Expectation is what the scan should produce
type Expectation struct {
	Vulnerable      bool           `yaml:"vulnerable"`
	MinimumSeverity model.Severity `yaml:"minimum_severity"`
	// Rules that must appear. A case can require a specific detector rather
	// than accepting any finding at all, which stops an unrelated rule from
	// masking a regression.
	Rules []string `yaml:"rules"`
	// ForbiddenRules must not appear. Used for fixed and benign cases that
	// previously produced a specific false positive.
	ForbiddenRules []string `yaml:"forbidden_rules"`
	// Status the scan must reach. Defaults to COMPLETED
	Status model.ScanStatus `yaml:"status"`
}

// Load reads every case under root. A directory containing a case.yaml is a
// case; anything else is fixture material belonging to one.
func Load(root string) ([]Case, error) {
	var cases []Case
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "case.yaml" {
			return nil
		}
		c, err := loadCase(root, path)
		if err != nil {
			return err
		}
		cases = append(cases, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	return cases, nil
}

func loadCase(root, path string) (Case, error) {
	var c Case
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	c.Dir = filepath.Dir(path)

	rel, err := filepath.Rel(root, c.Dir)
	if err != nil {
		return c, err
	}
	c.Class = Class(strings.SplitN(filepath.ToSlash(rel), "/", 2)[0])

	// Case files are written by hand, so accept "high" as well as "HIGH"
	if c.Expected.MinimumSeverity != "" {
		sev, err := model.ParseSeverity(string(c.Expected.MinimumSeverity))
		if err != nil {
			return c, fmt.Errorf("%s: expected.minimum_severity: %w", path, err)
		}
		c.Expected.MinimumSeverity = sev
	}

	if err := c.validate(); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c Case) validate() error {
	switch c.Class {
	case ClassVulnerable, ClassFixed, ClassBenign, ClassHoldout:
	default:
		return fmt.Errorf("case sits under %q, expected vulnerable, fixed, benign or holdout", c.Class)
	}
	if c.ID == "" {
		return fmt.Errorf("id is required")
	}
	if c.Category == "" {
		return fmt.Errorf("category is required")
	}
	if c.Notes == "" {
		return fmt.Errorf("notes is required: an unexplained fixture cannot be maintained")
	}
	if c.Target.Kind == "" {
		return fmt.Errorf("target.kind is required")
	}
	// A vulnerable case normally expects a finding. It may instead expect a status other than
	// COMPLETED, which says the scanner does not detect this and must not claim otherwise.
	if c.Class == ClassVulnerable && !c.Expected.Vulnerable {
		if c.Expected.Status == "" || c.Expected.Status == model.StatusCompleted {
			return fmt.Errorf("a case under vulnerable/ must expect a finding, or a status other than COMPLETED")
		}
	}
	if (c.Class == ClassFixed || c.Class == ClassBenign) && c.Expected.Vulnerable {
		return fmt.Errorf("a case under %s/ must not expect a finding", c.Class)
	}
	if c.Expected.Vulnerable && !c.Expected.MinimumSeverity.Valid() {
		return fmt.Errorf("expected.minimum_severity is required when expected.vulnerable is true")
	}
	return nil
}

// ScanTarget builds the scan target for the case, resolved against its directory
func (c Case) ScanTarget() model.Target {
	t := model.Target{Kind: c.Target.Kind, Name: c.ID, URL: c.Target.URL}
	path := c.Target.Path
	if path == "" {
		path = "."
	}
	t.Path = filepath.Join(c.Dir, path)
	return t
}
