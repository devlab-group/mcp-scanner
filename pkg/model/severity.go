package model

import (
	"fmt"
	"strings"
)

// Severity is a finding's impact rating
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Rank returns a comparable value. Unknown severities rank below INFO so a
// typo cannot trigger a --fail-on gate.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

// OneStepDown lowers s once, but never below INFO. The fixed limit prevents
// untrusted text from reducing its own finding below every gate.
func (s Severity) OneStepDown() Severity {
	r := s.Rank()
	if r <= 0 {
		return s
	}
	for sev, rank := range severityRank {
		if rank == r-1 {
			return sev
		}
	}
	return s
}

// AtLeast reports whether s is valid and at least as severe as min
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() && s.Valid() }

func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

func (s Severity) String() string { return string(s) }

// ParseSeverity accepts severity names in either case
func ParseSeverity(v string) (Severity, error) {
	s := Severity(strings.ToUpper(v))
	if !s.Valid() {
		return "", fmt.Errorf("unknown severity %q", v)
	}
	return s, nil
}
