// Package policy turns a scan result into a pass/fail decision and a process
// exit code. Keeping it separate from the scanner means CI behaviour can
// change without touching how findings are produced.
package policy

import (
	"fmt"
	"strings"

	"github.com/revinand/mcp-scanner/pkg/model"
)

// Exit codes. These are part of the CLI contract; existing values must not be
// reassigned.
const (
	ExitOK         = 0 // scan completed and policy passed
	ExitUsage      = 1 // bad flags or configuration
	ExitPolicyFail = 2 // scan completed and policy failed
	ExitIncomplete = 3 // scan could not determine an answer
	ExitInternal   = 4 // the scanner itself broke
)

// Policy is the gate applied after a scan
type Policy struct {
	// FailOn is the lowest severity that fails the build. Empty disables the
	// severity gate.
	FailOn model.Severity

	// FailOnUnknown fails the build when the scan could not complete. This
	// defaults to true, because an unknown result is not a pass.
	FailOnUnknown bool

	// Baseline holds finding IDs that are accepted for now. Baselined findings
	// stay in the report, marked suppressed.
	Baseline map[string]string // finding ID -> reason
}

// Default is the policy used when nothing is configured. It blocks HIGH findings and incomplete
// scans so an unattended pipeline does not turn an unknown or serious result green by default.
func Default() Policy {
	return Policy{FailOn: model.SeverityHigh, FailOnUnknown: true}
}

// FailOnNone is the spelling that turns the severity gate off. It is not a
// severity, so it never reaches ParseSeverity.
const FailOnNone = "none"

// ParseFailOn turns a configured fail_on value into a Policy.FailOn threshold: the empty
// severity for "none", which turns the gate off, and the parsed severity otherwise
func ParseFailOn(s string) (model.Severity, error) {
	if strings.EqualFold(s, FailOnNone) {
		return "", nil
	}
	return model.ParseSeverity(s)
}

// Decision is the outcome of applying a policy
type Decision struct {
	Pass     bool
	ExitCode int
	Reason   string
}

// Apply evaluates the gate after suppression has marked findings. This keeps the verdict, exit
// code, and every serialized copy aligned on which findings still count.
func (p Policy) Apply(res *model.ScanResult) Decision {
	if res == nil {
		return Decision{Pass: false, ExitCode: ExitInternal, Reason: "no scan result"}
	}

	switch res.Status {
	case model.StatusCompleted:
		// keep going
	case model.StatusError, model.StatusPartial, model.StatusSkipped:
		if p.FailOnUnknown {
			return Decision{
				Pass:     false,
				ExitCode: ExitIncomplete,
				Reason:   fmt.Sprintf("scan status %s: %s", res.Status, joinReasons(res.VerdictReasons)),
			}
		}
		// Tolerating an incomplete scan means not blocking on what the scanner could not see
		if d, blocked := p.severityGate(res); blocked {
			return d
		}
		return Decision{Pass: true, ExitCode: ExitOK, Reason: "incomplete scan tolerated by policy, and no finding reached the threshold"}
	default:
		return Decision{Pass: false, ExitCode: ExitInternal, Reason: "unknown scan status " + string(res.Status)}
	}

	if !p.FailOn.Valid() {
		return Decision{Pass: true, ExitCode: ExitOK, Reason: "no severity gate configured"}
	}
	if d, blocked := p.severityGate(res); blocked {
		return d
	}
	return Decision{Pass: true, ExitCode: ExitOK, Reason: "no finding reached the " + string(p.FailOn) + " threshold"}
}

// severityGate reports whether any finding that still counts is at or above
// the configured threshold. blocked is false when the gate is turned off, so
// --fail-on none stays a way to turn the gate off rather than a way to be
// told about it twice
func (p Policy) severityGate(res *model.ScanResult) (d Decision, blocked bool) {
	if !p.FailOn.Valid() {
		return Decision{}, false
	}
	for _, f := range res.Findings {
		if f.Suppressed {
			continue
		}
		if f.Severity.AtLeast(p.FailOn) {
			return Decision{
				Pass:     false,
				ExitCode: ExitPolicyFail,
				Reason:   fmt.Sprintf("%s finding %q (%s) is at or above the --fail-on threshold %s", f.Severity, f.Title, f.RuleID, p.FailOn),
			}, true
		}
	}
	return Decision{}, false
}

func joinReasons(rs []string) string {
	if len(rs) == 0 {
		return "no reason recorded"
	}
	return strings.Join(rs, "; ")
}
