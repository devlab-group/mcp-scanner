package policy

import (
	"testing"

	"github.com/revinand/mcp-scanner/pkg/model"
)

func result(status model.ScanStatus, fs ...model.Finding) *model.ScanResult {
	return &model.ScanResult{Status: status, Verdict: model.VerdictUnsafe, Findings: fs}
}

func f(id string, sev model.Severity) model.Finding {
	return model.Finding{ID: id, RuleID: "r", Title: "t", Severity: sev}
}

func suppressed(fi model.Finding) model.Finding {
	fi.Suppressed = true
	return fi
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name string
		pol  Policy
		res  *model.ScanResult
		want int
	}{
		{"clean scan", Policy{FailOn: model.SeverityHigh, FailOnUnknown: true},
			&model.ScanResult{Status: model.StatusCompleted, Verdict: model.VerdictSafe}, ExitOK},
		{"finding above threshold", Policy{FailOn: model.SeverityHigh, FailOnUnknown: true},
			result(model.StatusCompleted, f("a", model.SeverityCritical)), ExitPolicyFail},
		{"finding below threshold", Policy{FailOn: model.SeverityHigh, FailOnUnknown: true},
			result(model.StatusCompleted, f("a", model.SeverityMedium)), ExitOK},
		{"incomplete scan", Policy{FailOn: model.SeverityHigh, FailOnUnknown: true},
			result(model.StatusPartial), ExitIncomplete},
		{"incomplete scan tolerated", Policy{FailOn: model.SeverityHigh},
			result(model.StatusPartial), ExitOK},

		{"incomplete scan tolerated, blocking finding", Policy{FailOn: model.SeverityHigh},
			result(model.StatusPartial, f("a", model.SeverityCritical)), ExitPolicyFail},
		{"incomplete scan tolerated, finding below threshold", Policy{FailOn: model.SeverityHigh},
			result(model.StatusPartial, f("a", model.SeverityMedium)), ExitOK},
		{"incomplete scan tolerated, blocking finding baselined", Policy{FailOn: model.SeverityHigh},
			result(model.StatusPartial, suppressed(f("a", model.SeverityCritical))), ExitOK},
		{"incomplete scan tolerated, gate turned off", Policy{},
			result(model.StatusPartial, f("a", model.SeverityCritical)), ExitOK},

		// Every status other than COMPLETED is incomplete
		{"errored scan", Policy{FailOn: model.SeverityHigh, FailOnUnknown: true},
			result(model.StatusError), ExitIncomplete},
		{"skipped scan", Policy{FailOn: model.SeverityHigh, FailOnUnknown: true},
			result(model.StatusSkipped), ExitIncomplete},
		{"empty status", Policy{FailOn: model.SeverityHigh, FailOnUnknown: true},
			result(""), ExitInternal},
		{"no result at all", Policy{FailOn: model.SeverityHigh, FailOnUnknown: true},
			nil, ExitInternal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.pol.Apply(tc.res); got.ExitCode != tc.want {
				t.Fatalf("exit = %d (%s), want %d", got.ExitCode, got.Reason, tc.want)
			}
		})
	}
}

func TestGateIgnoresAnAlreadySuppressedFinding(t *testing.T) {
	suppressed := f("known", model.SeverityCritical)
	suppressed.Suppressed = true
	suppressed.SuppressionReason = "accepted 2026-09-01"

	res := result(model.StatusCompleted, suppressed)
	pol := Policy{FailOn: model.SeverityHigh, FailOnUnknown: true, Baseline: map[string]string{"known": "accepted 2026-09-01"}}
	if d := pol.Apply(res); d.ExitCode != ExitOK {
		t.Fatalf("exit = %d (%s), want ExitOK", d.ExitCode, d.Reason)
	}
	if !res.Findings[0].Suppressed {
		t.Fatal("a suppressed finding must stay in the report, marked")
	}
}

func TestGateDoesNotSuppressOnItsOwn(t *testing.T) {
	res := result(model.StatusCompleted, f("known", model.SeverityCritical))
	pol := Policy{FailOn: model.SeverityHigh, FailOnUnknown: true, Baseline: map[string]string{"known": "accepted"}}
	if d := pol.Apply(res); d.ExitCode != ExitPolicyFail {
		t.Fatalf("exit = %d (%s), want ExitPolicyFail", d.ExitCode, d.Reason)
	}
}

// A baseline must never rescue an incomplete scan: there is nothing to
// baseline when the scanner does not know what it missed
func TestBaselineDoesNotRescueIncompleteScan(t *testing.T) {
	res := result(model.StatusError, f("known", model.SeverityCritical))
	pol := Policy{FailOn: model.SeverityHigh, FailOnUnknown: true, Baseline: map[string]string{"known": "accepted"}}
	if d := pol.Apply(res); d.ExitCode != ExitIncomplete {
		t.Fatalf("exit = %d, want ExitIncomplete", d.ExitCode)
	}
}

// The usual caller is a pipeline. A green build on a critical finding because
// nobody passed a flag is the wrong default.
func TestDefaultPolicyFailsOnHigh(t *testing.T) {
	pol := Default()
	if pol.FailOn != model.SeverityHigh {
		t.Fatalf("default FailOn = %q, want HIGH", pol.FailOn)
	}
	res := result(model.StatusCompleted, f("a", model.SeverityCritical))
	if d := pol.Apply(res); d.ExitCode != ExitPolicyFail {
		t.Fatalf("exit = %d (%s), want ExitPolicyFail", d.ExitCode, d.Reason)
	}
	below := result(model.StatusCompleted, f("b", model.SeverityMedium))
	if d := pol.Apply(below); d.ExitCode != ExitOK {
		t.Fatalf("a MEDIUM finding failed the default gate: %s", d.Reason)
	}
}

// Turning the gate off stays possible, it just has to be asked for
func TestGateCanBeTurnedOff(t *testing.T) {
	pol := Default()
	pol.FailOn = ""
	res := result(model.StatusCompleted, f("a", model.SeverityCritical))
	if d := pol.Apply(res); d.ExitCode != ExitOK {
		t.Fatalf("exit = %d (%s), want ExitOK", d.ExitCode, d.Reason)
	}
}
