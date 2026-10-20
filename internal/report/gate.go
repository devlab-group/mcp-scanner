package report

import (
	"fmt"

	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// GateNote explains an UNSAFE verdict's exit code, or an incomplete scan that policy allowed
// to pass. An incomplete scan that fails the gate needs no extra note.
func GateNote(res *model.ScanResult, decision *policy.Decision) string {
	if decision == nil || res == nil {
		return ""
	}
	if res.Verdict != model.VerdictUnsafe {
		if decision.Pass && res.Status != model.StatusCompleted {
			return fmt.Sprintf("scan status %s, but %s - the process still exits 0", res.Status, decision.Reason)
		}
		return ""
	}
	if decision.Pass {
		return fmt.Sprintf("verdict: UNSAFE, but %s - the process still exits 0", decision.Reason)
	}
	return fmt.Sprintf("verdict: UNSAFE, and %s - the process exits %d", decision.Reason, decision.ExitCode)
}
