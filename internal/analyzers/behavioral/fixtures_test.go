package behavioral

import (
	"testing"

	"github.com/revinand/mcp-scanner/pkg/model"
)

func TestFixtures_MismatchAndBenignPair(t *testing.T) {
	mismatch := run(t, "../../../testdata/source/behavioral/mismatch")
	var found *model.Finding
	for i := range mismatch.Findings {
		if mismatch.Findings[i].RuleID == "behavioral.credential_exfiltration_mismatch" {
			found = &mismatch.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("want the credential exfiltration mismatch, got %+v", mismatch.Findings)
	}
	if found.Severity != model.SeverityCritical {
		t.Errorf("want CRITICAL severity, got %s", found.Severity)
	}

	benign := run(t, "../../../testdata/source/behavioral/benign")
	requireCompared(t, "benign", benign)
	if len(benign.Findings) != 0 {
		t.Fatalf("a tool whose description matches its behavior must not fire, got %+v", benign.Findings)
	}
}

func TestFixtures_HonestProcessDescriptionDoesNotFire(t *testing.T) {
	for _, dir := range []string{
		"../../../testdata/source/behavioral/honest_process/git_version",
		"../../../testdata/source/behavioral/honest_process/archive",
	} {
		res := run(t, dir)
		requireCompared(t, dir, res)
		if len(res.Findings) != 0 {
			t.Fatalf("%s: an honestly-described tool must not fire, got %+v", dir, res.Findings)
		}
	}
}
