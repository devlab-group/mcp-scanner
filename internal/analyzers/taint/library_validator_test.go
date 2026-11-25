package taint

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A library check the scanner cannot read (validators.domain(host)) sends a later finding on the
// same value to review; subprocess.check_output is a sink, not a check
func TestLibraryValidatorSendsToReview(t *testing.T) {
	const src = `import subprocess
import validators
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")

@mcp.tool()
def lookup(host: str) -> str:
    """Looks up the mail servers of a domain."""
    validators.check_domain(host)
    return subprocess.run("dig +short MX " + host, shell=True, capture_output=True, text=True).stdout

@mcp.tool()
def lookup_raw(host: str) -> str:
    """Looks up the mail servers of a domain."""
    return subprocess.check_output("dig +short MX " + host, shell=True, text=True)
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.py": src}))
	got := categoryFindings(res, "command_injection")
	if len(got) < 2 {
		t.Fatalf("want findings in both tools, got %+v", res.Findings)
	}
	for _, f := range got {
		checked := f.Line == 11
		if checked && f.Triage != model.TriageNeedsReview {
			t.Fatalf("after a library check the finding goes to review, got %s: %s", f.Triage, f.TriageReason)
		}
		if !checked && f.Triage == model.TriageNeedsReview {
			t.Fatalf("check_output is the sink, not a check: %s", f.TriageReason)
		}
	}
}

// Documentation about a command is not running one: a manual-page tool whose argv takes the
// caller's page name is not a declared command runner
func TestCommandDocumentationIsNotACommandRunner(t *testing.T) {
	for _, d := range []string{"Returns the help for a shell command", "Shows the man page of the given command"} {
		if _, declared := capabilityOf("argument_injection", "lookup", d); declared {
			t.Fatalf("%q must not declare running commands", d)
		}
	}
	for _, d := range []string{"Runs a shell command", "Executes the command the user gives"} {
		if _, declared := capabilityOf("command_injection", "run", d); !declared {
			t.Fatalf("%q declares running commands", d)
		}
	}
}
