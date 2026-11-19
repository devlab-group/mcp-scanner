package taint

import (
	"fmt"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A command line built by a helper that quotes every argument with the project's own escaping
// function goes to review; the pair, a helper that joins the arguments unquoted, stays a finding,
// and an unescape is not escaping
func TestEscapedByProjectFunction(t *testing.T) {
	tmpl := `import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

def quote_remote_arg(a):
    return "'" + a.replace("'", "'\\\\''") + "'"

def build_remote(args):
    return " ".join(%s)

@mcp.tool()
def run_remote(socket: str) -> str:
    """Runs tmux on the remote host"""
    cmd = ["ssh", "host"]
    cmd.append(build_remote(["tmux", "-S", socket, "ls"]))
    return subprocess.run(cmd, capture_output=True, text=True).stdout
`
	for _, tc := range []struct{ name, join, want string }{
		{"quoted by the project", "map(quote_remote_arg, args)", "needs_review"},
		{"joined unquoted", "args", ""},
		{"unescaped is not escaped", "map(html_unescape, args)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.join)}))
			fs := categoryFindings(res, "command_injection")
			if len(fs) == 0 {
				t.Fatalf("want a finding, got %+v", res.Findings)
			}
			if string(fs[0].Triage) != tc.want {
				t.Fatalf("want triage %q, got %q (%s)", tc.want, fs[0].Triage, fs[0].TriageReason)
			}
		})
	}
	_ = model.TriageNeedsReview
}
