package taint

import (
	"fmt"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// subprocess.run(args) with args built from literals in the same function: the list is read, so a
// value after a literal "--" is a plain argument; a "--" added inside an if is not trusted; and a
// tool argument that becomes the program is still a command injection
func TestArgvListBuiltInTheFunction(t *testing.T) {
	tmpl := `import shutil
import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def search(query: str, regex: bool = False) -> str:
    """Searches notes"""
    rg = shutil.which("rg")
%s
    return subprocess.run(args, capture_output=True, text=True).stdout
`
	for _, tc := range []struct {
		name, build string
		want        string // "" no finding; otherwise category
		sev         model.Severity
	}{
		{"value after a literal --", `    args = [rg, "--files-with-matches", "-g", "*.md"]
    if not regex:
        args.append("-F")
    args += ["--", query, "/notes"]`, "", ""},
		// the program is a variable here (shutil.which), so a finding stays at HIGH; what matters
		// is that a "--" on one branch does not clear it
		{"-- only on one branch", `    args = [rg, "--files-with-matches"]
    if not regex:
        args += ["--"]
    args += [query, "/notes"]`, "command_injection", model.SeverityHigh},
		{"tool argument as the program", `    args = [query, "--version"]`, "command_injection", model.SeverityHigh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.build)}))
			var got []model.Finding
			for _, f := range res.Findings {
				if f.Category == "command_injection" || f.Category == "argument_injection" {
					got = append(got, f)
				}
			}
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("want no finding, got %+v", got)
				}
				return
			}
			if len(got) == 0 || got[0].Category != tc.want || got[0].Severity != tc.sev {
				t.Fatalf("want %s %s, got %+v", tc.sev, tc.want, got)
			}
		})
	}
}

// Python's builtin exec runs Python source: code execution, not a shell command
func TestPythonExecIsCodeExecution(t *testing.T) {
	src := `from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def run(code: str) -> str:
    """Evaluates a snippet"""
    exec("result = " + code)
    return "ok"
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.py": src}))
	if len(categoryFindings(res, "eval")) == 0 || len(categoryFindings(res, "command_injection")) != 0 {
		t.Fatalf("want eval, not command_injection: %+v", res.Findings)
	}
}
