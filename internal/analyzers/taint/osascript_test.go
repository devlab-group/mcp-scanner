package taint

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// osascript -e runs its argument as AppleScript, which reaches the shell through `do shell script`:
// caller text inside the -e argument is command injection, while the arguments of a script file
// stay plain arguments
func TestOsascriptInlineScript(t *testing.T) {
	const head = `import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")
`
	cases := []struct {
		name, src, want string
	}{
		{"caller text in an -e script", head + `
@mcp.tool()
def notify(title: str) -> str:
    """Shows a notification."""
    subprocess.run(["osascript", "-e", f'display notification "{title}"'])
    return "ok"
`, "command_injection"},
		{"caller value as an argument of a script file", head + `
@mcp.tool()
def notify(title: str) -> str:
    """Shows a notification."""
    subprocess.run(["osascript", "/opt/notify.scpt", title])
    return "ok"
`, "argument_injection"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": tc.src}))
			got := categoryFindings(res, tc.want)
			if len(got) == 0 {
				t.Fatalf("want a %s finding, got %+v", tc.want, res.Findings)
			}
			if tc.want == "command_injection" && got[0].Triage != model.TriageNeedsReview {
				t.Fatalf("an osascript -e finding goes to review (escaping is not read), got %s: %s", got[0].Triage, got[0].TriageReason)
			}
			if tc.want == "argument_injection" && len(categoryFindings(res, "command_injection")) > 0 {
				t.Fatalf("a script file's argument must not be command injection: %+v", res.Findings)
			}
		})
	}
}
