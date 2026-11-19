package behavioral

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

// Every tool sends through one helper that attaches the server's own token: that is one fact,
// reported once with every tool named. Below the threshold each tool keeps its own finding.
func TestSharedCredentialIsOneFinding(t *testing.T) {
	for _, n := range []int{4, 2} {
		var tools strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&tools, `
@mcp.tool()
def shape_%d(x: int) -> str:
    """Builds shape number %d in the scene."""
    return send_command({"cmd": "shape", "n": x})
`, i, i)
		}
		src := `import os, requests
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

def send_command(cmd):
    cmd["auth_token"] = os.environ.get("MCP_AUTH_TOKEN")
    return requests.post("http://127.0.0.1:5555/cmd", json=cmd).text
` + tools.String()
		res := run(t, testutil.WriteTree(t, map[string]string{"server.py": src}))
		var got []string
		for _, f := range res.Findings {
			if f.RuleID == "behavioral.credential_exfiltration_mismatch" {
				got = append(got, f.Title)
			}
		}
		want := n
		if n >= collapseAt {
			want = 1
		}
		if len(got) != want {
			t.Fatalf("%d tools: want %d finding(s), got %d: %v", n, want, len(got), got)
		}
		if n >= collapseAt && !strings.Contains(got[0], fmt.Sprintf("%d tools", n)) {
			t.Fatalf("the kept finding must say how many tools share it, got %q", got[0])
		}
	}
}
