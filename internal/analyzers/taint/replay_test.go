package taint

import (
	"context"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

// Two tools pass their argument into one helper with a sink. The helper is walked once for that
// argument shape; the second tool's path must still be recorded, or which tool a finding names -
// and, for content sources, whether it is reachable at all - depends on which caller came first.
func TestReplay_SecondCallerOfASharedHelperKeepsItsPath(t *testing.T) {
	dir := mustWriteDir(t, map[string]string{
		"helper.py": `import subprocess

def run_remote(cmd):
    return subprocess.run("ssh host " + cmd, shell=True)
`,
		"a_tools.py": `from mcp.server.fastmcp import FastMCP
from helper import run_remote
mcp = FastMCP("a")

@mcp.tool()
def execute_script(cmd: str) -> str:
    """Runs a script"""
    return run_remote(cmd)
`,
		"b_tools.py": `from mcp.server.fastmcp import FastMCP
from helper import run_remote
mcp = FastMCP("b")

@mcp.tool()
def run_script(cmd: str) -> str:
    """Runs a stored script"""
    return run_remote(cmd)
`,
	})
	ac := &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()}
	g, _, _, err := source.LoadGraph(context.Background(), ac, dir)
	if err != nil {
		t.Fatal(err)
	}
	tc := newCtx(context.Background(), g)
	defer tc.closeAll()
	tc.walkAll(context.Background())
	sources := map[string]bool{}
	for _, f := range tc.findings {
		if f.Category == "command_injection" && len(f.Evidence) > 0 {
			sources[f.Evidence[0].Path[0].File] = true
		}
	}
	if !sources["a_tools.py"] || !sources["b_tools.py"] {
		t.Fatalf("want a command_injection path from each tool, got paths from %v", sources)
	}
}

// A caller that passes a fixed-host URL walks the request helper first with SSRF cleared; a later
// caller that passes the client's whole URL has the same parameters but is not cleared, so it must
// be walked on its own rather than stand behind the cleared walk
func TestReplay_ClearedSeedDoesNotStandForAnUnclearedOne(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "x", version: "1" });

async function get(url: string) {
  const r = await fetch(url);
  return r.text();
}

server.tool("a_status", "Gets the status page", async ({ id }: { id: string }) => {
  return { content: [{ type: "text", text: await get("https://status.example.invalid/" + id) }] };
});

server.tool("b_fetch", "Fetches a page", async ({ url }: { url: string }) => {
  return { content: [{ type: "text", text: await get(url + "?raw=1") }] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	if len(categoryFindings(res, "ssrf")) == 0 {
		t.Fatalf("the uncleared caller's SSRF is lost behind the cleared one: %+v", res.Findings)
	}
}
