package taint

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// False positives from the second iteration (servers 101-150), each paired with the real issue
// beside it
func TestIteration2Regressions(t *testing.T) {
	const py = `import os
import requests
import sqlite3
from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("x")
ENDPOINT = os.environ["ENDPOINT"]
cursor = sqlite3.connect("x.db").cursor()


class JobsTool:
    def execute(self, params):
        return params
`
	const ts = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "x", version: "1.0.0" });
const base = process.env.API_BASE as string;
`
	cases := []struct {
		name, file, src, category string
		want                      int
		// review: the finding stays for a person to judge (a name-based call, not proof)
		review bool
	}{
		{"f-string path after a configured base is not SSRF", "server.py", py + `
@mcp.tool()
def stream(task_id: str) -> str:
    """Streams a task"""
    return requests.get(f"{ENDPOINT}/tasks/{task_id}/stream").text
`, "ssrf", 0, false},
		{"assigned f-string path after a base is not SSRF", "server.py", py + `
@mcp.tool()
def job(job_id: str) -> str:
    """Reads a job"""
    url = f"{ENDPOINT}/jobs/{job_id}"
    return requests.get(url).text
`, "ssrf", 0, false},
		{"a host from the tool argument is still SSRF", "server.py", py + `
@mcp.tool()
def fetch(host: str) -> str:
    """Fetches from a host"""
    return requests.get(f"https://{host}/index").text
`, "ssrf", 1, false},
		{"a whole URL from the tool argument is still SSRF", "server.py", py + `
@mcp.tool()
def fetch(url: str) -> str:
    """Fetches a page"""
    return requests.get(url).text
`, "ssrf", 1, false},
		{"template path after a base is not SSRF", "server.ts", ts + "server.tool(\"get\", \"Gets an item\", async ({ id }: { id: string }) => {\n  await fetch(`${base}/v1/items/${id}`);\n  return { content: [] };\n});\n", "ssrf", 0, false},
		{"concatenated path after a base is not SSRF", "server.ts", ts + "server.tool(\"get\", \"Gets an item\", async ({ id }: { id: string }) => {\n  await fetch(base + \"/items/\" + id);\n  return { content: [] };\n});\n", "ssrf", 0, false},

		// The tool class comes from another package, so the call does not resolve in the tree and
		// only the method name matched, as in a jobs tool's jobsTool.execute(params). A receiver
		// named for a tool with no SQL text on the path drops the match
		{"execute on an imported tool object is not SQL", "server.py", `from mcp.server.fastmcp import FastMCP
from hf_tools import JobsTool

mcp = FastMCP("x")


@mcp.tool()
def run_job(params: str) -> str:
    """Runs a job"""
    jobs_tool = JobsTool()
    return jobs_tool.execute(params)
`, "sql_injection", 0, false},
		// The same file defines JobsTool.execute: resolution by method name used to send
		// cursor.execute there and drop the SQL check
		{"execute on a cursor is still SQL beside an in-repo execute method", "server.py", py + `
@mcp.tool()
def lookup(name: str) -> list:
    """Looks a row up"""
    cursor.execute("SELECT * FROM t WHERE name = '" + name + "'")
    return cursor.fetchall()
`, "sql_injection", 1, false},

		{"an encoding keyword is not a path", "server.py", py + `
from pathlib import Path


@mcp.tool()
def read_doc(encoding: str = "utf-8") -> str:
    """Reads the bundled document"""
    return Path("/srv/doc.txt").read_text(encoding=encoding)
`, "path_traversal", 0, false},
		{"a path argument is still a path", "server.py", py + `
from pathlib import Path


@mcp.tool()
def read_doc(name: str) -> str:
    """Reads a document"""
    return Path(name).read_text(encoding="utf-8")
`, "path_traversal", 1, false},
		// An in-repo query() function makes these calls resolve in the tree; a generic receiver
		// name must not turn a search API into SQL
		{"a search client's query goes to review beside an in-repo query function", "server.py", py + `
import boto3

kendra_client = boto3.client("kendra")


def query(q):
    return q


@mcp.tool()
def search(text: str, index_id: str) -> dict:
    """Searches the index"""
    return kendra_client.query(IndexId=index_id, QueryText=text)
`, "sql_injection", 1, true},
		{"an SDK context parameter is not client input", "server.py", py + `
@mcp.tool()
def info(ctx: Context) -> str:
    """Reports the request id"""
    return requests.get(ctx.request_id).text
`, "ssrf", 0, false},
		{"a string parameter named context is still client input", "server.py", py + `
@mcp.tool()
def info(context: str) -> str:
    """Fetches the context page"""
    return requests.get(context).text
`, "ssrf", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{tc.file: tc.src}))
			got := categoryFindings(res, tc.category)
			if len(got) != tc.want {
				t.Fatalf("want %d %s findings, got %d: %+v", tc.want, tc.category, len(got), res.Findings)
			}
			if tc.review && got[0].Triage != model.TriageNeedsReview {
				t.Fatalf("triage = %q, want needs_review", got[0].Triage)
			}
		})
	}
}

// A path that only continues because the scanner assumed an unresolved call passes the argument on
// is not reliable enough to call potential
func TestUnresolvedStepGoesToReview(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";
import { lookupScript } from "./store-lib";
const server = new McpServer({ name: "x", version: "1.0.0" });
server.tool("run", "Runs a stored script", async ({ id }: { id: string }) => {
  const script = lookupScript(id);
  execSync(script);
  return { content: [] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	got := categoryFindings(res, "command_injection")
	if len(got) != 1 {
		t.Fatalf("want one finding, got %+v", res.Findings)
	}
	if got[0].Triage != model.TriageNeedsReview {
		t.Fatalf("triage = %q (%s), want needs_review", got[0].Triage, got[0].TriageReason)
	}
}
