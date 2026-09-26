package taint

import (
	"testing"

	"github.com/revinand/mcp-scanner/internal/testutil"
)

func TestTaint_ListAppendCarriesTaint(t *testing.T) {
	for name, src := range map[string]string{
		"append": `
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")

@mcp.tool()
def archive(name: str) -> str:
    """Archive a named report directory."""
    cmd = ["bash", "-c"]
    cmd.append("tar czf /tmp/out.tgz " + name)
    return subprocess.run(cmd, capture_output=True, text=True).stdout
`,
		"extend": `
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")

@mcp.tool()
def archive(name: str) -> str:
    """Archive a named report directory."""
    cmd = ["bash", "-c"]
    cmd.extend(["tar czf /tmp/out.tgz " + name])
    return subprocess.run(cmd, capture_output=True, text=True).stdout
`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := testutil.WriteTree(t, map[string]string{"server.py": src})
			res := run(t, dir)
			if got := categoryFindings(res, "command_injection"); len(got) == 0 {
				t.Fatalf("want a command_injection finding, got none (status=%s)", res.Status)
			}
		})
	}
}

func TestTaint_JSPushCarriesTaint(t *testing.T) {
	for name, snippet := range map[string]string{
		"push":    "args.push(query);",
		"unshift": "args.unshift(query);",
	} {
		t.Run(name, func(t *testing.T) {
			dir := testutil.WriteTree(t, map[string]string{"server.js": `
const { exec } = require("node:child_process");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");

const server = new McpServer({ name: "ops", version: "1.0.0" });

server.tool("run", "Run a command.", { query: { type: "string" } }, async ({ query }) => {
  const args = ["-c"];
  ` + snippet + `
  return { content: [{ type: "text", text: exec(args.join(" ")).toString() }] };
});

module.exports = server;
`})
			res := run(t, dir)
			if got := categoryFindings(res, "command_injection"); len(got) == 0 {
				t.Fatalf("want a command_injection finding, got none (status=%s)", res.Status)
			}
		})
	}
}

func TestTaint_MutatingMethodOnAttributeReceiverNotTracked(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{"server.py": `
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")

class Runner:
    def __init__(self):
        self.items = ["bash", "-c"]

    def run(self, name: str) -> str:
        self.items.append("tar czf /tmp/out.tgz " + name)
        return "ok"

runner = Runner()

@mcp.tool()
def archive(name: str) -> str:
    """Archive a named report directory."""
    return runner.run(name)
`})
	res := run(t, dir)
	if got := categoryFindings(res, "command_injection"); len(got) != 0 {
		t.Fatalf("want no command_injection finding for an attribute receiver, got %+v", got)
	}
}

func TestTaint_InsertIndexArgumentIsNotContent(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{"server.py": `
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")

@mcp.tool()
def archive(index: int) -> str:
    """Archive at a chosen position."""
    cmd = ["bash", "-c", "tar czf /tmp/out.tgz report"]
    cmd.insert(index, "--verbose")
    return subprocess.run(cmd, capture_output=True, text=True).stdout
`})
	res := run(t, dir)
	if got := categoryFindings(res, "command_injection"); len(got) != 0 {
		t.Fatalf("want no command_injection finding for taint confined to insert's index, got %+v", got)
	}
}

// TestTaint_InsertValueArgumentCarriesTaint is InsertIndexArgumentIsNotContent's
// positive: taint in the value insert actually adds must still taint the
// receiver
func TestTaint_InsertValueArgumentCarriesTaint(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{"server.py": `
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")

@mcp.tool()
def archive(name: str) -> str:
    """Archive a named report directory."""
    cmd = ["bash", "-c"]
    cmd.insert(1, "tar czf /tmp/out.tgz " + name)
    return subprocess.run(cmd, capture_output=True, text=True).stdout
`})
	res := run(t, dir)
	if got := categoryFindings(res, "command_injection"); len(got) == 0 {
		t.Fatalf("want a command_injection finding, got none (status=%s)", res.Status)
	}
}
