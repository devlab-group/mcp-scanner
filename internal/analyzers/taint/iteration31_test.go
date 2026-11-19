package taint

import (
	"fmt"
	"testing"
)

func bestTriage(t *testing.T, files map[string]string, category string) string {
	t.Helper()
	res := analyze(t, mustWriteDir(t, files))
	rank := map[string]int{"": 0, "context": 1, "needs_review": 2, "potential": 3, "confirmed": 4}
	best := ""
	for _, f := range categoryFindings(res, category) {
		if tr := triageOf(f); rank[tr] > rank[best] {
			best = tr
		}
	}
	return best
}

// A check that cannot reject shell syntax - a NUL or ".." test, a prefix test - is no guard for a
// value spliced into a shell command line, in the handler or in the project function it passes
// through. A pattern test, or a test for a quote, may be the guard and keeps the finding for review.
func TestPathChecksDoNotGuardAShellCommand(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { execSync } from "child_process";
import * as path from "path";
const BASE = "/var/data";
function cleanDir(p: string): string {
  const n = path.normalize(p);
%s
  return path.resolve(BASE, n);
}
const server = new McpServer({ name: "x", version: "1" });
server.tool("pack", "Pack a folder", { folder: z.string() }, async ({ folder }) => {
  const d = cleanDir(folder);
  const out = execSync(%s).toString();
  return { content: [{ type: "text", text: out }] };
});
`
	for _, c := range []struct{ name, checks, cmd, want string }{
		{"NUL and prefix tests", "  if (n.includes(\"\\0\")) {\n    throw new Error(\"nul\");\n  }\n  if (!path.resolve(BASE, n).startsWith(BASE + path.sep)) {\n    throw new Error(\"outside\");\n  }", "`tar -czf /tmp/o.tgz ${d}`", "potential"},
		{"dotdot test", "  if (n.indexOf(\"..\") !== -1) {\n    throw new Error(\"dots\");\n  }", "`du -sh ${d}`", "potential"},
		{"anchored pattern", "  if (!/^[A-Za-z0-9_\\/]+$/.test(n)) {\n    throw new Error(\"bad\");\n  }", "`du -sh ${d}`", "needs_review"},
		{"quote test", "  if (n.includes(\"'\")) {\n    throw new Error(\"quote\");\n  }", "`du -sh '${d}'`", "needs_review"},
		{"NUL test and a stripping replace", "  if (n.includes(\"\\0\")) {\n    throw new Error(\"nul\");\n  }\n  const s = n.replace(/[;&|$`]/g, \"\");", "`du -sh ${d}`", "needs_review"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := bestTriage(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, c.checks, c.cmd)}, "command_injection")
			if got != c.want {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}

// The same in Python, a check in the handler itself; and a ".." test still counts for a path
func TestDotDotTestIsNoShellGuard(t *testing.T) {
	tmpl := `import re
import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def show(name: str) -> str:
    """Shows a file of the folder"""
    if %s:
        raise ValueError("bad name")
    %s
`
	for _, c := range []struct{ name, cond, use, category, want string }{
		{"dotdot before shell", `".." in name`, `return subprocess.run(f"cat /srv/{name}", shell=True, capture_output=True, text=True).stdout`, "command_injection", "potential"},
		{"fullmatch before shell", `not re.fullmatch(r"[A-Za-z0-9_.-]+", name)`, `return subprocess.run(f"cat /srv/{name}", shell=True, capture_output=True, text=True).stdout`, "command_injection", "needs_review"},
		{"dotdot before open", `".." in name`, `return open("/srv/" + name).read()`, "path_traversal", "needs_review"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := bestTriage(t, map[string]string{"server.py": fmt.Sprintf(tmpl, c.cond, c.use)}, c.category)
			if got != c.want {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}

// NAME.parse(v) and NAME.safeParse(v) of a project's z.object return the values they were given:
// a known pass-through, not an unknown call. A schema that checks values sends the finding to
// review; one whose every text entry is an anchored class of shell-inert characters clears the
// command line.
func TestZodParseIsAPassThrough(t *testing.T) {
	tmpl := `import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { execSync } from "child_process";
const zoneSchema = z.string().regex(/^[a-z]+$/);
const ArgsSchema = z.object({
  zone: %s,
  verbose: z.boolean().optional(),
});
const server = new Server({ name: "x", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{ name: "lookup", description: "Look up a zone", inputSchema: { type: "object", properties: { zone: { type: "string" } } } }],
}));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  %s
  const out = execSync("nslookup " + zone).toString();
  return { content: [{ type: "text", text: out }] };
});
`
	parse := "const { zone } = ArgsSchema.parse(request.params.arguments);"
	safe := "const r = ArgsSchema.safeParse(request.params.arguments);\n  if (!r.success) throw new Error(\"bad\");\n  const zone = r.data.zone;"
	for _, c := range []struct{ name, entry, call, want string }{
		{"plain string, parse", "z.string()", parse, "potential"},
		{"plain string, safeParse", "z.string()", safe, "potential"},
		{"anchored inert class", "z.string().regex(/^[a-z0-9.-]+$/)", parse, ""},
		{"refine with a function", "z.string().refine(looksFine)", safe, "needs_review"},
		{"class with a space", "z.string().regex(/^[a-z ]+$/)", parse, "needs_review"},
		{"nested schema not read", "zoneSchema", parse, "needs_review"},
		{"length bounds and trim", "z.string().min(1).max(64).trim()", safe, "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := bestTriage(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, c.entry, c.call)}, "command_injection")
			if got != c.want {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}

// pathlib's expanduser and os.path.expanduser pass the path on: the read that follows is the
// caller's path, not the result of an unknown call
func TestExpanduserPassesThePathOn(t *testing.T) {
	tmpl := `import os
from pathlib import Path
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def load(source: str) -> str:
    """Loads a document"""
    %s
`
	for _, use := range []string{
		"p = Path(source).expanduser()\n    return p.read_text()",
		"p = os.path.expanduser(source)\n    with open(p) as fh:\n        return fh.read()",
	} {
		t.Run(use[:12], func(t *testing.T) {
			if got := bestTriage(t, map[string]string{"server.py": fmt.Sprintf(tmpl, use)}, "path_traversal"); got != "potential" {
				t.Fatalf("want potential, got %q", got)
			}
		})
	}
}

// A bare parse(v) - a project's or a library's own function, not a schema's method - is not zod
func TestBareParseIsNotZod(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { parse } from "yaml";
import { execSync } from "child_process";
const server = new McpServer({ name: "x", version: "1" });
server.tool("run", "Run a job", { spec: z.string() }, async ({ spec }) => {
  const job = parse(spec);
  execSync("make " + job.target);
  return { content: [{ type: "text", text: "ok" }] };
});
`
	_ = bestTriage(t, map[string]string{"server.ts": src}, "command_injection")
}
