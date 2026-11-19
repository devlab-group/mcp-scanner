package taint

import (
	"fmt"
	"testing"
)

// A conditional whose branches are literals takes one of them: the condition picks which and
// carries no taint. The pair: a branch that is the argument itself still does.
func TestConditionalTaintsFromBranchesOnly(t *testing.T) {
	py := `from pathlib import Path
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
DOCS = Path("/srv/examples")

@mcp.tool()
def examples(kind: str) -> str:
    """Returns flow examples"""
    filename = %s
    return (DOCS / filename).read_text()
`
	ts := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFileSync } from "fs";
const server = new McpServer({ name: "x", version: "1" });
server.tool("examples", "Returns flow examples", async ({ kind }: { kind: string }) => {
  const filename = %s;
  return { content: [{ type: "text", text: readFileSync("/srv/examples/" + filename, "utf8") }] };
});
`
	for _, tc := range []struct {
		name, file, tmpl, expr string
		want                   int
	}{
		{"python literal branches", "server.py", py, `"a.jsonl" if kind == "flow" else "b.jsonl"`, 0},
		{"python argument branch", "server.py", py, `kind if kind.endswith(".jsonl") else "b.jsonl"`, 1},
		{"ts literal branches", "server.ts", ts, `kind === "flow" ? "a.jsonl" : "b.jsonl"`, 0},
		{"ts argument branch", "server.ts", ts, `kind === "flow" ? "a.jsonl" : kind`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{tc.file: fmt.Sprintf(tc.tmpl, tc.expr)}))
			if n := len(categoryFindings(res, "path_traversal")); (n > 0) != (tc.want > 0) {
				t.Fatalf("want %d path_traversal finding(s), got %d: %+v", tc.want, n, res.Findings)
			}
		})
	}
}

// Placeholders generated per element carry nothing of the elements; the pair, the elements
// themselves interpolated, still reach the query
func TestPlaceholderListIsNotTainted(t *testing.T) {
	ts := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import Database from "better-sqlite3";
const db = new Database("x.db");
const server = new McpServer({ name: "x", version: "1" });
server.tool("controls", "Lists controls in themes", async ({ themes }: { themes: string[] }) => {
  let q = "SELECT id FROM controls WHERE version = ?";
  q += %s;
  return { content: [{ type: "text", text: JSON.stringify(db.prepare(q).all(...themes)) }] };
});
`
	py := `import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
cur = sqlite3.connect("x.db").cursor()

@mcp.tool()
def controls(themes: list[str]) -> list:
    """Lists controls in themes"""
    q = "SELECT id FROM controls WHERE theme IN (" + %s + ")"
    cur.execute(q, themes)
    return cur.fetchall()
`
	for _, tc := range []struct {
		name, file, tmpl, expr string
		want                   bool
	}{
		{"ts placeholders", "server.ts", ts, "` AND theme IN (${themes.map(() => \"?\").join(\",\")})`", false},
		{"ts values", "server.ts", ts, "` AND theme IN (${themes.join(\",\")})`", true},
		{"python placeholders", "server.py", py, `", ".join(["?"] * len(themes))`, false},
		{"python generator placeholders", "server.py", py, `", ".join("?" for _ in themes)`, false},
		{"python values", "server.py", py, `", ".join(themes)`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{tc.file: fmt.Sprintf(tc.tmpl, tc.expr)}))
			if got := len(categoryFindings(res, "sql_injection")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A base URL from a zero-argument helper, then a path: the caller's value is in the path or the
// query; the pair, a helper handed the caller's value, may return any host
func TestBaseURLFromZeroArgumentHelper(t *testing.T) {
	ts := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import axios from "axios";
const server = new McpServer({ name: "x", version: "1" });
const getRefUrl = () => process.env.REF_URL || "https://api.ref.example";
const hostFor = (u: string) => u;
server.tool("read", "Reads a page", async ({ url }: { url: string }) => {
  const r = await axios.get(%s);
  return { content: [{ type: "text", text: String(r.data) }] };
});
`
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"zero-argument base", `getRefUrl() + "/read?url=" + encodeURIComponent(url)`, false},
		{"base computed from the argument", `hostFor(url) + "/read"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(ts, tc.expr)}))
			if got := len(categoryFindings(res, "ssrf")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// url += topic after url was assigned a fixed-host literal lands in the path; the pair, a url the
// caller supplied, is still SSRF
func TestAppendToFixedHostURL(t *testing.T) {
	ts := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "x", version: "1" });
server.tool("docs", "Fetches documentation", async ({ topic, base }: { topic: string; base: string }) => {
  %s
  url += topic;
  const r = await fetch(url);
  return { content: [{ type: "text", text: await r.text() }] };
});
`
	for _, tc := range []struct {
		name, init string
		want       bool
	}{
		{"literal base", `const baseUrl = "https://www.example.com/docs/latest/";
  let url = baseUrl;`, false},
		{"caller's base", `let url = base;`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(ts, tc.init)}))
			if got := len(categoryFindings(res, "ssrf")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// js-yaml's load is safe from version 4: the finding goes to review with that reason
func TestJsYamlLoadGoesToReview(t *testing.T) {
	ts := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import yaml from "js-yaml";
const server = new McpServer({ name: "x", version: "1" });
server.tool("parse", "Parses a document", async ({ doc }: { doc: string }) => {
  return { content: [{ type: "text", text: JSON.stringify(yaml.load(doc)) }] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": ts}))
	fs := categoryFindings(res, "deserialization")
	if len(fs) == 0 || fs[0].Triage != "needs_review" {
		t.Fatalf("want a deserialization finding in review, got %+v", fs)
	}
}
