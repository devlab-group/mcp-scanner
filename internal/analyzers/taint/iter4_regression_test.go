package taint

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Findings from the fourth iteration (small diverse servers), each paired with the real issue
func TestIteration4Regressions(t *testing.T) {
	const ts = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import axios from "axios";
const server = new McpServer({ name: "x", version: "1.0.0" });
const api = axios.create({ baseURL: "https://api.bitbucket.org/2.0" });
declare const sql: { exec(q: string, ...b: unknown[]): void };
`
	const py = `import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")
BASE = "https://api.digikala.com"


async def fetch(path, params=None):
    async with httpx.AsyncClient(base_url=BASE) as c:
        return (await c.get(path, params=params)).json()
`
	cases := []struct {
		name, file, src, category string
		want                      int
	}{
		{"a relative API path on a configured client is not SSRF", "server.ts", ts + "server.tool(\"prs\", \"Lists pull requests\", async ({ ws }: { ws: string }) => {\n  await api.get(`/repositories/${ws}/pullrequests`);\n  return { content: [] };\n});\n", "ssrf", 0},
		{"a URL from the argument is still SSRF", "server.ts", ts + "server.tool(\"get\", \"Gets a page\", async ({ url }: { url: string }) => {\n  await fetch(url);\n  return { content: [] };\n});\n", "ssrf", 1},
		{"a bare slash before the argument is still SSRF", "server.ts", ts + "server.tool(\"get\", \"Gets a page\", async ({ p }: { p: string }) => {\n  await fetch(`/${p}`);\n  return { content: [] };\n});\n", "ssrf", 1},
		{"the project's own fetch is not the global one", "server.py", py + `
@mcp.tool()
async def product(product_id: str) -> dict:
    """Gets a product"""
    return await fetch(f"/v1/product/{product_id}/")
`, "ssrf", 0},
		// A fetch(req, server) method elsewhere in the tree (a Bun.serve handler) does not shadow
		// the global fetch here, as in a design-tool bridge server
		{"a same-named function in another file does not shadow the global fetch", "server.ts", ts + "server.tool(\"fill\", \"Fills from an image URL\", async ({ imageUrl }: { imageUrl: string }) => {\n  await fetch(imageUrl);\n  return { content: [] };\n});\n", "ssrf", 1},
		// A fetch method of a class in the same file (pdf.js's FetchStandardFontDataFactory, as
		// bundled by one server) cannot be called by the bare name, so the global fetch stays a sink
		{"a same-file method named fetch does not shadow the global fetch", "server.ts", ts + "class Fonts {\n  async fetch(o: { filename: string }) { return o; }\n}\nserver.tool(\"img\", \"Loads an image URL\", async ({ url }: { url: string }) => {\n  await fetch(url);\n  return { content: [] };\n});\n", "ssrf", 1},
		{"fetch imported from a package is still the HTTP fetch", "server.ts", "import fetch from \"node-fetch\";\n" + ts + "server.tool(\"get\", \"Gets a page\", async ({ url }: { url: string }) => {\n  await fetch(url);\n  return { content: [] };\n});\n", "ssrf", 1},
		{"a container exec is still a process", "server.ts", ts + "declare const container: { exec(cmd: string): void };\nserver.tool(\"run\", \"Runs a build step\", async ({ step }: { step: string }) => {\n  container.exec(\"make \" + step);\n  return { content: [] };\n});\n", "command_injection", 1},
		{"a sandbox session exec is still a process", "server.ts", ts + "declare const session: { exec(cmd: string): void };\nserver.tool(\"run\", \"Runs a build step\", async ({ step }: { step: string }) => {\n  session.exec(\"make \" + step);\n  return { content: [] };\n});\n", "command_injection", 1},
		{"sql.exec with bound values is not command injection", "server.ts", ts + "server.tool(\"edit\", \"Edits a message\", async ({ text, id }: { text: string; id: string }) => {\n  sql.exec(\"UPDATE messages SET text = ? WHERE id = ?\", text, id);\n  return { content: [] };\n});\n", "command_injection", 0},
		{"sql.exec with spliced SQL is SQL injection", "server.ts", ts + "server.tool(\"find\", \"Finds a message\", async ({ id }: { id: string }) => {\n  sql.exec(\"SELECT * FROM messages WHERE id = '\" + id + \"'\");\n  return { content: [] };\n});\n", "sql_injection", 1},
		{"Rust &self is not client input", "main.rs", `use rmcp::tool;
use std::path::PathBuf;

struct Server { root: PathBuf }

fn read_manifest(root: &std::path::Path) -> String {
    std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default()
}

impl Server {
    #[tool(description = "Reads the project manifest")]
    async fn manifest(&self) -> String {
        read_manifest(&self.root)
    }
}

fn main() {}
`, "path_traversal", 0},
		{"a Rust tool argument is still client input", "main.rs", `use rmcp::tool;

struct Server;

impl Server {
    #[tool(description = "Reads a file")]
    async fn read(&self, path: String) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }
}

fn main() {}
`, "path_traversal", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{tc.file: tc.src}
			if tc.name == "fetch imported from a package is still the HTTP fetch" {
				files["libfetch.ts"] = "export function fetch(path: string) { return path; }\n"
			}
			if tc.name == "a same-named function in another file does not shadow the global fetch" {
				files["socket.ts"] = "export const handler = {\n  fetch(req: Request, server: unknown) {\n    return new Response(\"ok\");\n  },\n};\n"
			}
			if tc.file == "main.rs" {
				files["Cargo.toml"] = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\nrmcp = \"0.1\"\n"
			}
			res := analyze(t, mustWriteDir(t, files))
			if got := categoryFindings(res, tc.category); len(got) != tc.want {
				t.Fatalf("want %d %s findings, got %d: %+v", tc.want, tc.category, len(got), res.Findings)
			}
		})
	}
}

// Two paths reach one sink: from file contents (HIGH, needs review) and from an environment
// variable (LOW, context). The kept finding is the one that matters, not the more confident one.
func TestDedupeKeepsTheMostSeverePath(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fs from "fs";
const server = new McpServer({ name: "x", version: "1.0.0" });
function load(p: string) { return fs.readFileSync(p, "utf8"); }
server.tool("cfg", "Shows the configuration", async () => {
  const fromEnv = process.env.CONFIG_PATH as string;
  const fromFile = fs.readFileSync(process.env.POINTER_FILE as string, "utf8");
  load(fromEnv);
  load(fromFile);
  return { content: [] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	got := categoryFindings(res, "path_traversal")
	var atLoad []model.Finding
	for _, f := range got {
		if f.Line == 4 {
			atLoad = append(atLoad, f)
		}
	}
	if len(atLoad) != 1 {
		t.Fatalf("want one finding at the shared sink, got %+v", got)
	}
	if atLoad[0].Severity != model.SeverityHigh {
		t.Fatalf("kept severity %s (%s), want the HIGH file-contents path", atLoad[0].Severity, atLoad[0].TriageReason)
	}
}

// Two routes to one sink, one behind a check (review, more confident) and one without (potential):
// the unchecked route is kept whichever comes first, so the check does not hide it
func TestDedupeKeepsTheUncheckedRoute(t *testing.T) {
	mk := func(triage model.Triage, conf float64) model.Finding {
		return model.Finding{RuleID: "taint.path_traversal", Category: "path_traversal", File: "a.py", Line: 3,
			Title: "tainted data reaches open", Severity: model.SeverityHigh, Confidence: conf, Triage: triage}
	}
	checked, unchecked := mk(model.TriageNeedsReview, 1), mk("", 0.85)
	for _, order := range [][]model.Finding{{checked, unchecked}, {unchecked, checked}} {
		got := dedupeFindings(order)
		if len(got) != 1 || got[0].Triage == model.TriageNeedsReview {
			t.Fatalf("want the unchecked route kept, got %+v", got)
		}
	}
}
