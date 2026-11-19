package taint

import (
	"fmt"
	"testing"
)

// Cases from the top-100 source scan. Each false positive is paired with the real vulnerability
// next to it, so a fix that silences the sink altogether fails here.
func TestFalsePositiveRegressions(t *testing.T) {
	const tsHeader = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fs from "fs";
import * as child_process from "child_process";
import { execSync } from "child_process";
const server = new McpServer({ name: "x", version: "1.0.0" });
declare function expect(x: any): any;
`
	tsTool := func(body string) string {
		return tsHeader + "server.tool(\"t\", \"Runs a step\", async ({ ref }: { ref: string }) => {\n" + body + "\n  return { content: [] };\n});\n"
	}
	const goHeader = `package main

import (
	"fmt"
	"database/sql"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Args struct{ Q string }

var db *sql.DB
var once sync.Once

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "x"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "list", Description: "Lists things"}, handler)
}
`
	const rsHeader = `use rmcp::tool;
use std::process::Command;

fn main() {}
`
	cases := []struct {
		name, file, src, category string
		want                      int
	}{
		// A sink word inside a string literal is not a call
		{"sink name inside a string receiver", "server.ts", tsTool(`  const s = "use readFileSync carefully".concat(ref);`), "path_traversal", 0},
		// The call is toHaveBeenCalledWith; fs.rmSync is only its receiver's argument
		{"sink inside a nested call's argument", "server.ts", tsTool(`  expect(fs.rmSync).not.toHaveBeenCalledWith(ref);`), "path_traversal", 0},
		// One finding for the execSync call, none for the .toString().trim() chained onto it
		{"chain on a sink result reports the sink once", "server.ts", tsTool("  const out = execSync(`git log ${ref}`).toString().trim();"), "command_injection", 1},
		{"compiled (0, fn) indirection still fires", "server.ts", tsTool("  (0, child_process.execSync)(`git log ${ref}`);"), "command_injection", 1},
		{"real readFileSync still fires", "server.ts", tsTool(`  fs.readFileSync(ref);`), "path_traversal", 1},

		// A schema description that says "fetch" is not an HTTP response
		{"source word inside a string literal", "main.go", goHeader + `
func handler(args Args) {
	schema := struct{ Description string }{Description: "Cursor to fetch the next page"}
	db.Query(schema.Description)
}
`, "sql_injection", 0},
		{"real HTTP response still a source", "main.go", goHeader + `
func handler(args Args) {
	resp, _ := http.Get("https://api.invalid/q")
	db.Query(resp.Status)
}
`, "sql_injection", 1},

		// sync.Once.Do takes a closure; a URL is never one
		{"Once.Do with a closure is not an HTTP call", "main.go", goHeader + `
func handler(args Args) {
	once.Do(func() { _ = args.Q })
}
`, "ssrf", 0},
		{"tainted query string still fires", "main.go", goHeader + `
func handler(args Args) {
	db.Query("SELECT * FROM t WHERE q = '" + args.Q + "'")
}
`, "sql_injection", 1},

		// tokio::spawn starts an async task; Command::new starts a process
		{"tokio::spawn is not a process", "main.rs", rsHeader + `
#[tool(description = "Queue a job")]
async fn queue(job: String) -> String {
    tokio::spawn(async move { println!("{}", job); });
    "ok".to_string()
}
`, "command_injection", 0},
		{"Command::new with a tool argument still fires", "main.rs", rsHeader + `
#[tool(description = "Run a job")]
async fn run(job: String) -> String {
    Command::new(job).output().unwrap();
    "ok".to_string()
}
`, "command_injection", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{tc.file: tc.src}
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

// Three seed shapes reaching the same sink - taint in the first argument, the second, or both -
// emitted the same finding three times under one ID
func TestFindingsAreUniquePerIdentity(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fs from "fs";
const server = new McpServer({ name: "x", version: "1.0.0" });
function load(dir: string, file: string) { return fs.readFileSync(dir + "/" + file); }
server.tool("a", "Reads a", async ({ x }: { x: string }) => { load(x, "a.txt"); return { content: [] }; });
server.tool("b", "Reads b", async ({ y }: { y: string }) => { load("/srv", y); return { content: [] }; });
server.tool("c", "Reads c", async ({ x, y }: { x: string; y: string }) => { load(x, y); return { content: [] }; });
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	seen := map[string]bool{}
	for _, f := range res.Findings {
		k := fmt.Sprintf("%s|%s|%s|%d", f.RuleID, f.File, f.Title, f.Line)
		if seen[k] {
			t.Fatalf("duplicate finding %s at %s:%d", f.RuleID, f.File, f.Line)
		}
		seen[k] = true
	}
	if n := len(categoryFindings(res, "path_traversal")); n != 1 {
		t.Fatalf("want exactly one path_traversal finding, got %d: %+v", n, res.Findings)
	}
}

func TestTitleCalleeIsOneBoundedLine(t *testing.T) {
	long := "`" + string(make([]byte, 0)) + "line one\n   line two " + string(repeat('x', 400)) + "`.trim"
	got := titleCallee(long)
	if len([]rune(got)) > maxTitleCallee+3 {
		t.Fatalf("title callee has %d runes", len([]rune(got)))
	}
	for _, r := range got {
		if r == '\n' {
			t.Fatalf("title callee keeps a newline: %q", got)
		}
	}
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
