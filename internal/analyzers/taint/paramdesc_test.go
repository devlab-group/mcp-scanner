package taint

import (
	"fmt"
	"testing"
)

// A parameter's own description can declare what the tool does when the registration has no
// description; a parameter described as something else (an identifier) still makes the flow an
// injection, and a description that promises a boundary sends it to review
func TestParameterDescriptionDeclaresTheCapability(t *testing.T) {
	type tc struct{ name, file, src, category, wantKind, wantTriage string }
	ts := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "fs";
const server = new McpServer({ name: "x", version: "1" });
server.tool("summarize", { filePath: %s }, async ({ filePath }) => {
  return { content: [{ type: "text", text: String(fs.readFileSync(filePath).length) }] };
});
`
	py := `from typing import Annotated
from pydantic import Field
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def show(path: %s) -> str:
%s    with open(path) as f:
        return f.read()
`
	goSrc := `package main

import (
	"context"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("show", mcp.WithString("target", mcp.Required(), mcp.Description(%q))), handle)
}

func handle(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, _ := req.RequireString("target")
	data, err := os.ReadFile(target)
	return mcp.NewToolResultText(string(data)), err
}
`
	for _, c := range []tc{
		{"zod describe says file", "server.ts", fmt.Sprintf(ts, `z.string().describe("Path to the PDF file")`), "path_traversal", "dangerous_capability", "potential"},
		{"zod without describe", "server.ts", fmt.Sprintf(ts, `z.string()`), "path_traversal", "", "potential"},
		{"zod describe says identifier", "server.ts", fmt.Sprintf(ts, `z.string().describe("Identifier of the saved report")`), "path_traversal", "", "potential"},
		{"zod describe promises the workspace", "server.ts", fmt.Sprintf(ts, `z.string().describe("Path to a file inside the project workspace")`), "path_traversal", "", "needs_review"},
		{"Annotated Field says file", "server.py", fmt.Sprintf(py, `Annotated[str, Field(description="Path to the log file")]`, ""), "path_traversal", "dangerous_capability", "potential"},
		{"Annotated Field says identifier", "server.py", fmt.Sprintf(py, `Annotated[str, Field(description="Identifier of the saved report")]`, ""), "path_traversal", "", "potential"},
		{"docstring Args say file", "server.py", fmt.Sprintf(py, `str`, "    \"\"\"Show it.\n\n    Args:\n        path: Path to the log file\n    \"\"\"\n"), "path_traversal", "dangerous_capability", "potential"},
		{"mcp-go Description says file", "main.go", fmt.Sprintf(goSrc, "Path to the log file"), "path_traversal", "dangerous_capability", "potential"},
		{"mcp-go Description says identifier", "main.go", fmt.Sprintf(goSrc, "Identifier of the saved report"), "path_traversal", "", "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{c.file: c.src}))
			fs := categoryFindings(res, c.category)
			if len(fs) == 0 {
				t.Fatalf("want a %s finding, got none", c.category)
			}
			if string(fs[0].FindingKind) != c.wantKind || triageOf(fs[0]) != c.wantTriage {
				t.Fatalf("want kind %q triage %q, got kind %q triage %q (%s)", c.wantKind, c.wantTriage, fs[0].FindingKind, triageOf(fs[0]), fs[0].TriageReason)
			}
		})
	}
}

// A check on the path is reported even in a tool whose purpose is the sink: a page fetcher that
// tests the URL against one site goes to review, the same fetcher without the test is a capability
func TestCheckOnThePathWinsOverTheCapability(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "x", version: "1" });
server.tool("fetch-page", "Fetch a web page by URL", { url: z.string() }, async ({ url }) => {
%s  const r = await fetch(url);
  return { content: [{ type: "text", text: await r.text() }] };
});
`
	for _, c := range []struct{ name, check, kind, triage string }{
		{"with a host check", "  if (!url.match(/^https:\\/\\/[a-z]+\\.wikipedia\\.org\\/wiki\\//)) {\n    throw new Error(\"only Wikipedia\");\n  }\n", "", "needs_review"},
		{"without a check", "", "dangerous_capability", "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, c.check)}))
			fs := categoryFindings(res, "ssrf")
			if len(fs) == 0 || string(fs[0].FindingKind) != c.kind || triageOf(fs[0]) != c.triage {
				t.Fatalf("want kind %q triage %q, got %+v", c.kind, c.triage, fs)
			}
		})
	}
}
