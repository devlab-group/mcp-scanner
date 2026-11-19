package taint

import (
	"fmt"
	"testing"
)

// A check two calls below the handler: open -> locate, whose result the caller returns, and
// locate rejects the path through ensureUnder(ctx, full). Without that call the path stays
// potential.
func TestCheckTwoCallsBelowTheHandler(t *testing.T) {
	tmpl := `package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const reportsDir = "/var/lib/reports"

func ensureUnder(ctx context.Context, target string) error {
	r, err := filepath.Rel(reportsDir, target)
	if err != nil || strings.HasPrefix(r, "..") {
		return errors.New("not under the reports dir")
	}
	return nil
}

func locate(ctx context.Context, name string) (string, error) {
	full := filepath.Clean(filepath.Join(reportsDir, name))
%s	return full, nil
}

func openReport(ctx context.Context, name string) (string, error) {
	target, err := locate(ctx, name)
	if err != nil {
		return "", err
	}
	return target, nil
}

func handle(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, _ := req.RequireString("report")
	target, err := openReport(ctx, name)
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	defer out.Close()
	return mcp.NewToolResultText("exported"), nil
}

func main() {
	s := server.NewMCPServer("reports", "1")
	s.AddTool(mcp.NewTool("export_report", mcp.WithString("report", mcp.Required())), handle)
	_ = errors.New
	_ = strings.HasPrefix
}
`
	for _, c := range []struct{ name, check, want string }{
		{"checked", "\tif err := ensureUnder(ctx, full); err != nil {\n\t\treturn \"\", err\n\t}\n", "needs_review"},
		{"not checked", "", "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"main.go": fmt.Sprintf(tmpl, c.check)}))
			fs := categoryFindings(res, "path_traversal")
			if len(fs) == 0 || triageOf(fs[0]) != c.want {
				t.Fatalf("want triage %q, got %+v", c.want, fs)
			}
		})
	}
}

// dashboard.open(args.path) on an object a project function built, in a project that defines its
// own open() twice (a controller and its stub, so the name does not resolve to one), goes to
// review; the same call on an object from a library stays potential
func TestMethodSinkOnAProjectBuiltObject(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { makeOpener } from "some-opener-lib";

function createDashboardController() {
  return { async open(p: string) { return "http://127.0.0.1:7777/" + p.length; } };
}

function createStubController() {
  return { async open(p: string) { return "stub " + p.length; } };
}

const server = new McpServer({ name: "x", version: "1" });
const dashboard = %s;

server.tool("show", "Show a view", { path: z.string() }, async (args) => {
  const r = await dashboard.open(args.path);
  return { content: [{ type: "text", text: String(r) }] };
});
`
	for _, c := range []struct{ name, recv, want string }{
		{"built by a project function", "createDashboardController()", "needs_review"},
		{"built by a library", "makeOpener()", "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, c.recv)}))
			fs := categoryFindings(res, "path_traversal")
			if len(fs) == 0 || triageOf(fs[0]) != c.want {
				t.Fatalf("want triage %q, got %+v", c.want, fs)
			}
		})
	}
}

// SQL a language model wrote from the question goes to review; SQL built from the question by an
// f-string stays potential
func TestLanguageModelOutputReachingTheSink(t *testing.T) {
	tmpl := `import sqlite3
from openai import OpenAI
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
client = OpenAI()

def make_sql(question: str) -> str:
%s

@mcp.tool()
def ask(question: str) -> str:
    """Answer a question about the sales data"""
    sql = make_sql(question)
    return str(sqlite3.connect("s.db").execute(sql).fetchall())
`
	for _, c := range []struct{ name, body, want string }{
		{"model writes the SQL", `    resp = client.chat.completions.create(model="m", messages=[{"role": "user", "content": f"SQL for: {question}"}])
    return resp.choices[0].message.content`, "needs_review"},
		{"f-string builds the SQL", `    return f"SELECT * FROM sales WHERE region = '{question}'"`, "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, c.body)}))
			fs := categoryFindings(res, "sql_injection")
			if len(fs) == 0 || triageOf(fs[0]) != c.want {
				t.Fatalf("want triage %q, got %+v", c.want, fs)
			}
		})
	}
}

// (args) => axios.get(args.url): the member read from the whole-arguments object names the
// parameter whose description declares the capability
func TestMemberOfTheArgumentsObjectNamesTheParameter(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";
const server = new McpServer({ name: "x", version: "1" });
server.tool("get_article", { url: %s, article: z.string() }, async (args) => {
  const r = await axios.get(args.url);
  return { content: [{ type: "text", text: String(r.data) }] };
});
`
	for _, c := range []struct{ name, schema, kind string }{
		{"described as a URL to download", `z.string().describe("Official URL of the norm to download")`, "dangerous_capability"},
		{"not described", `z.string()`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, c.schema)}))
			fs := categoryFindings(res, "ssrf")
			if len(fs) == 0 || string(fs[0].FindingKind) != c.kind {
				t.Fatalf("want kind %q, got %+v", c.kind, fs)
			}
		})
	}
}
