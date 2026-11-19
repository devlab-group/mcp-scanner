package taint

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
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

// The taint walk stops after a fixed amount of work, between symbols and in a fixed order: two runs
// over the same tree with the same limit report the same findings and say why they are partial
func TestWorkLimitCutsTheSameWayEveryTime(t *testing.T) {
	var b strings.Builder
	b.WriteString("import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP(\"x\")\n")
	for i := range 40 {
		fmt.Fprintf(&b, "\n@mcp.tool()\ndef run%d(cmd: str) -> str:\n    \"\"\"Runs a check\"\"\"\n    return subprocess.run(\"echo \" + cmd, shell=True, capture_output=True, text=True).stdout\n", i)
	}
	dir := mustWriteDir(t, map[string]string{"server.py": b.String()})
	full := analyze(t, dir)
	workLimit = 400
	t.Cleanup(func() { workLimit = TaintWorkLimit })
	first, second := analyzeAny(t, dir), analyzeAny(t, dir)
	if len(first.Findings) == 0 || len(first.Findings) >= len(full.Findings) {
		t.Fatalf("want the limit to cut the walk part way: %d findings with it, %d without", len(first.Findings), len(full.Findings))
	}
	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("two runs with the same limit differ: %d and %d findings", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].Line != second.Findings[i].Line {
			t.Fatalf("finding %d differs between runs: line %d and %d", i, first.Findings[i].Line, second.Findings[i].Line)
		}
	}
	if first.Status != model.AnalyzerPartial || !strings.Contains(strings.Join(first.Coverage.LimitsHit, " "), "syntax nodes") {
		t.Fatalf("want PARTIAL with the work limit named, got %s %v", first.Status, first.Coverage.LimitsHit)
	}
}

// analyzeAny runs the analyzer like analyze but accepts any status, for tests of a partial walk
func analyzeAny(t *testing.T, dir string) model.AnalyzerResult {
	t.Helper()
	a := &Analyzer{}
	target := model.Target{Kind: model.TargetSource, Path: dir}
	ac := &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()}
	return a.Analyze(context.Background(), target, ac)
}

// save_marker(marker_file(sid), data): the argument is a project function's result whose return is
// an allowlist rebuild, so the callee's parameter starts cleared; without the rebuild it stays a path
func TestCheckedResultPassedAsAnArgument(t *testing.T) {
	tmpl := `import json, re
from pathlib import Path
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
MARKERS = Path.home() / ".markers"

def marker_file(session_id: str) -> Path:
    return MARKERS / ("muted." + %s)

def save_marker(target: Path, data: dict) -> None:
    with open(target, "w") as out:
        json.dump(data, out)

@mcp.tool()
def mute(session_id: str) -> str:
    """Mute notifications of a session"""
    save_marker(marker_file(session_id), {"muted": True})
    return "ok"
`
	for _, c := range []struct {
		name, expr string
		want       bool
	}{
		{"rebuilt from an allowlist", `re.sub(r"[^A-Za-z0-9_-]", "_", session_id)`, false},
		{"used as given", `session_id`, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, c.expr)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != c.want {
				t.Fatalf("want a path finding: %v, got %+v", c.want, categoryFindings(res, "path_traversal"))
			}
		})
	}
}

// A URL that comes back from a request to a fixed host is that service's answer: the download
// goes to review. When the caller chooses the host of the first request, it stays potential.
func TestURLFromAFixedHostAnswer(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

class Api {
  async imageUrls(base: string, fileId: string): Promise<Record<string, string>> {
    const r = await fetch(%s);
    const body = (await r.json()) as { images: Record<string, string> };
    return body.images;
  }
}

const api = new Api();
const server = new McpServer({ name: "x", version: "1" });
server.tool("export", "Export images of a file", { base: z.string(), fileId: z.string() }, async ({ base, fileId }) => {
  const urls = await api.imageUrls(base, fileId);
  const img = await fetch(urls["1"]);
  return { content: [{ type: "text", text: String(img.status) }] };
});
`
	for _, c := range []struct{ name, url, want string }{
		{"fixed host", "`https://api.figma.com/v1/images/${fileId}`", "needs_review"},
		{"caller's host", "`${base}/v1/images/${fileId}`", "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, c.url)}))
			var at []model.Finding
			for _, f := range categoryFindings(res, "ssrf") {
				if f.Line == 16 {
					at = append(at, f)
				}
			}
			if len(at) == 0 || triageOf(at[0]) != c.want {
				t.Fatalf("want triage %q at the download, got %+v", c.want, categoryFindings(res, "ssrf"))
			}
		})
	}
}
