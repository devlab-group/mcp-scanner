package taint

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A Pydantic validator attached to the parameter's annotation runs before the handler; the
// finding goes to review naming it. The pair: the same parameter without one stays plain.
func TestAnnotationValidatorGoesToReview(t *testing.T) {
	tmpl := `import subprocess
from typing import Annotated
from pydantic import BeforeValidator
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

def validate_path(p: str) -> str:
    if p.startswith("-") or "\\n" in p:
        raise ValueError("bad path")
    return p

@mcp.tool()
def head(path: %s) -> str:
    """Shows the start of a log"""
    return subprocess.run("head -n 20 " + path, shell=True, capture_output=True, text=True).stdout
`
	for _, tc := range []struct{ name, ann, want string }{
		{"annotated validator", "Annotated[str, BeforeValidator(validate_path)]", "needs_review"},
		{"plain str", "str", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.ann)}))
			fs := categoryFindings(res, "command_injection")
			if len(fs) == 0 || string(fs[0].Triage) != tc.want {
				t.Fatalf("want triage %q, got %+v", tc.want, fs)
			}
		})
	}
}

// A helper that resolves the path and raises unless it is_relative_to the base is an input check
func TestGuardByRelativeTo(t *testing.T) {
	tmpl := `from pathlib import Path
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
BASE = Path("/srv/kb")

def resolve_note(rel: str) -> Path:
    full = (BASE / rel).resolve()
%s
    return full

@mcp.tool()
def note(rel_path: str) -> str:
    """Returns a knowledge base note"""
    return resolve_note(rel_path).read_text()
`
	// The resolved path checked with is_relative_to is proven by the helper's return summary; a
	// string-prefix check without a separator admits /srv/kb-other and stays a finding
	for _, tc := range []struct{ name, check, want string }{
		{"relative_to check", `    if not full.is_relative_to(BASE):
        raise ValueError("path escapes kb_dir")`, "none"},
		{"unanchored string check", `    if not str(full).startswith(str(BASE)):
        raise ValueError("path escapes kb_dir")`, ""},
		{"no check", `    pass`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.check)}))
			fs := categoryFindings(res, "path_traversal")
			if tc.want == "none" {
				if len(fs) != 0 {
					t.Fatalf("want no finding, got %+v", fs)
				}
				return
			}
			if len(fs) == 0 || string(fs[0].Triage) != tc.want {
				t.Fatalf("want triage %q, got %+v", tc.want, fs)
			}
		})
	}
}

// A resource-template parameter reaching a file read: a pinned SDK that screens ".." sends it to
// review; an older SDK, or the screening switched off, leaves it a plain finding
func TestResourceTemplateScreeningBySDKVersion(t *testing.T) {
	server := `from pathlib import Path
from fastmcp import FastMCP
mcp = FastMCP("x"%s)
BASE = Path("/srv/policies")

@mcp.resource("iam://policies/{filename}")
def policy(filename: str) -> str:
    """Reads a policy template"""
    return (BASE / filename).read_text()
`
	for _, tc := range []struct{ name, pin, extra, want string }{
		{"fastmcp 4 screens", "fastmcp==4.1.4\n", "", "needs_review"},
		{"fastmcp 2 does not", "fastmcp==2.12.0\n", "", ""},
		{"screening switched off", "fastmcp==4.1.4\n", ", resource_security=None", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{
				"server.py":        fmt.Sprintf(server, tc.extra),
				"requirements.txt": tc.pin,
			}))
			fs := categoryFindings(res, "path_traversal")
			if len(fs) == 0 || string(fs[0].Triage) != tc.want {
				t.Fatalf("want triage %q, got %+v", tc.want, fs)
			}
		})
	}
}

// A method-named SQL sink handed a command object is not a query; a driver's { sql, values }
// object, or a statement string, still is
func TestCommandObjectIsNotSQL(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { AppStore } from "./app-store.js";
const store = new AppStore();
const server = new McpServer({ name: "x", version: "1" });
server.tool("save", "Saves an app", async ({ app }: { app: string }) => {
  const r = store.execute(%s);
  return { content: [{ type: "text", text: JSON.stringify(r) }] };
});
`
	for _, tc := range []struct {
		name, arg string
		want      bool
	}{
		{"command object", `{ type: "save_app", name: app, actor: "agent" }`, false},
		{"driver sql object", "{ sql: `SELECT * FROM apps WHERE name = '${app}'`, values: [] }", true},
		{"statement string", "`SELECT * FROM apps WHERE name = '${app}'`", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.arg)}))
			if got := len(categoryFindings(res, "sql_injection")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A project helper named for keeping a path under its root counts as an input check
func TestGuardByUnderRootHelper(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { promises as fs } from "fs";
import * as path from "path";
const server = new McpServer({ name: "x", version: "1" });
const ROOTS = ["/srv/files"];
async function resolveRealUnderRoot(p: string): Promise<string> {
  const real = await fs.realpath(path.resolve(ROOTS[0], p));
  return real;
}
server.tool("summarize", "Summarizes a note", async ({ p }: { p: string }) => {
  const real = await resolveRealUnderRoot(p);
  return { content: [{ type: "text", text: await fs.readFile(real, "utf-8") }] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	fs := categoryFindings(res, "path_traversal")
	if len(fs) == 0 || fs[0].Triage != "needs_review" {
		t.Fatalf("want path_traversal in review, got %+v", fs)
	}
}

// Dict and object literals with no SQL field are commands, also as a keyword argument
func TestCommandDictKeywordIsNotSQL(t *testing.T) {
	src := `from mcp.server.fastmcp import FastMCP
from weave.query import Query
mcp = FastMCP("x")

@mcp.tool()
def search(name: str) -> str:
    """Searches traces"""
    return str(Query(expr={"$eq": [name]}))
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.py": src}))
	if fs := categoryFindings(res, "sql_injection"); len(fs) != 0 {
		t.Fatalf("a dict with no SQL field is not a query, got %+v", fs)
	}
}

// An API client's query() called with named fields goes to review; a cursor's execute with the
// statement, positionally or as sql=, stays a finding
func TestKeywordOnlyQueryGoesToReview(t *testing.T) {
	tmpl := `from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def stats(site_url: str) -> str:
    """Shows search statistics"""
    return str(%s)
`
	for _, tc := range []struct{ name, call, want string }{
		{"api client named fields", `service.searchanalytics().query(siteUrl=site_url, body={"rowLimit": 1})`, "needs_review"},
		{"cursor positional", `cursor.execute("SELECT * FROM t WHERE s = '" + site_url + "'")`, ""},
		{"named sql", `cursor.execute(sql="SELECT * FROM t WHERE s = '" + site_url + "'")`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.call)}))
			fs := categoryFindings(res, "sql_injection")
			if len(fs) == 0 || string(fs[0].Triage) != tc.want {
				t.Fatalf("want triage %q, got %+v", tc.want, fs)
			}
		})
	}
}

// The input check can sit two calls down: readJob(id) -> jobPath(id), which throws unless id is a uuid
func TestGuardTwoCallsDown(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { promises as fs } from "fs";
import * as path from "path";
const server = new McpServer({ name: "x", version: "1" });
function jobPath(id: string) {
  if (!/^[a-f0-9-]{36}$/.test(id)) throw new Error("JOB_ID_INVALID");
  return path.join("/srv/jobs", id + ".json");
}
async function readJob(id: string) {
  return JSON.parse(await fs.readFile(jobPath(id), "utf8"));
}
server.tool("job_status", "Shows the status of a job", async ({ id }: { id: string }) => {
  return { content: [{ type: "text", text: JSON.stringify(await readJob(id)) }] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	fs := categoryFindings(res, "path_traversal")
	if len(fs) == 0 || fs[0].Triage != "needs_review" {
		t.Fatalf("want path_traversal in review, got %+v", fs)
	}
}

// A dispatcher hands its context to every handler: a check in a handler the path never reaches
// must not stand for this value
func TestGuardNotFromAnUnrelatedHandler(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFile } from "fs/promises";
import { join } from "path";
const server = new McpServer({ name: "x", version: "1" });
async function handleDocs(input: any, context: any) {
  return readFile(join("/srv/docs", input.category + ".md"), "utf-8");
}
async function handleDevice(input: any, context: any) {
  const device = await ensureDevice(context.adb);
  if (!device) throw new Error("no device");
  return device;
}
async function dispatch(name: string, input: any, context: any) {
  if (name === "docs") return handleDocs(input, context);
  return handleDevice(input, context);
}
server.tool("docs", "Shows documentation", async (input: any) => {
  return { content: [{ type: "text", text: String(await dispatch("docs", input, {})) }] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	for _, f := range categoryFindings(res, "path_traversal") {
		if f.Triage == "needs_review" && strings.Contains(f.TriageReason, "ensureDevice") {
			t.Fatalf("a check in an unrelated handler stood for this path: %s", f.TriageReason)
		}
	}
}

// adb shell hands what follows to the device's shell; adb install takes a plain argument
func TestAdbShellIsAShell(t *testing.T) {
	tmpl := `import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def device(serial: str, target: str) -> str:
    """Works with the connected phone"""
    return subprocess.run(["adb", "-s", "emulator-5554", %s, target], capture_output=True, text=True).stdout
`
	for _, tc := range []struct {
		name, mid, cat string
	}{
		{"adb shell", `"shell", "screenrecord"`, "command_injection"},
		{"adb install", `"install"`, "argument_injection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.mid)}))
			if len(categoryFindings(res, tc.cat)) == 0 {
				t.Fatalf("want %s, got %+v", tc.cat, res.Findings)
			}
			if tc.cat == "argument_injection" && len(categoryFindings(res, "command_injection")) != 0 {
				t.Fatalf("adb install is not a shell: %+v", res.Findings)
			}
		})
	}
}

// The uri argument of a fixed resource is the server's own constant; a template's is the client's
func TestFixedResourceURIIsNotInput(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "x", version: "1" });
const BASE = process.env.DOCS_BASE || "https://docs.example.com";
const docURI = process.argv[2];
const FIXED_URI = "https://docs.example.com/llms.txt";
const PAGE_URI = "https://docs.example.com/{page}";
server.registerResource("doc", %s, { description: "A document" }, async (uri: URL) => {
  const r = await fetch(uri.href);
  return { contents: [{ uri: uri.href, text: await r.text() }] };
});
`
	for _, tc := range []struct {
		name, uri string
		want      bool
	}{
		{"fixed", `"https://docs.example.com/llms.txt"`, false},
		{"template", `"https://docs.example.com/{page}"`, true},
		{"template literal with the server's base", "`${BASE}/llms.txt`", false},
		{"template literal with a template variable", "`${BASE}/{page}`", true},
		{"variable, unknown", "docURI", true},
		{"same-file constant, fixed", "FIXED_URI", false},
		{"same-file constant, template", "PAGE_URI", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.uri)}))
			if got := len(categoryFindings(res, "ssrf")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A URL that starts with a module-level base which already closes the host keeps the request on
// that host, whatever path follows: the base is fixed when the module loads, by the server's code
// and its configuration, never by an MCP request
func TestModuleConstantBaseFixesHost(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const DOMAIN = process.env.SHOP_DOMAIN;
%s
const server = new McpServer({ name: "x", version: "1" });
async function api(endpoint: string) {
  const r = await fetch(%s);
  return r.text();
}
server.tool("get", { id: z.string() }, async ({ id }) => {
  return { content: [{ type: "text", text: await api(%s) }] };
});
`
	for _, tc := range []struct {
		name, decl, url, arg string
		want                 bool
	}{
		{"literal base", `const API = "https://api.example.com/v1/";`, "`${API}${endpoint}`", "`items/${id}`", false},
		{"template base with the host closed", "const API = `https://${DOMAIN}/admin/api/`;", "`${API}${endpoint}`", "`items/${id}`", false},
		{"template base without a slash after the host", "const API = `https://${DOMAIN}`;", "`${API}${endpoint}`", "id", true},
		{"template base with only a scheme", "const API = `https://`;", "`${API}${endpoint}`", "id", true},
		{"base is the caller's input", `const API = "";`, "`${endpoint}${API}`", "id", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := fmt.Sprintf(tmpl, tc.decl, tc.url, tc.arg)
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
			if got := len(categoryFindings(res, "ssrf")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A base built by a call that is handed only constants is not the caller's input either:
// strings.TrimRight(base, "/") + "/" + url.PathEscape(id)
func TestCallOnConstantBaseThenPath(t *testing.T) {
	src := `package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var apiBase = "https://api.crossref.org/works"

func trimSlash(s string) string { return strings.TrimRight(s, "/") }

func lookup(ctx context.Context, doi string) error {
	u := %s + "/" + url.PathEscape(doi)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	_, err = http.DefaultClient.Do(req)
	return err
}

func main() {
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("doi", mcp.WithString("doi")), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		doi, _ := r.Params.Arguments["doi"].(string)
		return nil, lookup(ctx, doi)
	})
}
`
	for _, tc := range []struct {
		name, base string
		want       bool
	}{
		{"call on a constant", "trimSlash(apiBase)", false},
		{"call on the caller's input", "trimSlash(doi)", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"main.go": fmt.Sprintf(src, tc.base)}))
			if got := len(categoryFindings(res, "ssrf")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A tool that declares what the sink does but whose description also has a scope word is not
// decided by words: "under the workspace" is a broken promise, "only locals persist" is prose.
// Both stay injections and go to review, not to potential.
func TestScopeWordInDeclaredToolGoesToReview(t *testing.T) {
	py := "from mcp.server.fastmcp import FastMCP\nfrom pathlib import Path\nmcp = FastMCP(\"x\")\n"
	for _, tc := range []struct{ name, src, category string }{
		{"a promised boundary", py + `
@mcp.tool()
def drop(path: str) -> str:
    """Deletes a file under the workspace"""
    Path(path).unlink()
    return "ok"
`, "path_traversal"},
		{"a scope word that is prose", py + `
@mcp.tool()
def py_eval(code: str) -> str:
    """Execute Python code. Globals reset per call; only locals persist."""
    return str(eval(code))
`, "eval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{"server.py": tc.src})), tc.category)
			if len(got) == 0 {
				t.Fatal("want a finding")
			}
			f := got[0]
			if f.FindingKind == model.FindingDangerousCapability || f.Triage != model.TriageNeedsReview || !f.Severity.AtLeast(model.SeverityHigh) {
				t.Fatalf("kind=%q triage=%q severity=%s, want an injection in needs_review at HIGH (%s)", f.FindingKind, f.Triage, f.Severity, f.TriageReason)
			}
		})
	}
}

// A Rust builder chain that starts at Command::new with a literal program shows the whole argv at
// its .arg() call: a plain program gets the value as one argument, a shell with -c or ssh runs it
// as a command line. A Command held in a variable stays unknown.
func TestRustBuilderChainArgv(t *testing.T) {
	const rust = "use std::process::Command;\n\n#[tool(name = \"run\", description = \"Converts a document\")]\nfn run(name: String) -> String {\n    %s;\n    String::new()\n}\n"
	for _, tc := range []struct{ name, call, want string }{
		{"plain program", `Command::new("markitdown").arg(&name).output().unwrap()`, "argument_injection"},
		{"plain program, path-qualified, other builder methods", "std::process::Command::new(\"pandoc\")\n        .current_dir(\"/tmp\")\n        .args([\"-o\", \"out.md\"])\n        .arg(&name).output().unwrap()", "argument_injection"},
		{"shell with -c", `Command::new("sh").arg("-c").arg(&name).output().unwrap()`, "command_injection"},
		{"shell with -c in args", `Command::new("bash").args(["-c", &name]).output().unwrap()`, "command_injection"},
		{"ssh", `Command::new("ssh").arg("host").arg(&name).output().unwrap()`, "command_injection"},
		{"builder in a variable", "let mut c = Command::new(\"git\");\n    c.arg(&name).output().unwrap()", "command_injection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"tool.rs": fmt.Sprintf(rust, tc.call)}))
			cmd, arg := len(categoryFindings(res, "command_injection")), len(categoryFindings(res, "argument_injection"))
			got := ""
			switch {
			case cmd > 0:
				got = "command_injection"
			case arg > 0:
				got = "argument_injection"
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q: %+v", got, tc.want, res.Findings)
			}
		})
	}
}

// mcp-go's request getters (req.RequireString("path")) return the client's argument as sent: the
// path through one is known, not an unresolved call. The same method name in a file that does not
// import mcp-go stays unresolved.
func TestMcpGoArgumentGetterIsKnown(t *testing.T) {
	src := `package main

import (
	"context"
	"os"

	%s
)

func read(ctx context.Context, req %s) (string, error) {
	p, err := req.RequireString("name")
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	return string(b), err
}

func main() {
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("show", mcp.WithDescription("Shows a note")), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t, err := read(ctx, r)
		return mcp.NewToolResultText(t), err
	})
}
`
	for _, tc := range []struct {
		name, imports, typ, want string
	}{
		{"mcp-go request", "\"github.com/mark3labs/mcp-go/mcp\"\n\t\"github.com/mark3labs/mcp-go/server\"", "mcp.CallToolRequest", "potential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"main.go": fmt.Sprintf(src, tc.imports, tc.typ)}))
			fs := categoryFindings(res, "path_traversal")
			if len(fs) == 0 {
				t.Fatalf("want a path_traversal finding, got %+v", res.Findings)
			}
			got := string(fs[0].Triage)
			if got == "" {
				got = "potential"
			}
			if got != tc.want {
				t.Fatalf("triage %q, want %q (%s)", got, tc.want, fs[0].TriageReason)
			}
		})
	}
}

func TestGetterWithoutMcpGoImportStaysUnresolved(t *testing.T) {
	main := `package main

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("show", mcp.WithDescription("Shows a note")), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t, err := read(r)
		return mcp.NewToolResultText(t), err
	})
}
`
	util := `package main

import "os"

type getter interface{ RequireString(string) (string, error) }

func read(req getter) (string, error) {
	p, err := req.RequireString("name")
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	return string(b), err
}
`
	fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{"main.go": main, "util.go": util})), "path_traversal")
	if len(fs) == 0 {
		t.Fatal("want a path_traversal finding")
	}
	if fs[0].Triage != model.TriageNeedsReview {
		t.Fatalf("triage %q, want needs_review: without the mcp-go import the getter is not known (%s)", fs[0].Triage, fs[0].TriageReason)
	}
}

// A sink name that is a parameter of the code around the call is whatever the caller passes in:
// exec("git", args) inside runGit(exec: ExecFileFn, ...) may be execFile. The finding goes to
// review. The same call to the imported child_process exec stays potential.
func TestSinkNameThatIsAParameterGoesToReview(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
%s
const server = new McpServer({ name: "x", version: "1" });
%s
server.tool("log", { ref: z.string() }, async ({ ref }) => {
  run(%s"git log " + ref);
  return { content: [{ type: "text", text: "ok" }] };
});
`
	for _, tc := range []struct {
		name, imp, fn, arg string
		want               model.Triage
	}{
		{"parameter", `import { execFile } from "node:child_process";`, "function run(exec: (c: string) => void, cmd: string) { exec(cmd); }", "execFile, ", model.TriageNeedsReview},
		{"imported child_process exec", `import { exec } from "node:child_process";`, "function run(cmd: string) { exec(cmd); }", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.imp, tc.fn, tc.arg)}))
			fs := categoryFindings(res, "command_injection")
			if len(fs) == 0 {
				t.Fatalf("want a command_injection finding, got %+v", res.Findings)
			}
			if fs[0].Triage != tc.want {
				t.Fatalf("triage %q, want %q (%s)", fs[0].Triage, tc.want, fs[0].TriageReason)
			}
		})
	}
}

// new URL(x) parses x and changes nothing about its host, so the fixed-host checks look through
// it; new URL(path, base) keeps the base's host only when the path is relative
func TestNewURLKeepsTheFixedHost(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
function apiUrl(): string { return process.env.API || "https://gitlab.example.com/api/v4"; }
const server = new McpServer({ name: "x", version: "1" });
server.tool("t", { id: z.string() }, async ({ id }) => {
  const url = %s;
  await fetch(url.toString());
  return { content: [{ type: "text", text: "ok" }] };
});
`
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"fixed base", "new URL(`${apiUrl()}/users/${id}`)", false},
		{"relative path and a configured base", "new URL(`/users/${id}`, apiUrl())", false},
		{"the caller's URL", "new URL(id)", true},
		{"the caller's input first, with a base", "new URL(id, apiUrl())", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.expr)}))
			if got := len(categoryFindings(res, "ssrf")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A const or let declared in a { } block is a new variable: in switch (name) { case "a": { const
// url = id; ... } case "b": { const url = fixed; fetch(url) } } the second url never held the
// first's value. When the block ends the outer variable of that name is back as it was.
func TestBlockScopedConstIsANewVariable(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "x", version: "1" });
server.tool("t", { id: z.string(), name: z.string() }, async ({ id, name }) => {
%s
  return { content: [{ type: "text", text: "ok" }] };
});
`
	for _, tc := range []struct {
		name, body string
		lines      []int
	}{
		{"cases do not share a variable", `  switch (name) {
    case "a": {
      const url = id;
      await fetch(url);
      break;
    }
    case "b": {
      const url = "https://api.example.com/user";
      await fetch(url);
      break;
    }
  }`, []int{8}},
		{"the outer variable is back after the block", `  let url = id;
  if (name === "x") {
    const url = "https://api.example.com/user";
    await fetch(url);
  }
  await fetch(url);`, []int{10}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.body)}))
			var got []int
			for _, f := range categoryFindings(res, "ssrf") {
				got = append(got, f.Line)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.lines) {
				t.Fatalf("ssrf findings on lines %v, want %v", got, tc.lines)
			}
		})
	}
}

// A SQLAlchemy statement built from select/update/delete/insert binds Python values as parameters.
// Raw SQL inside it - text(), literal_column(), a formatted string - or a constructor that is not
// SQLAlchemy's keeps the finding.
func TestSQLAlchemyStatementBindsValues(t *testing.T) {
	tmpl := `from mcp.server.fastmcp import FastMCP
from sqlalchemy import select as _sa_select, text
from sqlalchemy.ext.asyncio import AsyncSession
%s
mcp = FastMCP("x")

@mcp.tool()
async def find(name: str, session: AsyncSession) -> str:
    rows = await session.execute(%s)
    return str(rows.all())
`
	for _, tc := range []struct {
		name, defs, stmt string
		want             bool
	}{
		{"imported constructor", "from sqlalchemy import select", "select(User).where(User.name == name)", false},
		{"module alias", "import sqlalchemy as sa", "sa.select(User).where(User.name == name)", false},
		{"same-file wrapper", "def select(*a):\n    return _sa_select(*a)", "select(User).where(User.name == name)", false},
		{"text() inside", "from sqlalchemy import select", `select(User).where(text(f"name = '{name}'"))`, true},
		{"a raw string", "from sqlalchemy import select", `f"SELECT * FROM users WHERE name = '{name}'"`, true},
		{"a local select that is not SQLAlchemy's", "def select(*a):\n    return ' '.join(a)", "select(name)", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.defs, tc.stmt)}))
			if got := len(categoryFindings(res, "sql_injection")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// The same statement built in a variable: every assignment must be a SQLAlchemy statement or a
// method chained onto it
func TestSQLAlchemyStatementInAVariable(t *testing.T) {
	tmpl := `from mcp.server.fastmcp import FastMCP
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
mcp = FastMCP("x")

@mcp.tool()
async def find(name: str, session: AsyncSession) -> str:
    stmt = select(User)
    %s
    rows = await session.execute(stmt)
    return str(rows.all())
`
	for _, tc := range []struct {
		name, more string
		want       bool
	}{
		{"chained where", "stmt = stmt.where(User.name == name)", false},
		{"parenthesized over lines with a comment", "stmt = (\n        select(User)\n        # the user's rows (#161)\n        .where(User.name == name)\n    )", false},
		{"parenthesized continuation", "stmt = (\n        stmt.where(User.name == name)\n        .limit(10)\n    )", false},
		{"text in a later step", `stmt = stmt.where(text(f"name = '{name}'"))`, true},
		{"replaced by a string", `stmt = "SELECT * FROM users WHERE name = '" + name + "'"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.more)}))
			if got := len(categoryFindings(res, "sql_injection")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// In Java a process starts through Runtime: Runtime.getRuntime().exec(cmd). An exec method on
// another object (jolokiaService.exec(mbean, op)) matched by name alone goes to review.
func TestJavaExecOnAnotherObjectGoesToReview(t *testing.T) {
	const java = "package fixture;\n\npublic class Jobs {\n    @Tool(name = \"run\", description = \"Calls an operation\")\n    public void run(String name) throws Exception {\n        %s;\n    }\n}\n"
	for _, tc := range []struct {
		name, call string
		want       model.Triage
	}{
		{"Runtime", "Runtime.getRuntime().exec(name)", ""},
		{"another API", "jolokiaService.exec(name, \"reset\")", model.TriageNeedsReview},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{"Jobs.java": fmt.Sprintf(java, tc.call)})), "command_injection")
			if len(fs) == 0 {
				t.Fatal("want a command_injection finding")
			}
			if fs[0].Triage != tc.want {
				t.Fatalf("triage %q, want %q (%s)", fs[0].Triage, tc.want, fs[0].TriageReason)
			}
		})
	}
}

// A tool registered in a test file is test code by its path: its findings go to review. The same
// tool in the server's source stays potential.
func TestHandlerInATestFileGoesToReview(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "x", version: "1" });
server.tool("get", { url: z.string() }, async ({ url }) => {
  const r = await fetch(url, { redirect: "error" });
  return { content: [{ type: "text", text: await r.text() }] };
});
`
	for _, tc := range []struct {
		file string
		want model.Triage
	}{
		{"document-processing.test.ts", model.TriageNeedsReview},
		{"server.ts", ""},
	} {
		t.Run(tc.file, func(t *testing.T) {
			fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{tc.file: src})), "ssrf")
			if len(fs) == 0 {
				t.Fatal("want an ssrf finding")
			}
			if fs[0].Triage != tc.want {
				t.Fatalf("triage %q, want %q (%s)", fs[0].Triage, tc.want, fs[0].TriageReason)
			}
		})
	}
}

// A FastMCP tool argument annotated int, float, bool or Literal[...] is validated by the SDK before
// the handler runs: it cannot carry a path or a command. A str argument still can.
func TestScalarAnnotatedToolArgumentIsNotInjectable(t *testing.T) {
	tmpl := `import os
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def stop(%s) -> str:
    os.remove(f"/tmp/preview-{port}.pid")
    return "ok"
`
	for _, tc := range []struct {
		name, param string
		want        bool
	}{
		{"int", "port: int = 8000", false},
		{"optional int", "port: Optional[int] = None", false},
		{"int or None", "port: int | None = None", false},
		{"annotated int", "port: Annotated[int, Field(ge=1)] = 8000", false},
		{"literal", `port: Literal["a", "b"] = "a"`, false},
		{"str", "port: str = '8000'", true},
		{"no annotation", "port=8000", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.param)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A URL that is one of two branches keeps its host when each branch does
func TestConditionalURLKeepsTheHost(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import axios from "axios";
import { z } from "zod";
const api = axios.create({ baseURL: process.env.METABASE_URL });
const server = new McpServer({ name: "x", version: "1" });
server.tool("list", { ns: z.string().optional() }, async ({ ns }) => {
  const url = %s;
  const r = await fetch(url);
  return { content: [{ type: "text", text: await r.text() }] };
});
`
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"two relative paths", "ns ? `/api/collection?namespace=${ns}` : \"/api/collection\"", false},
		{"one branch is the caller's", "ns ? ns : \"/api/collection\"", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.expr)}))
			if got := len(categoryFindings(res, "ssrf")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// this.open(...) where the class defines open is the object's own method, not fs open or the
// open package; a bare open(...) with that import is still the sink
func TestOwnMethodIsNotTheSinkOfTheSameName(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs";
import { Catalog } from "./catalog.js";
export const catalog = new Catalog();
class Tracer {
  begin(id: string) { %s; }
  private open(kind: string, id: string): void { console.log("tracing", kind, id.length); }
}
const tracer = new Tracer();
const server = new McpServer({ name: "x", version: "1" });
server.tool("trace", { id: z.string() }, async ({ id }) => {
  tracer.begin(id);
  return { content: [{ type: "text", text: "ok" }] };
});
`
	for _, tc := range []struct {
		name, call string
		want       bool
	}{
		{"own method", "this.open('manual', id)", false},
		{"fs.openSync", "fs.openSync(id, \"r\")", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// another class elsewhere also has an open method, so the name alone is ambiguous
			other := "export class Catalog { open(key: string, flags: string) { return key + flags; } }\n"
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.call), "catalog.ts": other}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A dialect insert picked by a local name: ins = sqlite_insert if ... else pg_insert
func TestSQLAlchemyConstructorPickedByALocalName(t *testing.T) {
	tmpl := `from mcp.server.fastmcp import FastMCP
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
mcp = FastMCP("x")

@mcp.tool()
def add(name: str, session) -> str:
    ins = %s
    session.execute(ins(Portfolio).values(name=name))
    return "ok"
`
	for _, tc := range []struct {
		name, rhs string
		want      bool
	}{
		{"two dialect inserts", `sqlite_insert if session.get_bind().dialect.name == "sqlite" else pg_insert`, false},
		{"something else", `make_query`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.rhs)}))
			if got := len(categoryFindings(res, "sql_injection")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A Java SDK tool whose handler is a lambda is analyzed: its argument reaching Runtime.exec is
// found
func TestJavaLambdaToolHandlerIsAnalyzed(t *testing.T) {
	src := `package x;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
public final class Tools {
  public SyncToolSpecification runTool() {
    final var aTool = McpSchema.Tool.builder("run", schema).description("Starts a job").build();
    return new SyncToolSpecification(aTool, (exchange, request) -> {
      String job = (String) request.arguments().get("job");
      Runtime.getRuntime().exec("sh -c " + job);
      return null;
    });
  }
}
`
	if fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{"Tools.java": src})), "command_injection"); len(fs) == 0 {
		t.Fatal("want a command_injection finding from the lambda handler")
	}
}

// A Go tool handler that takes the project's own params type (bundling the arguments with the
// server's config) sends its findings to review; one that takes mcp.CallToolRequest does not
func TestGoCustomHandlerParamsGoToReview(t *testing.T) {
	tmpl := `package main

import (
	"context"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"example.com/x/api"
)

func read(%s) (*mcp.CallToolResult, error) {
	b, _ := os.ReadFile(%s)
	return mcp.NewToolResultText(string(b)), nil
}

func main() {
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("show", mcp.WithDescription("Shows a note")), read)
}
`
	for _, tc := range []struct {
		name, params, arg string
		want              model.Triage
	}{
		{"project params type", "params api.ToolHandlerParams", "params.Config.TokenFile", model.TriageNeedsReview},
		{"SDK request", "ctx context.Context, req mcp.CallToolRequest", "req.GetString(\"name\", \"\")", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{"main.go": fmt.Sprintf(tmpl, tc.params, tc.arg)})), "path_traversal")
			if len(fs) == 0 {
				t.Fatal("want a path_traversal finding")
			}
			if fs[0].Triage != tc.want {
				t.Fatalf("triage %q, want %q (%s)", fs[0].Triage, tc.want, fs[0].TriageReason)
			}
		})
	}
}

// os.path.commonpath([root, p]) != root followed by an exit keeps p under root once p is normalized
// (realpath, abspath, normpath); without normalization ".." still escapes and the finding stays
func TestCommonpathContainmentGuard(t *testing.T) {
	tmpl := `import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
BASE = "/var/lib/app/files"

@mcp.tool()
def fetch_file(rel: str) -> str:
    """Returns a stored file."""
    candidate = %s
    if os.path.commonpath([BASE, candidate]) != BASE:
        raise ValueError("outside")
    with open(candidate) as fh:
        return fh.read()
`
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"realpath", "os.path.realpath(os.path.join(BASE, rel))", false},
		{"normpath", "os.path.normpath(os.path.join(BASE, rel))", false},
		{"not normalized", "os.path.join(BASE, rel)", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.expr)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A project function that returns its parameter only after a containment check clears the call's
// result: open(resolve(name)) and p = resolve(name); open(p). A function that returns the
// parameter unchecked, or checks it wrongly, does not.
func TestReturnSummaryCarriesAContainmentCheck(t *testing.T) {
	tmpl := `import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
BASE = os.path.realpath("/var/lib/app")

def locate(rel):
    full = os.path.realpath(os.path.join(BASE, rel))
    %s
    return full

@mcp.tool()
def load(rel: str) -> str:
    """Loads a stored item."""
    %s
`
	check := "if full != BASE and not full.startswith(BASE + os.sep):\n        raise ValueError(\"outside\")"
	for _, tc := range []struct {
		name, guard, use string
		want             bool
	}{
		{"checked, used inline", check, "with open(locate(rel)) as fh:\n        return fh.read()", false},
		{"checked, used through a variable", check, "p = locate(rel)\n    with open(p) as fh:\n        return fh.read()", false},
		{"not checked", "pass", "with open(locate(rel)) as fh:\n        return fh.read()", true},
		{"checked without a separator", "if not full.startswith(BASE):\n        raise ValueError(\"outside\")", "with open(locate(rel)) as fh:\n        return fh.read()", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.guard, tc.use)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// The Go form: a method returning (path, error) only after a root check, called as
// abs, err := w.resolve(p); if err != nil { return }; os.ReadFile(abs)
func TestReturnSummaryGoResolver(t *testing.T) {
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

type space struct{ root string }

func (w *space) resolve(rel string) (string, error) {
	p := filepath.Clean(filepath.Join(w.root, rel))
	if %s {
		return "", errors.New("escapes the workspace")
	}
	return p, nil
}

type tools struct{ w *space }

func (t *tools) read(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	abs, err := t.w.resolve(r.GetString("path", ""))
	if err != nil {
		return nil, err
	}
	b, _ := os.ReadFile(abs)
	return mcp.NewToolResultText(string(b)), nil
}

func main() {
	t := &tools{w: &space{root: "/srv"}}
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("show_note", mcp.WithDescription("Shows a note")), t.read)
}
`
	for _, tc := range []struct {
		name, cond string
		want       bool
	}{
		{"prefix with a separator", `p != w.root && !strings.HasPrefix(p, w.root+string(filepath.Separator))`, false},
		{"prefix without a separator", `!strings.HasPrefix(p, w.root)`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"main.go": fmt.Sprintf(tmpl, tc.cond)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A value rebuilt from an allowlist of letters, digits, "_" and "-" cannot carry a separator or a
// dot; an allowlist that keeps "." or "/" still can
func TestAllowlistRebuildClearsPath(t *testing.T) {
	tmpl := `import re
from pathlib import Path
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
STORE = Path("/var/lib/app/profiles")

@mcp.tool()
def drop_profile(label: str) -> str:
    """Removes a saved profile."""
    clean = %s
    (STORE / f"{clean}.json").unlink()
    return "removed"
`
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"join with a replacement", `"".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in label)`, false},
		{"join with a filter", `"".join(ch for ch in label if ch.isalnum())`, false},
		{"re.sub negated class", `re.sub(r"[^A-Za-z0-9_-]", "", label)`, false},
		{"join that keeps dots", `"".join(ch for ch in label if ch.isalnum() or ch in "._")`, true},
		{"re.sub that keeps slashes", `re.sub(r"[^A-Za-z0-9/_-]", "", label)`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.expr)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

func TestAllowlistRebuildClearsPathTS(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { unlinkSync } from "node:fs";
const server = new McpServer({ name: "x", version: "1" });
server.tool("drop_profile", "Removes a saved profile", { label: z.string() }, async ({ label }) => {
  const clean = %s;
  unlinkSync("/var/lib/app/profiles/" + clean + ".json");
  return { content: [{ type: "text", text: "removed" }] };
});
`
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"negated class", `label.replace(/[^a-zA-Z0-9_-]/g, "")`, false},
		{"class that keeps dots", `label.replace(/[^a-zA-Z0-9._-]/g, "")`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.expr)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// The program of an argv call that is a parameter or a variable decides between a command line and
// an argument, so the finding goes to review; a same-file constant counts as the literal it holds
func TestArgvProgramNotWrittenOut(t *testing.T) {
	tmpl := `import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
SHELL = "/bin/sh"

def run(program, argv):
    return subprocess.run([program, *argv], capture_output=True, text=True).stdout

@mcp.tool()
def log_since(rev: str) -> str:
    """Lists commits since a revision."""
    %s
`
	for _, tc := range []struct {
		name, body string
		want       model.Triage
	}{
		{"program is a parameter", `return run("git", ["log", rev])`, model.TriageNeedsReview},
		{"program is a same-file constant shell", `return subprocess.run([SHELL, "-c", "git log " + rev], capture_output=True, text=True).stdout`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.body)})), "command_injection")
			if len(fs) == 0 {
				t.Fatalf("want a command_injection finding")
			}
			got := fs[0].Triage
			for _, f := range fs {
				if f.Triage == "" {
					got = ""
				}
			}
			if got != tc.want {
				t.Fatalf("triage %q, want %q (%s)", got, tc.want, fs[0].TriageReason)
			}
		})
	}
}

// An argv unpacked into the call (create_subprocess_exec(*cmd)) was built elsewhere: whether the
// tainted element is the program or an argument is unknown, so the finding goes to review
func TestUnpackedArgvGoesToReview(t *testing.T) {
	src := `import asyncio
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

async def execute(cmd):
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    return out.decode()

@mcp.tool()
async def describe(pkg: str) -> str:
    """Describes a package."""
    return await execute(["pip", "show", pkg])
`
	fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{"server.py": src})), "command_injection")
	if len(fs) == 0 {
		t.Fatal("want a command_injection finding")
	}
	for _, f := range fs {
		if f.Triage != model.TriageNeedsReview {
			t.Fatalf("triage %q, want needs_review (%s)", f.Triage, f.TriageReason)
		}
	}
}

// A sink method called on a cleaned helper's result: entry_file(key).read_text()
func TestReturnSummaryOnTheReceiver(t *testing.T) {
	tmpl := `import re
from pathlib import Path
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
CACHE = Path("/var/cache/app")

def entry_file(key):
    token = %s
    return CACHE / f"{token}.bin"

@mcp.tool()
def cached(key: str) -> str:
    """Returns a cached entry."""
    return entry_file(key).read_text()
`
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"cleaned", `re.sub(r"[^A-Za-z0-9_-]", "", key)`, false},
		{"not cleaned", `key.strip()`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.expr)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// Go's os/exec package name is not a shell exec: exec.LookPath only searches PATH
func TestGoExecPackageIsNotAShellExec(t *testing.T) {
	src := `package main

import (
	"context"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("which", mcp.WithDescription("Finds an indexer")), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		p, _ := exec.LookPath("idx-" + r.GetString("lang", ""))
		return mcp.NewToolResultText(p), nil
	})
}
`
	if fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{"main.go": src})), "command_injection"); len(fs) != 0 {
		t.Fatalf("exec.LookPath reported as command injection: %+v", fs)
	}
}

// A Go parameter typed bool or numeric cannot carry text: a query built from it is not injectable.
// The same flow into a string parameter still is.
func TestGoScalarParameterCarriesNoText(t *testing.T) {
	tmpl := `package main

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var db *sql.DB

func listChats(ctx context.Context, label string, %s) error {
	q := fmt.Sprintf("SELECT * FROM chats WHERE %%v = 1", flag)
	_, err := db.QueryContext(ctx, q+" AND label = ?", label)
	return err
}

func main() {
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("chats", mcp.WithDescription("Lists chats")), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return nil, listChats(ctx, r.GetString("label", ""), %s)
	})
}
`
	for _, tc := range []struct {
		name, param, arg string
		want             bool
	}{
		{"bool parameter", "flag bool", `r.GetString("flag", "") != ""`, false},
		{"string parameter", "flag string", `r.GetString("flag", "")`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"main.go": fmt.Sprintf(tmpl, tc.param, tc.arg)}))
			if got := len(categoryFindings(res, "sql_injection")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A hex-encoded value holds only 0-9 and a-f: a file name built from it cannot leave its directory
func TestHexEncodingClearsPath(t *testing.T) {
	tmpl := `import hashlib
import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
STORE = "/var/lib/app/snapshots"

def snapshot_name(view):
    return %s

@mcp.tool()
def save_snapshot(view: str, body: str) -> str:
    """Stores a snapshot of a view."""
    with open(os.path.join(STORE, snapshot_name(view)), "w") as fh:
        fh.write(body)
    return "saved"
`
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"hex of the bytes", `f"snap_{view.encode('utf-8').hex()}.json"`, false},
		{"digest", `hashlib.sha256(view.encode()).hexdigest() + ".json"`, false},
		{"hex beside the raw value", `f"{view}_{view.encode().hex()}.json"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.expr)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// An interface method with one implementation per dialect, each quoting its arguments through the
// project's own escaping function: the query is not proven safe, but it is not a plain injection
// either, so it goes to review. Without the escaping it stays a finding.
func TestEscapingInsideEveryImplementationGoesToReview(t *testing.T) {
	tmpl := `package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type Dialect interface{ Call(proc string, args ...string) string }
type mysqlDialect struct{}
type pgDialect struct{}

func escapeLiteral(s string) string { return strings.ReplaceAll(s, "'", "''") }

func (mysqlDialect) Call(proc string, args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = %s
	}
	return fmt.Sprintf("CALL %%s(%%s);", proc, strings.Join(q, ", "))
}

func (pgDialect) Call(proc string, args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = %s
	}
	return fmt.Sprintf("SELECT %%s(%%s);", proc, strings.Join(q, ", "))
}

var db *sql.DB
var dialect Dialect = mysqlDialect{}

func main() {
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("checkout", mcp.WithDescription("Checks out a branch")), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		_, err := db.ExecContext(ctx, dialect.Call("DOLT_CHECKOUT", r.GetString("branch", "")))
		return nil, err
	})
}
`
	esc, raw := `fmt.Sprintf("'%%s'", escapeLiteral(a))`, `fmt.Sprintf("'%%s'", a)`
	for _, tc := range []struct {
		name, a, b string
		want       model.Triage
	}{
		{"every implementation escapes", esc, esc, model.TriageNeedsReview},
		{"one implementation does not", esc, raw, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{"main.go": fmt.Sprintf(tmpl, tc.a, tc.b)})), "sql_injection")
			if len(fs) == 0 {
				t.Fatal("want a sql_injection finding")
			}
			if fs[0].Triage != tc.want {
				t.Fatalf("triage %q, want %q (%s)", fs[0].Triage, tc.want, fs[0].TriageReason)
			}
		})
	}
}

// Arguments past a variadic position reach the variadic parameter: run("git", "log", rev) with
// def run(program, *argv), and call(proc, a, b) with func call(proc string, args ...string)
func TestVariadicArgumentsReachTheirParameter(t *testing.T) {
	py := `import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

def run(program, *argv):
    return subprocess.run(" ".join([program, *argv]), shell=True, capture_output=True, text=True).stdout

@mcp.tool()
def log_since(rev: str) -> str:
    """Lists commits since a revision."""
    return run("git", "log", rev)
`
	goSrc := `package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var db *sql.DB

func call(proc string, args ...string) string {
	return fmt.Sprintf("CALL %s('%s');", proc, strings.Join(args, "','"))
}

func main() {
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("reset", mcp.WithDescription("Resets a branch")), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		_, err := db.ExecContext(ctx, call("DOLT_RESET", "--soft", r.GetString("rev", "")))
		return nil, err
	})
}
`
	for _, tc := range []struct{ name, file, src, category string }{
		{"python *argv", "server.py", py, "command_injection"},
		{"go ...string", "main.go", goSrc, "sql_injection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{tc.file: tc.src})), tc.category); len(fs) == 0 {
				t.Fatalf("want a %s finding through the variadic parameter", tc.category)
			}
		})
	}
}

// A Go function declared to return a bool or a number hands back no text
func TestGoScalarResultCarriesNoText(t *testing.T) {
	tmpl := `package main

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var db *sql.DB

func option(r mcp.CallToolRequest, name string) %s {
	v, _ := r.GetArguments()[name].(%s)
	return v%s
}

func main() {
	s := server.NewMCPServer("x", "1")
	s.AddTool(mcp.NewTool("kill", mcp.WithDescription("Stops a process")), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		q%s := option(r, "query")
		_, err := db.ExecContext(ctx, fmt.Sprintf("KILL %%v", q))
		return nil, err
	})
}
`
	for _, tc := range []struct {
		name, typ string
		want      bool
	}{
		{"bool result", "bool", false},
		{"string result", "string", true},
		{"number and error", "(int64, error)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, ret, recv := tc.typ, "", ""
			if tc.typ == "(int64, error)" {
				base, ret, recv = "int64", ", nil", ", _"
			}
			res := analyze(t, mustWriteDir(t, map[string]string{"main.go": fmt.Sprintf(tmpl, tc.typ, base, ret, recv)}))
			if got := len(categoryFindings(res, "sql_injection")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A function that returns the value only through the project's quoting function, written in the
// return itself, sends the sink to review
func TestEscapingInTheReturnGoesToReview(t *testing.T) {
	src := `import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
db = sqlite3.connect("app.db")

def quote_ident(name):
    return '"' + name.replace('"', '""') + '"'

def describe_sql(table):
    return "PRAGMA table_info(" + quote_ident(table) + ")"

@mcp.tool()
def describe(table: str) -> list:
    """Describes a table."""
    return db.execute(describe_sql(table)).fetchall()
`
	fs := categoryFindings(analyze(t, mustWriteDir(t, map[string]string{"server.py": src})), "sql_injection")
	if len(fs) == 0 || fs[0].Triage != model.TriageNeedsReview {
		t.Fatalf("want a sql_injection finding in review, got %+v", fs)
	}
}

// A summarized call inside a larger assigned expression: name = f"{prefix(path)}{stamp}.json"
func TestReturnSummaryInsideAnAssignedExpression(t *testing.T) {
	tmpl := `import os
import time
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
BACKUPS = "/var/lib/app/backups"

def prefix(path):
    return %s

@mcp.tool()
def backup(path: str, body: str) -> str:
    """Backs up a dashboard."""
    name = f"{prefix(path)}{int(time.time())}.json"
    with open(os.path.join(BACKUPS, name), "w") as fh:
        fh.write(body)
    return name
`
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"hex prefix", `f"dash_{path.encode('utf-8').hex()}_"`, false},
		{"raw prefix", `f"dash_{path}_"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.expr)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}

// A plain name after a dot is another object's attribute: os.path in os.path.join is not the tool's
// path parameter. The parameter itself is still found.
func TestAttributeIsNotTheVariableOfTheSameName(t *testing.T) {
	tmpl := `import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
STORE = "/var/lib/app"

@mcp.tool()
def archive(path: str) -> str:
    """Archives an item."""
    name = %s
    with open(os.path.join(STORE, name)) as fh:
        return fh.read()
`
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"name does not use path", `"latest.json"`, false},
		{"name uses path", `path + ".json"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.expr)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, res.Findings)
			}
		})
	}
}
