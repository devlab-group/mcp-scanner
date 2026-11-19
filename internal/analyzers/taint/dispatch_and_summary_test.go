package taint

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// triageOf reads an empty triage as potential, the default a finding is reported with
func triageOf(f model.Finding) string {
	if f.Triage == "" {
		return "potential"
	}
	return string(f.Triage)
}

// A server without an MCP SDK switches on the JSON-RPC method itself; the function its tools/call
// branch hands the request to is every tool's handler. The tool's purpose is unknown, so a whole
// argument reaching a sink goes to review, while one spliced into a command or joined under a base
// directory stays potential.
func TestHandWrittenJSONRPCServer(t *testing.T) {
	tmpl := `package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
)

type envelope struct {
	Method string          ` + "`json:\"method\"`" + `
	Params json.RawMessage ` + "`json:\"params\"`" + `
}

func runTool(raw json.RawMessage) (any, error) {
	var call struct {
		Name      string            ` + "`json:\"name\"`" + `
		Arguments map[string]string ` + "`json:\"arguments\"`" + `
	}
	if err := json.Unmarshal(raw, &call); err != nil {
		return nil, err
	}
	%s
}

func route(req envelope) any {
	switch req.Method {
	case "tools/list":
		return nil
	case "tools/call":
		res, _ := runTool(req.Params)
		return res
	}
	return nil
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var req envelope
		if json.Unmarshal(sc.Bytes(), &req) == nil {
			route(req)
		}
	}
	_ = filepath.Join
	_ = exec.Command
}
`
	for _, tc := range []struct{ name, body, category, want string }{
		{"whole argument is the path", `data, err := os.ReadFile(call.Arguments["file"])
	return string(data), err`, "path_traversal", "needs_review"},
		{"argument joined under a base", `data, err := os.ReadFile(filepath.Join("/srv/notes", call.Arguments["file"]))
	return string(data), err`, "path_traversal", "potential"},
		{"argument spliced into a shell command", `out, err := exec.Command("sh", "-c", "ping -c 1 "+call.Arguments["host"]).Output()
	return string(out), err`, "command_injection", "potential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"main.go": fmt.Sprintf(tmpl, tc.body)}))
			fs := categoryFindings(res, tc.category)
			if len(fs) == 0 || triageOf(fs[0]) != tc.want {
				t.Fatalf("want a %s finding with triage %q, got %+v", tc.category, tc.want, fs)
			}
		})
	}
}

// The tools/call literal in a server that registers its tools through an SDK (a proxy forwarding
// calls) adds no handler: the SDK's tools are the server's tools
func TestJSONRPCBranchIgnoredWhenSDKToolsExist(t *testing.T) {
	src := `import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def status() -> str:
    """Shows the service status"""
    return "ok"

def forward(msg):
    if msg.get("method") == "tools/call":
        subprocess.run("echo " + msg["params"]["name"], shell=True)
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.py": src}))
	for _, f := range categoryFindings(res, "command_injection") {
		if tr := triageOf(f); tr == "potential" || tr == "needs_review" {
			t.Fatalf("forward is no handler of this server, got %+v", f)
		}
	}
}

// Spring AI's @McpTool marks a tool method; its parameters are the tool's arguments
func TestSpringAIMcpToolAnnotation(t *testing.T) {
	tmpl := `package demo;

import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;

public class Tools {
    %s
    public String ping(@McpToolParam(description = "Host") String host) throws Exception {
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
        return new String(p.getInputStream().readAllBytes());
    }
}
`
	for _, tc := range []struct {
		name, ann string
		want      bool
	}{
		{"annotated", `@McpTool(name = "ping_host", description = "Ping a host")`, true},
		{"not annotated", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"Tools.java": fmt.Sprintf(tmpl, tc.ann)}))
			got := false
			for _, f := range categoryFindings(res, "command_injection") {
				if triageOf(f) == "potential" {
					got = true
				}
			}
			if got != tc.want {
				t.Fatalf("want a potential command injection: %v, got %+v", tc.want, categoryFindings(res, "command_injection"))
			}
		})
	}
}

// Server[Any](on_call_tool=...) is the low-level Python server constructor with a type argument
func TestGenericServerConstructorKeywords(t *testing.T) {
	src := `import os
from typing import Any
from mcp import types
from mcp.server.lowlevel import Server

def build():
    async def list_tools(ctx, params=None):
        return types.ListToolsResult(tools=[types.Tool(name="ping", description="Ping a host", inputSchema={})])

    async def call_tool(ctx, params):
        host = params.arguments["host"]
        os.system(f"ping -c 1 {host}")
        return types.CallToolResult(content=[])

    return %s(name="pinger", on_list_tools=list_tools, on_call_tool=call_tool)
`
	for _, ctor := range []string{"Server[Any]", "Server"} {
		t.Run(ctor, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(src, ctor)}))
			fs := categoryFindings(res, "command_injection")
			if len(fs) == 0 || triageOf(fs[0]) != "potential" {
				t.Fatalf("want a potential command injection, got %+v", fs)
			}
		})
	}
}

// fetch(name) where fetch is the enclosing function's own parameter runs whatever the callers
// pass; the global of that name in the pair stays a sink
func TestCallingAParameterIsNotTheLibraryFunction(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "x", version: "1" });

async function withFallback(names: string[]%s) {
  for (const n of names) {
    try { return await fetch(n); } catch { continue; }
  }
}

server.tool("quote", "Get a quote from a data source", { source: z.string() }, async ({ source }) => {
  const r = await withFallback([source]%s);
  return { content: [{ type: "text", text: String(r) }] };
});
`
	for _, tc := range []struct{ name, param, arg, want string }{
		{"fetch is a parameter", ", fetch: (n: string) => Promise<unknown>", ", (n) => cache.get(n)", "needs_review"},
		{"fetch is the global", "", "", "potential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.param, tc.arg)}))
			fs := categoryFindings(res, "ssrf")
			if len(fs) == 0 || triageOf(fs[0]) != tc.want {
				t.Fatalf("want an ssrf finding with triage %q, got %+v", tc.want, fs)
			}
		})
	}
}

// A zod enum, literal, number or boolean in the registration's own schema is validated by the SDK
// before the handler runs: such a parameter carries no text. z.string() in the pair stays a source.
func TestZodScalarSchemaParamsAreNotSeeded(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { execSync } from "child_process";
const server = new McpServer({ name: "x", version: "1" });

server.tool("git-info", "Show repository information", { view: %s }, async ({ view }) => {
  return { content: [{ type: "text", text: execSync("git " + view).toString() }] };
});
`
	for _, tc := range []struct {
		schema string
		want   bool
	}{
		{`z.enum(["status", "log"])`, false},
		{`z.number().int()`, false},
		{`z.string()`, true},
		{`z.enum(["status", "log"]).or(z.string())`, true},
	} {
		t.Run(tc.schema, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.schema)}))
			if got := len(categoryFindings(res, "command_injection")) > 0; got != tc.want {
				t.Fatalf("want a command injection finding: %v, got %+v", tc.want, categoryFindings(res, "command_injection"))
			}
		})
	}
}

// A project function whose returns never carry the argument (it writes the argument into a file
// and returns the file's own path) sends the finding at the result's use to review; one that
// returns the argument, or stores it on the object, keeps it potential
func TestReturnThatDoesNotCarryTheArgument(t *testing.T) {
	tmpl := `import subprocess, tempfile, os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

class Store:
    def save(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".py")
        with os.fdopen(fd, "w") as f:
            f.write(content)
%s

store = Store()

@mcp.tool()
def run_snippet(code: str) -> str:
    """Saves a snippet and shows its first lines"""
    p = store.save(code)
    return subprocess.run("head -n 5 " + p, shell=True, capture_output=True, text=True).stdout
`
	for _, tc := range []struct{ name, tail, want string }{
		{"returns its own temp path", "        return path", "needs_review"},
		{"returns the argument", "        return content", "potential"},
		{"stores the argument on the object", "        self.last = content\n        return path", "potential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.tail)}))
			fs := categoryFindings(res, "command_injection")
			if len(fs) == 0 || triageOf(fs[0]) != tc.want {
				t.Fatalf("want triage %q, got %+v", tc.want, fs)
			}
		})
	}
}

// pid = normalize_id(raw) inside a function on the path: the check inside the called function is on
// the value's way even though the path does not name it - when the function is named for checking,
// or when its result is what the caller returns. When the result is set aside and the raw value
// goes on, the check is not on the way.
func TestAssignedCheckerCallIsOnTheWay(t *testing.T) {
	tmpl := `import re
from pathlib import Path
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
CACHE = Path("/srv/cache")
ID = re.compile(r"[A-Za-z][A-Za-z0-9.-]*/[0-9]{7}")

def %[1]s(value: str) -> str:
    v = value.strip()
    if not ID.fullmatch(v):
        raise ValueError("invalid id")
    return v

def open_entry(raw: str) -> Path:
    pid = %[1]s(raw)
    return CACHE / %[2]s.replace("/", "__")

@mcp.tool()
def read_paper(paper_id: str) -> str:
    """Returns a cached paper"""
    entry = open_entry(paper_id)
    return (entry / "main.tex").read_text()
`
	for _, tc := range []struct{ fn, returned, want string }{
		{"normalize_id", "pid", "needs_review"},
		{"lookup_id", "pid", "needs_review"},
		{"lookup_id", "raw", "potential"},
	} {
		t.Run(tc.fn+" returns "+tc.returned, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.fn, tc.returned)}))
			fs := categoryFindings(res, "path_traversal")
			if len(fs) == 0 || triageOf(fs[0]) != tc.want {
				t.Fatalf("want triage %q, got %+v", tc.want, fs)
			}
		})
	}
}

// writeFile(path, data): the written bytes are not the file. Caller content in a file the server
// names is no path traversal; a caller-named file is.
func TestWrittenDataIsNotThePath(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "fs";
const server = new McpServer({ name: "x", version: "1" });

server.tool("save", "Save a note", { name: z.string(), text: z.string() }, async ({ name, text }) => {
  await fs.promises.writeFile(%s);
  return { content: [{ type: "text", text: "saved" }] };
});
`
	for _, tc := range []struct {
		args string
		want bool
	}{
		{`"/srv/notes/last.txt", text`, false},
		{`"/srv/notes/" + name, "x"`, true},
	} {
		t.Run(tc.args, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.args)}))
			if got := len(categoryFindings(res, "path_traversal")) > 0; got != tc.want {
				t.Fatalf("want a path finding: %v, got %+v", tc.want, categoryFindings(res, "path_traversal"))
			}
		})
	}
}

// opts.get("host") on the client's own mapping is a known lookup that hands back part of the
// argument; CACHE.get(host) on another object is a call the scanner does not follow
func TestGetByLiteralKeyOnTheClientMapping(t *testing.T) {
	tmpl := `import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
CACHE = {}

@mcp.tool()
def ping(opts: dict) -> str:
    """Ping a host"""
    host = %s
    os.system("ping -c 1 " + host)
    return "ok"
`
	for _, tc := range []struct{ expr, want string }{
		{`opts.get("host", "")`, "potential"},
		{`(opts or {}).get("host")`, "potential"},
		{`CACHE.get(opts["host"])`, "needs_review"},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.expr)}))
			fs := categoryFindings(res, "command_injection")
			if len(fs) == 0 || triageOf(fs[0]) != tc.want {
				t.Fatalf("want triage %q, got %+v", tc.want, fs)
			}
		})
	}
}

// In a hand-written JSON-RPC server only the handler parameters the tools/call branch fills carry
// the client's data: opts left to its default holds the server's own options. The same branch in a
// web asset (a browser page answering an embedded app) registers nothing.
func TestJSONRPCHandlerParamsTheBranchFills(t *testing.T) {
	tmpl := `import { rmSync } from "fs";

export async function callTool(name, args = {}, opts = {}) {
  rmSync("/srv/state/" + %s, { force: true });
  return {};
}

export async function handleMessage(msg) {
  const { method, params } = msg;
  if (method === "tools/list") {
    return { tools: [] };
  }
  if (method === "tools/call") {
    return await callTool(params.name, params.arguments || {});
  }
}
`
	for _, tc := range []struct {
		name, file, expr string
		want             bool
	}{
		{"argument the branch passes", "src/protocol.mjs", "args.id", true},
		{"option left to its default", "src/protocol.mjs", "opts.sessionId", false},
		{"browser page", "static/js/host.mjs", "args.id", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(tc.file)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(fmt.Sprintf(tmpl, tc.expr)), 0o644); err != nil {
				t.Fatal(err)
			}
			res := analyze(t, dir)
			got := false
			for _, f := range categoryFindings(res, "path_traversal") {
				if tr := triageOf(f); tr == "potential" || tr == "needs_review" {
					got = true
				}
			}
			if got != tc.want {
				t.Fatalf("want a path finding: %v, got %+v", tc.want, categoryFindings(res, "path_traversal"))
			}
		})
	}
}
