package taint

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A schema constant defined in another file declares what the parameter is for: described as a URL
// to download, the fetch is a capability; with no description it stays an injection
func TestParameterSchemaInAnotherFile(t *testing.T) {
	server := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ImageParams } from "./schemas.js";
const server = new McpServer({ name: "x", version: "1" });
server.tool("create-image", ImageParams.shape, async (params) => {
  const r = await fetch(params.url);
  return { content: [{ type: "text", text: String(r.status) }] };
});
`
	for _, c := range []struct{ name, url, kind string }{
		{"described", `z.string().describe("URL of the image to download")`, "dangerous_capability"},
		{"not described", `z.string()`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			schemas := fmt.Sprintf("import { z } from \"zod\";\nexport const ImageParams = z.object({\n  url: %s,\n});\n", c.url)
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": server, "schemas.ts": schemas}))
			fs := categoryFindings(res, "ssrf")
			if len(fs) == 0 || string(fs[0].FindingKind) != c.kind {
				t.Fatalf("want kind %q, got %+v", c.kind, fs)
			}
		})
	}
}

// A tool stores the caller's command in a module-level dict and a scheduler runs every stored
// command later: the flow through the shared container is traced. When the scheduler only counts
// the stored entries, or the state is a module object rather than a container, nothing is reported.
func TestDeferredExecutionThroughModuleState(t *testing.T) {
	tmpl := `import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
%s

@mcp.tool()
def queue_job(job: str, command: str) -> str:
    """Queues a nightly job"""
    %s
    return "queued"

def nightly_worker() -> None:
    %s
`
	for _, c := range []struct {
		name, decl, store, run string
		want                   bool
	}{
		{"container run later", "JOBS: dict[str, str] = {}", "JOBS[job] = command", "for line in list(JOBS.values()):\n        subprocess.run(line, shell=True)", true},
		{"container only counted", "JOBS: dict[str, str] = {}", "JOBS[job] = command", `subprocess.run("echo " + str(len(JOBS)), shell=True)`, false},
		{"module object, not a container", "class Queue:\n    latest = ''\nQUEUE = Queue()", "QUEUE.latest = command", "subprocess.run(QUEUE.latest, shell=True)", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, c.decl, c.store, c.run)}))
			got := false
			for _, f := range categoryFindings(res, "command_injection") {
				if f.Line > 0 && triageOf(f) == "potential" {
					got = true
				}
			}
			if got != c.want {
				t.Fatalf("want a potential command injection: %v, got %+v", c.want, categoryFindings(res, "command_injection"))
			}
		})
	}
}

// The Docker SDK runs the caller's command in a container; a fixed image and command is not a flow
func TestDockerSDKRunsTheCommand(t *testing.T) {
	tmpl := `import docker
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
client = docker.from_env()

@mcp.tool()
def check(package: str) -> str:
    """Report the installed version of a package"""
    return client.containers.run("python:3.12-slim", %s, remove=True).decode()
`
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{`f"pip show {package}"`, true},
		{`"pip list"`, false},
	} {
		t.Run(c.cmd, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "server.py"), []byte(fmt.Sprintf(tmpl, c.cmd)), 0o644); err != nil {
				t.Fatal(err)
			}
			res := analyze(t, dir)
			if got := len(categoryFindings(res, "command_injection")) > 0; got != c.want {
				t.Fatalf("want a command injection: %v, got %+v", c.want, categoryFindings(res, "command_injection"))
			}
		})
	}
}

// int(n), len(x), x.length carry a number, not the caller's text; the value itself does
func TestNumericValuesCarryNoText(t *testing.T) {
	tmpl := `import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def tail(lines: str) -> str:
    """Show the end of the service log"""
    return subprocess.run("tail -n " + %s + " /var/log/app.log", shell=True, capture_output=True, text=True).stdout
`
	for _, c := range []struct {
		expr string
		want bool
	}{
		{`str(int(lines))`, false},
		{`str(len(lines))`, false},
		{`lines`, true},
		{`lines.strip()`, true},
	} {
		t.Run(c.expr, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, c.expr)}))
			if got := len(categoryFindings(res, "command_injection")) > 0; got != c.want {
				t.Fatalf("want a command injection: %v, got %+v", c.want, categoryFindings(res, "command_injection"))
			}
		})
	}
}

// The same method names in another SDK are not Docker: the Google Tag Manager client's
// accounts.containers.create and a file without the Docker SDK import report nothing
func TestDockerSinksNeedTheDockerImport(t *testing.T) {
	src := `from googleapiclient.discovery import build
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
tagmanager = build("tagmanager", "v2")

@mcp.tool()
def create_container(account_id: str, name: str) -> str:
    """Create a Tag Manager container"""
    return str(tagmanager.accounts().containers().create(parent="accounts/" + account_id, body={"name": name}).execute())

@mcp.tool()
def create_named(name: str) -> str:
    """Create a Tag Manager container by name"""
    return str(tagmanager.accounts.containers.create(name))
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.py": src}))
	if fs := categoryFindings(res, "command_injection"); len(fs) > 0 {
		t.Fatalf("want no command injection without the Docker SDK, got %+v", fs)
	}
}
