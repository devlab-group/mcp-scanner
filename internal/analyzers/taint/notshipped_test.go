package taint

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

const pyShellTool = `import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("t")


@mcp.tool()
def run(name: str) -> str:
    """Runs a check"""
    return subprocess.run(f"check {name}", shell=True, capture_output=True, text=True).stdout
`

func shellTriage(t *testing.T, files map[string]string) model.Triage {
	t.Helper()
	return shellTriageIn(t, files, "")
}

// shellTriageIn is the triage of the command injection found in file ("" for any file)
func shellTriageIn(t *testing.T, files map[string]string, file string) model.Triage {
	t.Helper()
	res := run(t, testutil.WriteTree(t, files))
	for _, f := range res.Findings {
		if f.Category == "command_injection" && (file == "" || f.File == file) {
			return f.Triage
		}
	}
	t.Fatalf("no command_injection finding in %q: %+v", file, res.Findings)
	return ""
}

const tsShellTool = `import { execSync } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
const server = new McpServer({ name: "t", version: "1" });
server.tool("run", "Runs a check", { name: z.string() }, async ({ name }) => {
  return { content: [{ type: "text", text: execSync("check " + name).toString() }] };
});
await server.connect(new StdioServerTransport());
`

// The folder's name says test or evaluation code; whether the finding goes to context depends on
// what else the tree says. A manifest or deployment file that starts the file keeps the finding; a
// test of a test framework, or a test double beside the tree's real server, is context; a server
// that is the only one of the tree, or one only a deployment file inside such a folder starts, goes
// to review with its severity.
func TestTestAndEvalCodeIsContext(t *testing.T) {
	const ctx, review, kept, notCtx = model.TriageContext, model.TriageNeedsReview, model.Triage(""), model.Triage("not context")
	elsewhere := map[string]string{"server.py": pyShellTool}
	with := func(base map[string]string, kv ...string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			out[kv[i]] = kv[i+1]
		}
		return out
	}
	for _, c := range []struct {
		name  string
		files map[string]string
		want  model.Triage // "" = neither context nor review: the finding stays as traced
		file  string       // the file whose finding is weighed, when the tree has two servers
	}{
		// the only server of the tree: the folder's name is all that says it is not run
		{"lone evaluation harness", map[string]string{"evals/harness.py": pyShellTool}, review, ""},
		{"lone server in tests", map[string]string{"tests/helper_server.py": pyShellTool}, review, ""},
		{"lone benchmark server", map[string]string{"benchmarks/srv.py": pyShellTool}, review, ""},
		// beside the tree's real server, or a test of a test framework
		{"test double beside the server", with(elsewhere, "tests/helper_server.py", pyShellTool), ctx, "tests/helper_server.py"},
		{"evaluation harness beside the server", with(elsewhere, "evals/harness.py", pyShellTool), ctx, "evals/harness.py"},
		{"pytest module", map[string]string{"test_server.py": "import pytest\n" + pyShellTool}, ctx, ""},
		{"test file named only by the test script", map[string]string{"tests/fake.test.ts": tsShellTool, "package.json": `{"scripts": {"test": "node --test tests/fake.test.ts"}}`}, ctx, ""},
		{"a word of the manifest is no entry point", with(elsewhere, "evals/harness.py", pyShellTool, "pyproject.toml", "[project]\ndescription = \"harness for evals\"\n"), ctx, "evals/harness.py"},
		// started by a package manifest or a deployment file
		{"project.scripts module path", map[string]string{"src/mypkg/evals/server.py": pyShellTool, "src/mypkg/__init__.py": "", "src/mypkg/evals/__init__.py": "", "pyproject.toml": "[project.scripts]\nmypkg-evals = \"mypkg.evals.server:main\"\n"}, kept, ""},
		{"fixture the manifest ships", map[string]string{"fixtures/demo_srv.py": pyShellTool, "pyproject.toml": "[project.scripts]\ndemo = \"fixtures.demo_srv:mcp.run\"\n"}, kept, ""},
		{"bin of a nested package", map[string]string{"benchmarks/server/index.js": tsShellTool, "benchmarks/server/package.json": `{"name": "bench-mcp", "bin": {"bench-mcp": "./index.js"}}`}, kept, ""},
		{"build output of the file", map[string]string{"src/evals/server.ts": tsShellTool, "package.json": `{"bin": {"x": "dist/evals/server.js"}}`}, kept, ""},
		{"start script", with(elsewhere, "tests/server.js", tsShellTool, "package.json", `{"scripts": {"start": "node tests/server.js"}}`), notCtx, "tests/server.js"},
		{"Dockerfile of the project", with(elsewhere, "tests/server.py", pyShellTool, "Dockerfile", "FROM python:3.12\nCOPY . /app\nCMD [\"python\", \"/app/tests/server.py\"]\n"), notCtx, "tests/server.py"},
		{"smithery start command", map[string]string{"fixtures/gitserver.py": pyShellTool, "smithery.yaml": "startCommand:\n  type: stdio\n  commandFunction: |-\n    (config) => ({ command: 'python', args: ['fixtures/gitserver.py'] })\n"}, kept, ""},
		{"python -m in a Dockerfile", with(elsewhere, "evals/server.py", pyShellTool, "Dockerfile", "FROM python:3.12\nCMD python -m evals.server\n"), kept, "evals/server.py"},
		// a deployment file inside the test or evaluation folder: whether that image runs anywhere
		// is for a person to judge
		{"image of the benchmark folder", with(elsewhere, "benchmarks/load.py", pyShellTool, "benchmarks/Dockerfile", "FROM python:3.12\nCMD [\"python\", \"load.py\"]\n"), review, "benchmarks/load.py"},
		// named by a package manifest without being started: shipped with the package, perhaps
		{"listed in files", with(elsewhere, "evals/server.js", tsShellTool, "package.json", `{"files": ["dist", "evals/server.js"]}`), review, "evals/server.js"},
		{"module in an include list", with(elsewhere, "evals/harness.py", pyShellTool, "pyproject.toml", "[tool.hatch.build.targets.wheel]\npackages = [\"src/app\", \"evals.harness\"]\n"), review, "evals/harness.py"},
		// not test code at all (a test_ name or a tests/ folder may still send a handler to review)
		{"module named test_ without tests", map[string]string{"test_runner.py": pyShellTool}, notCtx, ""},
		{"the server beside a tests folder", map[string]string{"server.py": pyShellTool, "tests/test_server.py": "import server\n"}, kept, "server.py"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := shellTriageIn(t, c.files, c.file)
			switch c.want {
			case notCtx:
				if got == ctx {
					t.Fatalf("triage %s, want anything but context", got)
				}
			case kept:
				if got == ctx || got == review {
					t.Fatalf("triage %s, want the finding kept as traced", got)
				}
			default:
				if got != c.want {
					t.Fatalf("triage %s, want %s", got, c.want)
				}
			}
		})
	}
}
