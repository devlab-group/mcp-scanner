package taint

import "testing"

// A tree without a resolved MCP handler drops a path to context only when nothing in it says MCP:
// an MCP dependency or package name in a manifest keeps the path a question, as an import does
func TestNoHandlerTreeNeedsNoSignOfMCP(t *testing.T) {
	const build = `import { execSync } from "child_process";
import * as fs from "fs";
export function build() {
  const target = fs.readFileSync("/etc/tool/target.conf", "utf8");
  execSync("make " + target);
}
`
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"plain command-line tool", map[string]string{"build.ts": build}, "context"},
		{"a manifest without MCP", map[string]string{"build.ts": build, "pyproject.toml": "[project]\nname = \"converter\"\ndependencies = [\"requests\"]\n"}, "context"},
		{"MCP in requirements", map[string]string{"build.ts": build, "requirements.txt": "mcp==1.9.0\nrequests\n"}, "needs_review"},
		{"package named as an MCP server", map[string]string{"build.ts": build, "package.json": `{"name": "notes-mcp-server", "version": "1.0.0"}`}, "needs_review"},
		{"rmcp in a Cargo manifest", map[string]string{"build.ts": build, "Cargo.toml": "[dependencies]\nrmcp = \"0.1\"\n"}, "needs_review"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := bestTriage(t, c.files, "command_injection"); got != c.want {
				t.Fatalf("triage %q, want %q", got, c.want)
			}
		})
	}
}
