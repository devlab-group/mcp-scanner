package source

import (
	"context"
	"slices"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

const fastMCPServer = `from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetch")


@mcp.tool()
def fetch(url: str) -> str:
    """Fetches a URL."""
    return url
`

// A tree that imports an MCP SDK lets a receiver-less tool(...) call with two or more arguments
// count as a registration. A project's own function that happens to be named tool - the fetch
// server's test helper tool(bindir, "node", body), which writes a fake executable - is not one,
// and each of its call sites was reported as a separate, unanalyzable MCP tool.
func TestDiscover_LocalHelperNamedToolIsNotARegistration(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
		// contains checks only that every name in want was found, for a case whose other
		// capabilities this change does not touch
		contains bool
	}{
		{
			name: "helper defined and called in the same file",
			files: map[string]string{
				"server.py": fastMCPServer,
				"tests/test_subprocess.py": `from pathlib import Path


def tool(bindir: Path, name: str, body: str) -> Path:
    path = bindir / name
    path.write_text(body)
    return path


def test_node(tmp_path):
    tool(tmp_path, "node", "echo v20")
    tool(tmp_path, "npm", "exit 1")
`,
			},
			want: []string{"fetch"},
		},
		{
			name: "helper defined in another file",
			files: map[string]string{
				"server.py":         fastMCPServer,
				"tests/helpers.py":  "def tool(bindir, name, body):\n    return bindir / name\n",
				"tests/test_one.py": "from tests.helpers import *\n\n\ndef test_one(tmp_path):\n    tool(tmp_path, \"node\", \"echo\")\n",
			},
			want: []string{"fetch"},
		},
		{
			name: "server method still registers when a local function shares its name",
			files: map[string]string{
				"server.ts": `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
export const server = new McpServer({ name: "x", version: "1.0.0" });
server.tool("echo", "Echoes text back", async ({ text }) => ({ content: [{ type: "text", text }] }));
`,
				"util.ts": "export function tool(a: string, b: string) { return a + b; }\ntool(\"node\", \"npm\");\n",
			},
			want: []string{"echo"},
		},
		{
			name: "a local tool wrapper that registers is still found",
			files: map[string]string{
				"server.ts": `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
export const server = new McpServer({ name: "x", version: "1.0.0" });
function tool(name: string, description: string, handler: any) {
  server.tool(name, description, handler);
}
tool("wipe", "Deletes the workspace", async () => ({ content: [] }));
`,
			},
			want:     []string{"wipe"},
			contains: true,
		},
		{
			name: "a hand-rolled registry with an inline handler still registers",
			files: map[string]string{
				"server.ts": `import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { readFileSync } from "fs";
const tools: any[] = [];
function tool(name: string, description: string, handler: any) {
  tools.push({ name, description, handler });
}
tool("read_note", "Reads a note", async ({ path }: { path: string }) => readFileSync(path, "utf8"));
`,
			},
			want: []string{"read_note"},
		},
		{
			name: "a hand-rolled registry with a function reference still registers",
			files: map[string]string{
				"server.py": `from mcp.server.lowlevel import Server

TOOLS = {}


def tool(name, description, handler):
    TOOLS[name] = (description, handler)


def lookup(q):
    return q


tool("lookup", "Looks a record up", lookup)
`,
			},
			want: []string{"lookup"},
		},
		{
			name: "an imported tool function still registers",
			files: map[string]string{
				"server.py":  "from mcp.server.fastmcp import FastMCP\nfrom sdk.registry import tool\n\n\ndef lookup(q):\n    return q\n\n\ntool(\"lookup\", \"Looks a record up\", lookup)\n",
				"helpers.py": "def tool(bindir, name, body):\n    return bindir / name\n",
			},
			want: []string{"lookup"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := testutil.WriteTree(t, tc.files)
			g, _, err := Build(context.Background(), dir)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			var got []string
			for _, c := range g.Capabilities {
				got = append(got, c.Name)
			}
			slices.Sort(got)
			if tc.contains {
				for _, w := range tc.want {
					if !slices.Contains(got, w) {
						t.Fatalf("capabilities = %q, want %q among them", got, w)
					}
				}
				return
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("capabilities = %q, want %q", got, tc.want)
			}
		})
	}
}
