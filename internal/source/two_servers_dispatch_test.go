package source

import (
	"context"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

// Two low-level servers in one tree, each with its own @app.call_tool() named call_tool: every
// tool goes to the dispatcher of its own module, and the answer is the same on every build. One
// dispatcher per kind for the whole tree used to keep whichever map order visited last.
func TestDispatchPerServerModule(t *testing.T) {
	server := func(tool string) string {
		return `from mcp.server import Server
from mcp.types import Tool, TextContent

app = Server("x")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(name="` + tool + `", description="A tool", inputSchema={"type": "object"})]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    return [TextContent(type="text", text=name)]
`
	}
	dir := testutil.WriteTree(t, map[string]string{
		"pkg/server.py":     server("search"),
		"pkg/server_old.py": server("legacy_search"),
	})
	for i := range 20 {
		g, _, err := Build(context.Background(), dir)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, c := range g.Capabilities {
			if c.Handler == "" {
				continue
			}
			h := g.Symbols[c.Handler]
			if h == nil || h.File != c.File {
				t.Fatalf("build %d: the tool listed in %s dispatches to %v", i, c.File, h)
			}
			n++
		}
		if n != 2 {
			t.Fatalf("build %d: want 2 tools with a handler, got %d", i, n)
		}
	}
}
