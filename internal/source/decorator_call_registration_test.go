package source

import (
	"context"
	"slices"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

// mcp.tool()(fn) and mcp.tool(name=..., description=...)(fn) register tools with a plain call
// (seen in a vendor's server); the Go SDK's server.AddTools(mcp.NewServerTool(name, desc, handler,
// ...)) puts the handler third (seen in a community server). All three used to give a tree with no tool, or a tool
// without its handler.
func TestDiscover_DecoratorCallsAndNewServerTool(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"server.py": `from mcp.server.fastmcp import FastMCP


def find_exceptions(path: str) -> str:
    """Finds exceptions in a file"""
    return path


def run_query(sql: str) -> str:
    """Runs a query"""
    return sql


mcp = FastMCP("x")
mcp.tool()(find_exceptions)
mcp.tool(name="query", description="Runs an arbitrary query")(run_query)
`,
		"main.go": `package main

import "github.com/modelcontextprotocol/go-sdk/mcp"

type P struct{ Q string }

func BookSearch(ctx any, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[P]) (*mcp.CallToolResultFor[any], error) {
	return nil, nil
}

func main() {
	server := mcp.NewServer("x", "1", nil)
	server.AddTools(
		mcp.NewServerTool("book_search", "Search books by title", BookSearch, mcp.Input()),
	)
}
`,
	})
	g, _, err := Build(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	handlers := 0
	for _, c := range g.Capabilities {
		got[c.Name] = c.Description
		if c.Handler != "" {
			handlers++
		}
	}
	want := map[string]string{
		"find_exceptions": "Finds exceptions in a file",
		"query":           "Runs an arbitrary query",
		"book_search":     "Search books by title",
	}
	for name, desc := range want {
		if got[name] != desc {
			t.Errorf("capability %q: description %q, want %q (all: %v)", name, got[name], desc, got)
		}
	}
	if len(g.Capabilities) != 3 || handlers != 3 {
		names := []string{}
		for n := range got {
			names = append(names, n)
		}
		slices.Sort(names)
		t.Fatalf("want 3 capabilities with handlers, got %d (%d with handlers): %v", len(g.Capabilities), handlers, names)
	}
}
