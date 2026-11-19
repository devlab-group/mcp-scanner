package source

import (
	"context"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

// registerTool(name, config, handler) with both arguments declared as module constants is the
// TypeScript SDK's usual shape. Neither resolved, and the name fell back to the inline handler's
// whole source text, which prompt defense then scanned as declared text.
func TestDiscover_RegisterToolWithModuleConstants(t *testing.T) {
	const header = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
`
	cases := []struct {
		name, src, wantName, wantDesc string
		resolved                      bool
	}{
		{"const name and config object", header + `
const name = "echo";
const config = {
  title: "Echo Tool",
  description: "Echoes back the input string",
};
export const register = (server: McpServer) => {
  server.registerTool(name, config, async (args) => ({ content: [] }));
};
`, "echo", "Echoes back the input string", true},
		{"exported constants with as const", header + `
export const name = "echo" as const;
export const config = { description: "Echoes back the input string" } as const;
export const register = (server: McpServer) => {
  server.registerTool(name, config, async (args) => ({ content: [] }));
};
`, "echo", "Echoes back the input string", true},
		// The handler rebinds name, so the module constant cannot be trusted to be the one passed
		{"shadowed name stays unresolved", header + `
const name = "echo";
const config = { description: "Echoes back the input string" };
export const register = (server: McpServer) => {
  server.registerTool(name, config, async (args) => {
    const { name } = args;
    return { content: [] };
  });
};
`, "", "Echoes back the input string", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := testutil.WriteTree(t, map[string]string{"echo.ts": tc.src})
			g, _, err := Build(context.Background(), dir)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if len(g.Capabilities) != 1 {
				t.Fatalf("want one capability, got %+v", g.Capabilities)
			}
			c := g.Capabilities[0]
			if c.NameResolved != tc.resolved || (tc.resolved && c.Name != tc.wantName) {
				t.Fatalf("name = %q (resolved %v), want %q (resolved %v)", c.Name, c.NameResolved, tc.wantName, tc.resolved)
			}
			if !c.DescriptionResolved || c.Description != tc.wantDesc {
				t.Fatalf("description = %q (resolved %v), want %q", c.Description, c.DescriptionResolved, tc.wantDesc)
			}
			if got := displayName(c); strings.Contains(got, "=>") || strings.Contains(got, "\n") {
				t.Fatalf("display name carries handler code: %q", got)
			}
		})
	}
}

func TestDiscover_GoPackageConstantName(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{"main.go": `package main

import "github.com/mark3labs/mcp-go/server"

const toolName = "lookup"
const toolDesc = "Looks a record up"

func main() {
	s := server.NewMCPServer("x", "1.0.0")
	s.AddTool(toolName, toolDesc, handle)
}

func handle() {}
`})
	g, _, err := Build(context.Background(), dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, c := range g.Capabilities {
		if c.Name == "lookup" && c.Description == "Looks a record up" {
			return
		}
	}
	t.Fatalf("Go package constants not resolved: %+v", g.Capabilities)
}
