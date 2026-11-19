package registration

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

func handlerNames(g *graph.Graph) map[string]string {
	out := map[string]string{}
	for _, c := range g.Capabilities {
		if c.Handler != "" && g.Symbols[c.Handler] != nil {
			out[c.Name] = g.Symbols[c.Handler].Name
		} else {
			out[c.Name] = ""
		}
	}
	return out
}

// A module base class registers through self._add_tool(server=..., method=self.search, name=...),
// and the helper hands the SDK offload_to_thread(method): the handler is the method passed in
func TestDiscover_HandlerPassedAsMethodKeyword(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Python: {
			"base.py": `from mcp.server.fastmcp import FastMCP

class Base:
    def _add_tool(self, server, method, name):
        prefixed = f"x_{name}"
        server.add_tool(offload_to_thread(method), name=prefixed)
`,
			"hosts.py": `class Hosts(Base):
    def register(self, server):
        self._add_tool(server=server, method=self.search_hosts, name="search_hosts")

    def search_hosts(self, query: str) -> str:
        """Searches hosts."""
        return query

    def register_more(self, server):
        server.add_tool(self.list_hosts, name="list_hosts", description=computed_description())

    def list_hosts(self) -> str:
        """Docstring the explicit description replaces."""
        return ""
`,
		},
	})
	Discover(g)
	if h := handlerNames(g)["search_hosts"]; h != "search_hosts" {
		t.Fatalf("want search_hosts handled by search_hosts, got %q in %+v", h, g.Capabilities)
	}
	for _, c := range g.Capabilities {
		switch c.Name {
		case "search_hosts":
			if !c.DescriptionResolved || c.Description != "Searches hosts." {
				t.Errorf("want the handler's docstring as description, got %+v", c)
			}
		case "list_hosts":
			// The pair: a description argument the scanner cannot read stays unresolved; the
			// docstring is not what the client sees
			if c.DescriptionResolved {
				t.Errorf("explicit computed description must stay unresolved, got %+v", c)
			}
		}
	}
}

// accountTool(name, config, handler) turns its handler into a local callback before registering;
// the function the call site passes is still the handler
func TestDiscover_WrapperWithLocalCallbackKeepsCallSiteHandler(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.TypeScript: {
			"context.ts": `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
export function makeContext(server: McpServer) {
  return {
    accountTool(name: string, config: any, handler: any) {
      const { callback } = buildAccountTool(config, handler);
      return server.registerTool(name, config, callback);
    },
  };
}
`,
			"tools.ts": `export function register(context: any) {
  context.accountTool("list_gateways", { description: "List gateways" }, async (params: any) => {
    return { content: [{ type: "text", text: String(params.page) }] };
  });
}
`,
		},
	})
	Discover(g)
	var c *graph.Capability
	for i := range g.Capabilities {
		if g.Capabilities[i].Name == "list_gateways" {
			c = &g.Capabilities[i]
		}
	}
	if c == nil || c.Handler == "" {
		t.Fatalf("want list_gateways with the inline handler, got %+v", g.Capabilities)
	}
	if !c.DescriptionResolved || c.Description != "List gateways" {
		t.Fatalf("want the call site's config description, got %+v", c)
	}
}

// The pair: a wrapper whose call site passes no function keeps no handler, rather than taking a
// non-function argument for one
func TestDiscover_WrapperWithoutFunctionArgumentHasNoHandler(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.TypeScript: {
			"context.ts": `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
export function makeContext(server: McpServer) {
  return {
    namedTool(name: string, config: any) {
      return server.registerTool(name, config, defaultHandler());
    },
  };
}
`,
			"tools.ts": `export function register(context: any) {
  context.namedTool("ping", { description: "Ping" });
}
`,
		},
	})
	Discover(g)
	for _, c := range g.Capabilities {
		if c.Name == "ping" && c.Handler != "" {
			t.Fatalf("ping must not get a handler, got %+v", c)
		}
	}
}
