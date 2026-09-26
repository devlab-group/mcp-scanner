package registration

import (
	"testing"

	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/internal/source/language"
)

func findCaps(caps []graph.Capability, form string) []graph.Capability {
	var out []graph.Capability
	for _, c := range caps {
		if c.Form == form {
			out = append(out, c)
		}
	}
	return out
}

func TestDiscover_TypeScriptRequestHandler(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.TypeScript: {
			"server.ts": `server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      { name: "search_logs", description: "Searches project logs for a pattern" },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const pattern = request.params.arguments.pattern;
  exec("grep -r " + pattern + " /var/log");
});
`,
		},
	})
	Discover(g)

	caps := findCaps(g.Capabilities, "request_handler")
	if len(caps) != 1 {
		t.Fatalf("want exactly 1 request_handler capability, got %d: %+v", len(caps), g.Capabilities)
	}
	c := caps[0]
	if c.Kind != graph.CapabilityTool {
		t.Errorf("want a tool capability, got %+v", c)
	}
	if !c.NameResolved || c.Name != "search_logs" {
		t.Errorf("want name search_logs resolved from the tools array, got %+v", c)
	}
	if !c.DescriptionResolved || c.Description != "Searches project logs for a pattern" {
		t.Errorf("want the description resolved from the tools array, got %+v", c)
	}
	if c.Handler == "" {
		t.Fatalf("want the Handler wired to the CallToolRequestSchema dispatch handler, got %+v", c)
	}
	if g.Symbols[c.Handler] == nil {
		t.Fatalf("Handler %q does not resolve to a symbol", c.Handler)
	}
}

func TestDiscover_TypeScriptRequestHandler_ConciseArrowBody(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.TypeScript: {
			"server.ts": `server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "search_logs", description: "Searches project logs for a pattern" },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) =>
  exec("grep -r " + request.params.arguments.pattern + " /var/log")
);
`,
		},
	})
	Discover(g)

	caps := findCaps(g.Capabilities, "request_handler")
	if len(caps) != 1 {
		t.Fatalf("want exactly 1 request_handler capability, got %d: %+v", len(caps), g.Capabilities)
	}
	c := caps[0]
	if !c.NameResolved || c.Name != "search_logs" {
		t.Errorf("want name search_logs resolved from the concise-body tools array, got %+v", c)
	}
	if !c.DescriptionResolved || c.Description != "Searches project logs for a pattern" {
		t.Errorf("want the description resolved from the concise-body tools array, got %+v", c)
	}
	if c.Handler == "" || g.Symbols[c.Handler] == nil {
		t.Fatalf("want the Handler wired to the concise-body dispatch handler, got %+v", c)
	}
}

func TestDiscover_TypeScriptRequestHandler_UnresolvedListStillEmitsOne(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.TypeScript: {
			"server.ts": `server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools: await loadToolsFromDatabase() };
});

server.setRequestHandler(CallToolRequestSchema, dispatch);

async function dispatch(request) {
  return "";
}
`,
		},
	})
	Discover(g)

	caps := findCaps(g.Capabilities, "request_handler")
	if len(caps) != 1 {
		t.Fatalf("want exactly 1 unresolved request_handler capability, got %d: %+v", len(caps), g.Capabilities)
	}
	c := caps[0]
	if c.NameResolved || c.DescriptionResolved {
		t.Errorf("want an unresolved capability, got %+v", c)
	}
	if c.Handler == "" {
		t.Fatalf("want the Handler still wired to dispatch even though the list side did not resolve, got %+v", c)
	}
}

func TestDiscover_PythonRequestHandlerDecorators(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Python: {
			"server.py": `
@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name="search_logs", description="Searches project logs for a pattern"),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    pattern = arguments["pattern"]
    os.system("grep -r " + pattern + " /var/log")
`,
		},
	})
	Discover(g)

	caps := findCaps(g.Capabilities, "request_handler")
	if len(caps) != 1 {
		t.Fatalf("want exactly 1 request_handler capability, got %d: %+v", len(caps), g.Capabilities)
	}
	c := caps[0]
	if c.Kind != graph.CapabilityTool {
		t.Errorf("want a tool capability, got %+v", c)
	}
	if !c.NameResolved || c.Name != "search_logs" {
		t.Errorf("want name search_logs resolved from the list_tools return value, got %+v", c)
	}
	if !c.DescriptionResolved || c.Description != "Searches project logs for a pattern" {
		t.Errorf("want the description resolved from the list_tools return value, got %+v", c)
	}
	if c.Handler == "" || g.Symbols[c.Handler] == nil || g.Symbols[c.Handler].Name != "call_tool" {
		t.Errorf("want Handler wired to call_tool, got %+v", c)
	}

	// The bug this regresses: two ordinary tool registrations literally
	// named after the decorators themselves, and no visibility into the
	// real tool at all
	for _, cap := range g.Capabilities {
		if cap.Name == "list_tools" || cap.Name == "call_tool" {
			t.Errorf("list_tools/call_tool must not be read as tool registrations of their own, got %+v", g.Capabilities)
		}
	}
}
