package registration

import (
	"context"
	"testing"

	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/internal/source/language"
	"github.com/revinand/mcp-scanner/internal/source/parser"
)

func buildGraph(t *testing.T, files map[language.ID]map[string]string) *graph.Graph {
	t.Helper()
	g := graph.New("/fake")
	for lang, byPath := range files {
		adapter := language.ByID(lang)
		for path, src := range byPath {
			res, err := parser.ParseFile(context.Background(), adapter, path, []byte(src))
			if err != nil {
				t.Fatalf("ParseFile(%s): %v", path, err)
			}
			g.Files[path] = &graph.File{Path: path, Language: string(lang), Imports: res.Imports}
			for _, s := range res.Symbols {
				g.Symbols[s.ID] = s
			}
			g.Calls = append(g.Calls, res.Calls...)
		}
	}
	parser.Resolve(g)
	return g
}

func findCap(caps []graph.Capability, form string) *graph.Capability {
	for i := range caps {
		if caps[i].Form == form {
			return &caps[i]
		}
	}
	return nil
}

func TestDiscover_GoDirect(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Go: {
			"handler.go": `package main

func echoHandler(ctx context.Context, args EchoArgs) (string, error) {
	return args.Text, nil
}
`,
			"register.go": `package main

func register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "echo", Description: "Echoes input back"}, echoHandler)
}
`,
		},
	})
	Discover(g)
	c := findCap(g.Capabilities, "direct")
	if c == nil {
		t.Fatalf("no direct capability found among %+v", g.Capabilities)
	}
	if c.Kind != graph.CapabilityTool || !c.NameResolved || c.Name != "echo" {
		t.Errorf("want tool echo, got %+v", c)
	}
	if !c.DescriptionResolved || c.Description != "Echoes input back" {
		t.Errorf("want description resolved, got %+v", c)
	}
	if c.Handler == "" {
		t.Errorf("want handler resolved cross-file, got %+v", c)
	}
	if g.Symbols[c.Handler] == nil || g.Symbols[c.Handler].Name != "echoHandler" {
		t.Errorf("handler did not resolve to echoHandler: %+v", c)
	}
}

func TestDiscover_PythonDecorator(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Python: {
			"server.py": `
@mcp.tool()
def echo(text: str) -> str:
    """Echoes input back."""
    return text
`,
		},
	})
	Discover(g)
	c := findCap(g.Capabilities, "decorator")
	if c == nil {
		t.Fatalf("no decorator capability found among %+v", g.Capabilities)
	}
	if c.Kind != graph.CapabilityTool || !c.NameResolved || c.Name != "echo" {
		t.Errorf("want tool echo (from function name fallback), got %+v", c)
	}
	if !c.DescriptionResolved || c.Description != "Echoes input back." {
		t.Errorf("want description from docstring fallback, got %+v", c)
	}
}

func TestDiscover_GoFunctionalOptionsFactory(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Go: {
			"handler.go": `package main

func statusHandler(ctx context.Context, args StatusArgs) (string, error) {
	return "ok", nil
}
`,
			"register.go": `package main

func register(s *mcp.Server) {
	s.AddTool(mcp.NewTool("status",
		mcp.WithDescription("Reports the current service status"),
		mcp.WithString("url", mcp.Required()),
	), statusHandler)
}
`,
		},
	})
	Discover(g)
	c := findCap(g.Capabilities, "factory")
	if c == nil {
		t.Fatalf("no factory capability found among %+v", g.Capabilities)
	}
	if !c.NameResolved || c.Name != "status" {
		t.Errorf("want name status resolved from mcp.NewTool's first argument, got %+v", c)
	}
	if !c.DescriptionResolved || c.Description != "Reports the current service status" {
		t.Errorf("want description resolved from WithDescription, got %+v", c)
	}
	if c.Handler == "" || g.Symbols[c.Handler] == nil || g.Symbols[c.Handler].Name != "statusHandler" {
		t.Errorf("want handler resolved to statusHandler, got %+v", c)
	}
}

func TestDiscover_GoFunctionalOptionsFactory_TitleDoesNotOverrideName(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Go: {
			"handler.go": `package main

func statusHandler(ctx context.Context, args StatusArgs) (string, error) {
	return "ok", nil
}
`,
			"register.go": `package main

func register(s *mcp.Server) {
	s.AddTool(mcp.NewTool("status",
		mcp.WithTitleAnnotation("Status Checker"),
	), statusHandler)
}
`,
		},
	})
	Discover(g)
	c := findCap(g.Capabilities, "factory")
	if c == nil {
		t.Fatalf("no factory capability found among %+v", g.Capabilities)
	}
	if !c.NameResolved || c.Name != "status" {
		t.Errorf("want the NewTool positional name kept, not overridden by the title, got %+v", c)
	}
}

func TestDiscover_GoWrapper(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Go: {
			"wrap.go": `package main

func registerTool(s *mcp.Server, name string, description string, fn Handler) {
	s.AddTool(&mcp.Tool{Name: name, Description: description}, fn)
}

func setup(s *mcp.Server) {
	registerTool(s, "search", "Searches the index", searchHandler)
}
`,
		},
	})
	Discover(g)
	c := findCap(g.Capabilities, "wrapper")
	if c == nil {
		t.Fatalf("no wrapper capability found among %+v", g.Capabilities)
	}
	if !c.NameResolved || c.Name != "search" {
		t.Errorf("want name search resolved through the wrapper, got %+v", c)
	}
	if !c.DescriptionResolved || c.Description != "Searches the index" {
		t.Errorf("want description resolved through the wrapper, got %+v", c)
	}
	if c.HandlerText != "searchHandler" {
		t.Errorf("want handler text searchHandler, got %+v", c)
	}
}

func TestDiscover_GoFactory(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Go: {
			"factory.go": `package main

func newEchoTool() *mcp.Tool {
	return &mcp.Tool{Name: "echo", Description: "Echoes input"}
}

func register(s *mcp.Server) {
	s.AddTool(newEchoTool(), echoHandler)
}
`,
		},
	})
	Discover(g)
	c := findCap(g.Capabilities, "factory")
	if c == nil {
		t.Fatalf("no factory capability found among %+v", g.Capabilities)
	}
	if !c.NameResolved || c.Name != "echo" || !c.DescriptionResolved || c.Description != "Echoes input" {
		t.Errorf("want name/description resolved through the factory's return literal, got %+v", c)
	}
}

func TestDiscover_LoopIsCountedNotDropped(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Go: {
			"loop.go": `package main

func register(s *mcp.Server, names []string) {
	for _, name := range names {
		s.AddTool(&mcp.Tool{Name: name}, dispatch)
	}
}
`,
		},
	})
	Discover(g)
	c := findCap(g.Capabilities, "loop")
	if c == nil {
		t.Fatalf("registration inside a loop must still be discovered, got %+v", g.Capabilities)
	}
	if c.NameResolved {
		t.Errorf("a loop variable name is not statically known; want NameResolved=false, got %+v", c)
	}
}

func TestDiscover_TypeScriptRegisterToolConfigObject(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.TypeScript: {
			"server.ts": `
function setup(server: McpServer): void {
  server.registerTool("config_echo", { title: "Echo Tool", description: "Echoes input back" }, echoHandler);
}
`,
		},
	})
	Discover(g)
	c := findCap(g.Capabilities, "direct")
	if c == nil {
		t.Fatalf("no direct capability found among %+v", g.Capabilities)
	}
	if !c.NameResolved || c.Name != "config_echo" {
		t.Errorf("want name config_echo resolved from the first positional argument, got %+v", c)
	}
	if !c.DescriptionResolved || c.Description != "Echoes input back" {
		t.Errorf("want description resolved from the config object's description key, got %+v", c)
	}
}

func TestDiscover_TypeScriptRegisterToolTitleFallsBackForName(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.TypeScript: {
			"server.ts": `
function setup(server: McpServer, dynamicName: string): void {
  server.registerTool(dynamicName, { title: "Echo Tool", description: "Echoes input back" }, echoHandler);
}
`,
		},
	})
	Discover(g)
	c := findCap(g.Capabilities, "direct")
	if c == nil {
		t.Fatalf("no direct capability found among %+v", g.Capabilities)
	}
	if !c.NameResolved || c.Name != "Echo Tool" {
		t.Errorf("want name Echo Tool resolved from the config object's title key, got %+v", c)
	}
	if !c.DescriptionResolved || c.Description != "Echoes input back" {
		t.Errorf("want description resolved from the config object's description key, got %+v", c)
	}
}

func TestDecoratorArg_ReadsNestedDictStyleValue(t *testing.T) {
	dec := `mcp.tool(annotations={"title": "Echo Tool"})`
	v, ok := decoratorArg(dec, "title")
	if !ok || v != "Echo Tool" {
		t.Errorf("want title \"Echo Tool\" read from the nested annotations dict, got %q, %v", v, ok)
	}
}

func TestDiscover_UnresolvedNameIsStillCounted(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Go: {
			"dynamic.go": `package main

func register(s *mcp.Server, toolName string) {
	s.AddTool(&mcp.Tool{Name: toolName}, dispatch)
}
`,
		},
	})
	Discover(g)
	if len(g.Capabilities) != 1 {
		t.Fatalf("want exactly one discovered-but-unresolved capability, got %+v", g.Capabilities)
	}
	if g.Capabilities[0].NameResolved {
		t.Errorf("toolName is a runtime parameter, not a literal; want unresolved, got %+v", g.Capabilities[0])
	}
}

// Map direct prompt and resource registrations to the correct capability kind
func TestDiscover_DirectPromptAndResourceForms(t *testing.T) {
	cases := []struct {
		name string
		lang language.ID
		file string
		src  string
		want graph.CapabilityKind
	}{
		{"Go AddPrompt", language.Go, "server.go", `package main

func setup(s *mcp.Server) {
	s.AddPrompt(&mcp.Prompt{Name: "greet", Description: "Greets a user"}, greet)
}
`, graph.CapabilityPrompt},
		{"Go AddResource", language.Go, "server.go", `package main

func setup(s *mcp.Server) {
	s.AddResource(&mcp.Resource{URI: "notes://today", Name: "today", Description: "Today's notes"}, readNotes)
}
`, graph.CapabilityResource},
		{"Go AddResourceTemplate", language.Go, "server.go", `package main

func setup(s *mcp.Server) {
	s.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: "notes://{day}", Name: "notes", Description: "Notes by day"}, readNotes)
}
`, graph.CapabilityResource},
		{"TypeScript registerPrompt", language.TypeScript, "server.ts", `
function setup(server: McpServer): void {
  server.registerPrompt("greet", { description: "Greets a user" }, greet);
}
`, graph.CapabilityPrompt},
		{"TypeScript registerResource", language.TypeScript, "server.ts", `
function setup(server: McpServer): void {
  server.registerResource("notes", "notes://{name}", { description: "Notes by name" }, readNotes);
}
`, graph.CapabilityResource},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := buildGraph(t, map[language.ID]map[string]string{tc.lang: {tc.file: tc.src}})
			Discover(g)
			if len(g.Capabilities) != 1 || g.Capabilities[0].Kind != tc.want {
				t.Fatalf("want one %s capability, got %+v", tc.want, g.Capabilities)
			}
		})
	}
}
