package registration

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

// A resource's URI and description each come from their own place: the URI from its argument
// (a literal or a same-file constant), the description from the metadata object, never the URI
func TestDiscover_ResourceURIAndDescription(t *testing.T) {
	for _, tc := range []struct {
		name, src             string
		uri, desc             string
		descResolved, isFixed bool
	}{
		{"registerResource, URI constant", `
const RESOURCE_URI = "memory://graph";
function setup(server: McpServer): void {
  server.registerResource("graph", RESOURCE_URI, { title: "Graph", description: "The whole graph", mimeType: "application/json" }, read);
}`, "memory://graph", "The whole graph", true, true},
		{"registerResource, URI literal", `
function setup(server: McpServer): void {
  server.registerResource("graph", "memory://graph", { description: "The whole graph" }, read);
}`, "memory://graph", "The whole graph", true, true},
		{"registerResource, metadata constant", `
const META = { title: "Graph", description: "The whole graph" };
function setup(server: McpServer): void {
  server.registerResource("graph", "memory://graph", META, read);
}`, "memory://graph", "The whole graph", true, true},
		{"older server.resource with metadata", `
function setup(server: McpServer): void {
  server.resource("guide", "wiki://guide", { mimeType: "text/plain", description: "Onboarding guide" }, async (uri) => ({ contents: [] }));
}`, "wiki://guide", "Onboarding guide", true, true},
		{"URI template constant", `
const NOTE_URI = "notes://{id}";
function setup(server: McpServer): void {
  server.registerResource("note", NOTE_URI, { description: "One note" }, read);
}`, "notes://{id}", "One note", true, false},
		{"no metadata", `
function setup(server: McpServer): void {
  server.resource("notes", "notes://{name}", readNotes);
}`, "notes://{name}", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := buildGraph(t, map[language.ID]map[string]string{language.TypeScript: {"server.ts": tc.src}})
			Discover(g)
			if len(g.Capabilities) != 1 || g.Capabilities[0].Kind != graph.CapabilityResource {
				t.Fatalf("want one resource, got %+v", g.Capabilities)
			}
			c := g.Capabilities[0]
			if c.URI != tc.uri || c.URIFixed != tc.isFixed {
				t.Errorf("uri %q fixed %v, want %q fixed %v", c.URI, c.URIFixed, tc.uri, tc.isFixed)
			}
			if c.Description != tc.desc || c.DescriptionResolved != tc.descResolved {
				t.Errorf("description %q (resolved %v), want %q (resolved %v)", c.Description, c.DescriptionResolved, tc.desc, tc.descResolved)
			}
		})
	}
}

// The URI comes only from a place that holds one; text in the handler's body or the literal
// prefix of a concatenation is not it
func TestDiscover_ResourceURIOnlyFromItsOwnPlace(t *testing.T) {
	for _, tc := range []struct {
		name string
		lang language.ID
		file string
		src  string
		uri  string
	}{
		{"Go descriptor, URI constant from another file, URL in the handler", language.Go, "ui.go", `package github

func Register(s *mcp.Server) {
	s.AddResource(&mcp.Resource{URI: GetMeUIResourceURI, Name: "get_me_ui", Description: "UI"},
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Meta: mcp.Meta{"csp": []string{"https://avatars.example.com"}}}, nil
		})
}
`, ""},
		{"Go descriptor, URI literal", language.Go, "ui.go", `package github

func Register(s *mcp.Server) {
	s.AddResource(&mcp.Resource{Name: "get_me_ui", URI: "ui://get_me/app.html"}, readUI)
}
`, "ui://get_me/app.html"},
		{"Go descriptor, URI constant in this file", language.Go, "ui.go", `package github

const appURI = "ui://get_me/app.html"

func Register(s *mcp.Server) {
	s.AddResource(&mcp.Resource{URI: appURI, Name: "get_me_ui"}, readUI)
}
`, "ui://get_me/app.html"},
		{"Go descriptor, URI built by concatenation", language.Go, "ui.go", `package slack

func Register(s *mcp.Server, ws string) {
	s.AddResource(&mcp.Resource{URI: "slack://" + ws + "/channels", Name: "channels"}, readChannels)
}
`, ""},
		{"TypeScript URI from configuration, URL in the handler", language.TypeScript, "index.ts", `
function setup(server: McpServer): void {
  server.resource("graphql-schema", new URL(env.ENDPOINT).href, async (uri) => {
    const r = await fetch("http://localhost:4000/graphql");
    return { contents: [{ uri: uri.href, text: await r.text() }] };
  });
}
`, ""},
		{"TypeScript ResourceTemplate", language.TypeScript, "unread.ts", `
function setup(server: McpServer): void {
  server.registerResource("unread", new ResourceTemplate("email://{account}/unread", { list: undefined }), { description: "Unread counts" }, read);
}
`, "email://{account}/unread"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := buildGraph(t, map[language.ID]map[string]string{tc.lang: {tc.file: tc.src}})
			Discover(g)
			var uris []string
			for _, c := range g.Capabilities {
				if c.Kind == graph.CapabilityResource {
					uris = append(uris, c.URI)
				}
			}
			if len(uris) != 1 || uris[0] != tc.uri {
				t.Fatalf("resource URIs %q, want [%q] (capabilities %+v)", uris, tc.uri, g.Capabilities)
			}
		})
	}
}

// A Python decorator passes the URI by keyword as often as by position
func TestDiscover_PythonResourceURIByKeyword(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{language.Python: {"server.py": `
@mcp.resource(uri="docs://guide", description="The guide")
def guide():
    return "hello"
`}})
	Discover(g)
	if len(g.Capabilities) != 1 || g.Capabilities[0].URI != "docs://guide" {
		t.Fatalf("got %+v, want one resource with URI docs://guide", g.Capabilities)
	}
}
