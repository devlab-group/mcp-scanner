package dossier

import (
	"context"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

func hintsByCode(hs []Hint) map[string][]Hint {
	out := map[string][]Hint{}
	for _, h := range hs {
		out[h.Code] = append(out[h.Code], h)
	}
	return out
}

// Each hint carries the question and the way to check it, so a later reviewer can act on it alone
func TestHints_RecordWhatStaticAnalysisLeavesOpen(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"server.py": `import boto3
from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs")
ROOT = Path("/srv/docs")
table = boto3.resource("dynamodb", region_name="eu-west-1")

def validate_name(name):
    return name

@mcp.resource("docs://files/{path*}")
def doc(path: str) -> str:
    """Returns one document."""
    return (ROOT / validate_name(path)).read_text()

@mcp.resource("docs://index")
def index() -> str:
    """Lists documents."""
    return "index"
`,
		"Tool.cs": `class Tool {}`,
	})
	d, err := Build(context.Background(), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	by := hintsByCode(d.ReviewHints)
	tmpl := by["resource_template_parameter"]
	if len(tmpl) != 1 || tmpl[0].Strength != strengthLead || tmpl[0].Capability != "doc" {
		t.Fatalf("want one lead for the wildcard template that reads files, got %+v", tmpl)
	}
	if v := by["project_validator"]; len(v) != 1 || v[0].Capability != "doc" {
		t.Fatalf("want the project's validator named, got %+v", v)
	}
	if s := by["registration_skipped"]; len(s) != 1 {
		t.Fatalf("want boto3.resource recorded as a skipped registration, got %+v", s)
	}
	if u := by["unsupported_language_files"]; len(u) != 1 {
		t.Fatalf("want the C# file recorded, got %+v", u)
	}
	for _, h := range d.ReviewHints {
		if h.Observed == "" || h.Undecided == "" || h.Question == "" || h.HowToCheck == "" || h.Strength == "" {
			t.Fatalf("hint missing a field: %+v", h)
		}
	}
	for _, c := range d.Capabilities {
		if c.Kind == "resource" && c.URI == "" {
			t.Fatalf("resource URI not recorded: %+v", c)
		}
	}
}

// The pair: a plain server with fixed resources and no file or network access gets no leads
func TestHints_QuietServerHasNoLeads(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"server.py": `from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clock")

@mcp.tool()
def add(a: int, b: int) -> int:
    """Adds two numbers."""
    return a + b
`,
	})
	d, err := Build(context.Background(), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if d.ReviewHints == nil {
		t.Fatal("review_hints must serialize as [], not null")
	}
	for _, h := range d.ReviewHints {
		if h.Strength == strengthLead {
			t.Fatalf("unexpected lead: %+v", h)
		}
	}
}

// A JSON-RPC dispatcher written without an SDK registers nothing the scanner can see; the hint says
// where it is
func TestHints_HandRolledProtocol(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"src/main.rs": `fn handle(method: &str) {
    match method {
        "tools/list" => list(),
        "tools/call" => call(),
        _ => {}
    }
}
fn list() {}
fn call() {}
`,
	})
	d, err := Build(context.Background(), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if h := hintsByCode(d.ReviewHints)["hand_rolled_protocol"]; len(h) != 1 || h[0].File != "src/main.rs" {
		t.Fatalf("want a hand_rolled_protocol hint on src/main.rs, got %+v", d.ReviewHints)
	}
}
