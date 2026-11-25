package dossier

import (
	"context"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

func buildTree(t *testing.T, files map[string]string) *Dossier {
	t.Helper()
	d, err := Build(context.Background(), testutil.WriteTree(t, files), "test")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func byName(d *Dossier) map[string]Capability {
	out := map[string]Capability{}
	for _, c := range d.Capabilities {
		out[c.Name] = c
	}
	return out
}

// What a registration declares and what the code it reaches does, side by side
func TestAnnotationsAgainstCode(t *testing.T) {
	d := buildTree(t, map[string]string{
		"server.ts": `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { writeFileSync } from "node:fs";
import { z } from "zod";
const server = new McpServer({ name: "t", version: "1" });
server.registerTool(
  "read_note",
  { description: "Read a note", inputSchema: { id: z.string() }, annotations: { readOnlyHint: true, openWorldHint: false } },
  async ({ id }) => {
    writeFileSync("/srv/notes/last.txt", id);
    return { content: [{ type: "text", text: id }] };
  },
);
server.tool("list_notes", "List the notes", { id: z.string() }, { readOnlyHint: true }, async ({ id }) => ({ content: [{ type: "text", text: id }] }));
`,
		"main.py": `import os
import requests
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("x")

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def fetch_page(url: str) -> str:
    """Returns the page."""
    return requests.get(url).text

@mcp.tool(description="Deletes the note", annotations={"destructiveHint": False})
def drop(name: str) -> str:
    os.remove(name)
    return "ok"

@mcp.tool()
def plain(kind: str) -> str:
    """Returns the kind."""
    return kind
`,
	})
	c := byName(d)
	n := c["read_note"]
	if !n.Annotations["readOnlyHint"] || n.Annotations["openWorldHint"] {
		t.Fatalf("read_note annotations: %+v", n.Annotations)
	}
	if len(n.AnnotationConflicts) != 1 || !strings.Contains(n.AnnotationConflicts[0], "writeFileSync") {
		t.Fatalf("read_note conflicts: %+v", n.AnnotationConflicts)
	}
	if l := c["list_notes"]; !l.Annotations["readOnlyHint"] || len(l.AnnotationConflicts) != 0 {
		t.Fatalf("list_notes: %+v", l)
	}
	if f := c["fetch_page"]; !f.Annotations["readOnlyHint"] || len(f.AnnotationConflicts) != 0 || f.Effects == nil || f.Effects.ReadsText[0] != "network" {
		t.Fatalf("fetch_page: %+v %+v", f.Annotations, f.Effects)
	}
	dr := c["drop"]
	if dr.Annotations["destructiveHint"] || len(dr.AnnotationConflicts) != 1 {
		t.Fatalf("drop: %+v %+v", dr.Annotations, dr.AnnotationConflicts)
	}
	if p := c["plain"]; p.Annotations != nil || p.Effects != nil {
		t.Fatalf("plain has no hints and no effects: %+v", p)
	}
}

// Private data, outside text and a way out: three lists, set only when all three show
func TestCombination(t *testing.T) {
	d := buildTree(t, map[string]string{"main.py": `import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")

@mcp.tool()
def read_note(name: str) -> str:
    """Reads a note."""
    with open(name) as fh:
        return fh.read()

@mcp.tool()
def page(url: str) -> str:
    """Returns a page."""
    return requests.get(url).text

@mcp.tool()
def share(text: str) -> str:
    """Shares a text."""
    return requests.post("https://share.example.com/x", json={"t": text}).text
`})
	if d.Combination == nil || !d.Combination.All {
		t.Fatalf("all three parts are there: %+v", d.Combination)
	}
	if len(d.Combination.Private) != 1 || len(d.Combination.External) == 0 || len(d.Combination.Outbound) == 0 {
		t.Fatalf("parts: %+v", d.Combination)
	}
	quiet := buildTree(t, map[string]string{"main.py": `from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")

@mcp.tool()
def upper(name: str) -> str:
    """Returns the name in capitals."""
    return name.upper()
`})
	if quiet.Combination != nil {
		t.Fatalf("nothing combined: %+v", quiet.Combination)
	}
}

// Work handed to the server's own backend on this machine is named, not passed over
func TestNotTraced(t *testing.T) {
	d := buildTree(t, map[string]string{"main.py": `import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")
BACKEND = "http://127.0.0.1:8123"

@mcp.tool()
def run_job(name: str) -> str:
    """Runs a job."""
    return requests.post(BACKEND + "/jobs", json={"name": name}).text

@mcp.tool()
def forecast(city: str) -> str:
    """Returns the forecast."""
    return requests.get("https://weather.example.com/v1").text
`})
	c := byName(d)
	if j := c["run_job"]; len(j.NotTraced) != 1 || !strings.Contains(j.NotTraced[0], "127.0.0.1:8123") {
		t.Fatalf("run_job: %+v", j.NotTraced)
	}
	if f := c["forecast"]; len(f.NotTraced) != 0 {
		t.Fatalf("forecast: %+v", f.NotTraced)
	}
}
