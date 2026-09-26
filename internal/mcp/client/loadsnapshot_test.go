package client

import (
	"os"
	"path/filepath"
	"testing"

	internalsnapshot "github.com/revinand/mcp-scanner/internal/mcp/snapshot"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func TestLoadSnapshotOwnFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	orig := &model.Snapshot{
		SchemaVersion: model.SchemaVersion,
		ServerName:    "acme",
		Tools:         []model.ToolInfo{{Name: "search", Description: "search things"}},
	}
	writeSnapshot(t, path, orig)

	got, err := loadSnapshotFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerName != "acme" || len(got.Tools) != 1 {
		t.Fatalf("got %+v", got)
	}
}

const plainDocJSON = `{
  "serverInfo": {"name": "plain-doc", "version": "2.0.0"},
  "protocolVersion": "2025-06-18",
  "instructions": "be careful",
  "capabilities": {"tools": {}},
  "tools": [
    {
      "name": "run",
      "description": "runs a command",
      "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
      "annotations": {"readOnlyHint": false}
    }
  ],
  "prompts": [{"name": "greet", "description": "greets"}],
  "resources": [{"uri": "file:///tmp/x", "name": "x"}]
}`

func TestLoadSnapshotPlainMCPDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "doc.json")
	if err := os.WriteFile(path, []byte(plainDocJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadSnapshotFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerName != "plain-doc" {
		t.Fatalf("server name = %q", got.ServerName)
	}
	if len(got.Tools) != 1 || got.Tools[0].Name != "run" {
		t.Fatalf("tools = %+v", got.Tools)
	}
	if got.Tools[0].InputSchema["type"] != "object" {
		t.Fatalf("input schema not converted: %+v", got.Tools[0].InputSchema)
	}
	if len(got.Prompts) != 1 || len(got.Resources) != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestLoadSnapshotRejectsUnrecognizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "junk.json")
	if err := os.WriteFile(path, []byte(`{"hello":"world"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSnapshotFile(t, path); err == nil {
		t.Fatal("an unrecognized JSON document was accepted as a snapshot")
	}
}

func writeSnapshot(t *testing.T, path string, s *model.Snapshot) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := internalsnapshot.Write(f, s); err != nil {
		t.Fatal(err)
	}
}

func TestWriteThenLoadPreservesTheSnapshotHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	orig := &model.Snapshot{
		SchemaVersion: model.SchemaVersion,
		ServerName:    "acme",
		Instructions:  "be careful",
		Tools: []model.ToolInfo{{
			Name:        "run",
			Description: "runs a command",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"command": map[string]any{"type": "string"}},
				"required":   []any{"command"},
			},
		}},
		Prompts:   []model.PromptInfo{{Name: "greet", Description: "greets"}},
		Resources: []model.ResourceInfo{{URI: "file:///tmp/x", Name: "x"}},
	}
	writeSnapshot(t, path, orig)

	loaded, err := loadSnapshotFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := internalsnapshot.Hash(orig)
	after, _ := internalsnapshot.Hash(loaded)
	if before != after {
		t.Fatalf("the snapshot changed across a save and a load: %s != %s", before, after)
	}
}

func loadSnapshotFile(t *testing.T, path string) (*model.Snapshot, error) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadSnapshotBytes(data, path)
}

// Keep resource templates and prompt arguments from plain MCP documents in the scan surface
func TestLoadSnapshotPlainDocumentKeepsTemplatesAndPromptArguments(t *testing.T) {
	doc := `{
  "tools": [{"name": "run", "description": "Runs a job", "inputSchema": {"type": "object"}}],
  "prompts": [{"name": "summarize", "description": "Summarizes", "arguments": [{"name": "topic", "description": "What to summarize", "required": true}]}],
  "resourceTemplates": [{"uriTemplate": "notes://{day}", "name": "notes", "description": "Notes by day"}]
}`
	got, err := LoadSnapshotBytes([]byte(doc), "doc.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Templates) != 1 || got.Templates[0].URITemplate != "notes://{day}" || got.Templates[0].Description != "Notes by day" {
		t.Fatalf("templates = %+v", got.Templates)
	}
	if len(got.Prompts) != 1 || len(got.Prompts[0].Arguments) != 1 {
		t.Fatalf("prompts = %+v", got.Prompts)
	}
	if a := got.Prompts[0].Arguments[0]; a.Name != "topic" || a.Description != "What to summarize" || !a.Required {
		t.Fatalf("argument = %+v", a)
	}
}

// Refuse a malformed versioned snapshot instead of returning its partially decoded lists
func TestLoadSnapshotRefusesAVersionedSnapshotThatDoesNotDecode(t *testing.T) {
	data := `{"schema_version": "1.0.0", "tools": [{"name": "t", "description": "d"}], "prompts": "not a list"}`
	if got, err := LoadSnapshotBytes([]byte(data), "snap.json"); err == nil {
		t.Fatalf("a snapshot with a malformed prompts field loaded: %+v", got)
	}
}
