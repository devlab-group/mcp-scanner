package snapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/pkg/model"
)

func sample() *model.Snapshot {
	return &model.Snapshot{
		SchemaVersion: model.SchemaVersion,
		ServerName:    "acme-tools",
		ServerVersion: "1.0.0",
		Capabilities:  map[string]any{"tools": map[string]any{"listChanged": true}},
		Tools: []model.ToolInfo{
			{Name: "read_file", Description: "reads a file", InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string"},
				},
				"required": []any{"path"},
			}},
			{Name: "search", Description: "searches", InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"query": map[string]any{"type": "string"}},
			}},
		},
	}
}

func TestHashStableUnderKeyAndSliceReordering(t *testing.T) {
	a := sample()
	b := sample()
	// Reorder the tool list and rebuild the schema map with different
	// insertion order; neither should move the hash
	b.Tools[0], b.Tools[1] = b.Tools[1], b.Tools[0]
	b.Tools[1].InputSchema = map[string]any{
		"required":   []any{"path"},
		"type":       "object",
		"properties": map[string]any{"path": map[string]any{"type": "string"}},
	}

	ha, err := Hash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := Hash(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("hash changed under reordering: %s != %s", ha, hb)
	}
}

func TestHashChangesOnSemanticSchemaChange(t *testing.T) {
	a := sample()
	b := sample()
	b.Tools[0].InputSchema["required"] = []any{} // "path" is no longer required

	ha, _ := Hash(a)
	hb, _ := Hash(b)
	if ha == hb {
		t.Fatal("hash did not change when a required argument became optional")
	}
}

func TestWriteSanitizesToolName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	s := sample()
	s.Tools[0].Name = "invoice‮gnp.exe"
	writeFile(t, path, s)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(string(data), '‮') {
		t.Fatalf("bidi override character reached the saved file raw: %q", data)
	}
	if !strings.Contains(string(data), `\u202e`) {
		t.Fatalf("expected the bidi override escaped as \\u202e, got %q", data)
	}
}

func writeFile(t *testing.T, path string, s *model.Snapshot) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Write(f, s); err != nil {
		t.Fatal(err)
	}
}
