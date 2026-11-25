package taint

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
)

// outsideTree makes <tmp>/root (with a tests/ folder and a small Python server) and <tmp>/outside
func outsideTree(t *testing.T) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root, outside = filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "tests"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "server.py"), "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP(\"x\")\n")
	return root, outside
}

func writeFile(t *testing.T, p, text string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, target, at string) {
	t.Helper()
	if err := os.Symlink(target, at); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func buildGraph(t *testing.T, root string) *graph.Graph {
	t.Helper()
	g, _, err := source.Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// A manifest that is a link out of the tree is not read. It is also no evidence that the file
// under tests/ is not started: the rule must not lower the finding on a read it was refused, or
// a hostile tree hides its finding by linking package.json away
func TestLaunchedByManifest_ARefusedManifestKeepsTheFinding(t *testing.T) {
	root, outside := outsideTree(t)
	writeFile(t, filepath.Join(outside, "manifest.json"), `{"name": "outside"}`)
	link(t, filepath.Join("..", "outside", "manifest.json"), filepath.Join(root, "package.json"))
	gi := &guardIndex{root: root, files: map[string][]string{}}
	if !startedBy(gi, "tests/server.py") {
		t.Fatal("a refused manifest was read as 'nothing starts this file'")
	}
	if !gi.refused["package.json"] {
		t.Fatalf("the refused manifest was not recorded: %v", gi.refused)
	}
}

func startedBy(gi *guardIndex, file string) bool {
	strong, _ := gi.launch(file)
	return strong != ""
}

// The tree's own manifests decide as before
func TestLaunchedByManifest_ReadsTheTreesOwnManifests(t *testing.T) {
	root, _ := outsideTree(t)
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "x", "scripts": {"build": "tsc"}}`)
	gi := &guardIndex{root: root, files: map[string][]string{}}
	if startedBy(gi, "tests/server.py") {
		t.Fatal("a manifest that does not name the file was read as starting it")
	}
	writeFile(t, filepath.Join(root, "package.json"), `{"bin": {"x": "tests/server.py"}}`)
	// manifests are read once per scan, and a scan's tree does not change: a new index
	gi = &guardIndex{root: root, files: map[string][]string{}}
	if !startedBy(gi, "tests/server.py") {
		t.Fatal("a manifest of the tree that names the file was not read")
	}
	if len(gi.refused) != 0 {
		t.Fatalf("readable manifests recorded as refused: %v", gi.refused)
	}
}

// templateScreening reads the tree's pins of the Python MCP SDK; a requirements file that links
// out of the tree is not one of them
func TestTemplateScreening_IgnoresALinkOutOfTheTree(t *testing.T) {
	root, outside := outsideTree(t)
	writeFile(t, filepath.Join(outside, "reqs.txt"), "mcp==2.0.0\n")
	link(t, filepath.Join("..", "outside", "reqs.txt"), filepath.Join(root, "requirements.txt"))
	if got := templateScreening(buildGraph(t, root)); got != "" {
		t.Fatalf("templateScreening = %q, want \"\": the only pin is in a file outside the tree", got)
	}
	if err := os.Remove(filepath.Join(root, "requirements.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "requirements.txt"), "mcp==2.0.0\n")
	if got := templateScreening(buildGraph(t, root)); got != "mcp 2.x" {
		t.Fatalf("templateScreening = %q, want \"mcp 2.x\" from the tree's own requirements.txt", got)
	}
}

// An endless device behind a link must not hang the scan
func TestTemplateScreening_DoesNotReadADevice(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero")
	}
	root, _ := outsideTree(t)
	link(t, "/dev/zero", filepath.Join(root, "requirements.txt"))
	if got := templateScreening(buildGraph(t, root)); got != "" {
		t.Fatalf("templateScreening = %q", got)
	}
}

// Python code the walk never took in (a virtualenv) does not switch the screening off, and code
// the graph holds does, as before
func TestTemplateScreening_ReadsOnlyTheGraphsPythonFiles(t *testing.T) {
	root, _ := outsideTree(t)
	writeFile(t, filepath.Join(root, "requirements.txt"), "mcp==2.0.0\n")
	if err := os.MkdirAll(filepath.Join(root, ".venv", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, ".venv", "lib", "other.py"), "resource_security = None\n")
	if got := templateScreening(buildGraph(t, root)); got != "mcp 2.x" {
		t.Fatalf("templateScreening = %q, want \"mcp 2.x\": a virtualenv's code is not the server's", got)
	}
	writeFile(t, filepath.Join(root, "server.py"), "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP(\"x\", resource_security = None)\n")
	if got := templateScreening(buildGraph(t, root)); got != "" {
		t.Fatalf("templateScreening = %q, want \"\": the server switches the screening off", got)
	}
}
