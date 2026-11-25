package dossier

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A cloned repository can keep README.md and package.json as links to any file on the scanning
// machine. The dossier prints the README and the manifests, so following the links would copy
// that file into the output
func TestBuild_DoesNotFollowLinksOutOfTheTree(t *testing.T) {
	base := t.TempDir()
	root, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(outside, "credentials"):  "[default]\naws_secret_access_key = OUTSIDE-SECRET\n",
		filepath.Join(outside, "package.json"): `{"name": "outside-manifest", "version": "9.9.9"}`,
		filepath.Join(root, "server.py"): `from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def ping() -> str:
    """Answers pong"""
    return "pong"
`,
	}
	for p, text := range files {
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for at, target := range map[string]string{
		"README.md":    filepath.Join("..", "outside", "credentials"),
		"package.json": filepath.Join(outside, "package.json"),
	} {
		if err := os.Symlink(target, filepath.Join(root, at)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}

	d, err := Build(context.Background(), root, "test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.Repository.Readme, "OUTSIDE-SECRET") || d.Repository.Readme != "" {
		t.Errorf("readme = %q, want empty: README.md links out of the tree", d.Repository.Readme)
	}
	for _, m := range d.Repository.Manifests {
		if m.Name == "outside-manifest" {
			t.Errorf("manifest read through a link out of the tree: %+v", m)
		}
	}
}

// A link that stays inside the tree is an ordinary way to share a README between packages and is
// still read
func TestBuild_FollowsLinksInsideTheTree(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "intro.md"), []byte("# Demo server\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("docs", "intro.md"), filepath.Join(root, "README.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	d, err := Build(context.Background(), root, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Repository.Readme, "Demo server") {
		t.Errorf("readme = %q, want the linked file inside the tree", d.Repository.Readme)
	}
}

// Every file the dossier reads by name - the README, each kind of manifest, a source file - is a
// link to one file outside the tree: not a byte of it may reach the output
func TestBuild_NoByteOfAnOutsideFileReachesTheOutput(t *testing.T) {
	base := t.TempDir()
	root, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "pkg"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const marker = "OUTSIDE-MARKER-7f3a"
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte(`{"name": "`+marker+`", "version": "`+marker+`"}`+"\nname = \""+marker+"\"\nmodule "+marker+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "server.py"), []byte("from mcp.server.fastmcp import FastMCP\nmcp = FastMCP(\"demo\")\n\n@mcp.tool()\ndef ping() -> str:\n    \"\"\"Answers pong\"\"\"\n    return \"pong\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"README.md", "package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml", "pom.xml", "pkg/package.json", "pkg/helper.py", "pkg/index.ts"} {
		if err := os.Symlink(secret, filepath.Join(root, filepath.FromSlash(name))); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	d, err := Build(context.Background(), root, "test")
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), marker) {
		t.Fatalf("the dossier carries bytes of a file outside the tree:\n%s", out)
	}
}
