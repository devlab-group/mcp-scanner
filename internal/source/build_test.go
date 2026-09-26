package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuild_SyntaxErrorDowngradesCoverage(t *testing.T) {
	dir := t.TempDir()
	// Register a tool so an unrelated no-registration limit cannot satisfy this test
	broken := "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP(\"ops\")\n\n\n" +
		"@mcp.tool()\ndef handler(name: str) -> str:\n    \"\"\"Echoes a name.\"\"\"\n    return name\n\n\n" +
		"def helper(name):\n    x = f\"unterminated {name\n    return x\n"
	if err := os.WriteFile(filepath.Join(dir, "broken.py"), []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}

	_, cov, err := Build(context.Background(), dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cov.FilesParsed != 1 {
		t.Errorf("want the file still counted as parsed, got FilesParsed=%d", cov.FilesParsed)
	}
	if cov.FilesFailed != 0 {
		t.Errorf("want no parse failure recorded - the grammar did produce a tree, got FilesFailed=%d", cov.FilesFailed)
	}
	if !hasSubstring(cov.LimitsHit, "only partly parsed") {
		t.Fatalf("want a LimitsHit entry for the partly parsed file, got %v", cov.LimitsHit)
	}
	if gaps := cov.Gaps(); len(gaps) == 0 {
		t.Error("want Coverage.Gaps() to report the partial parse as a gap, got none")
	}
}

func TestBuild_CleanFileNoGap(t *testing.T) {
	_, cov, err := Build(context.Background(), "../../testdata/source/discovery/go")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cov.FilesParsed == 0 {
		t.Fatalf("want at least one file counted as parsed, got FilesParsed=%d", cov.FilesParsed)
	}
	if cov.CapabilitiesDiscovered == 0 {
		t.Fatal("fixture is expected to resolve at least one MCP capability")
	}
	if len(cov.LimitsHit) != 0 {
		t.Errorf("want no LimitsHit entry for a tree with resolved MCP registrations, got %v", cov.LimitsHit)
	}
}

// A clean parse with zero recognized registrations is not proof that no MCP surface exists.
// Report a gap so an unsupported registration form cannot produce a clean empty scan.
func TestBuild_NoRegistrationIsAGap(t *testing.T) {
	dir := t.TempDir()
	clean := "def handler(name):\n    return name\n"
	if err := os.WriteFile(filepath.Join(dir, "clean.py"), []byte(clean), 0o644); err != nil {
		t.Fatal(err)
	}

	_, cov, err := Build(context.Background(), dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cov.FilesParsed != 1 {
		t.Errorf("want the file counted as parsed, got FilesParsed=%d", cov.FilesParsed)
	}
	if cov.CapabilitiesDiscovered != 0 {
		t.Fatalf("fixture is expected to resolve no MCP capability, got %d", cov.CapabilitiesDiscovered)
	}
	if len(cov.LimitsHit) == 0 {
		t.Fatal("want a LimitsHit entry for zero resolved registrations, got none")
	}
	if gaps := cov.Gaps(); len(gaps) == 0 {
		t.Error("want Coverage.Gaps() to report the zero-registration tree as a gap, got none")
	}
}

func TestBuild_NoRegistrationSharpensWithKnownImport(t *testing.T) {
	dir := t.TempDir()
	src := "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n" +
		"def handler(name):\n    return name\n"
	if err := os.WriteFile(filepath.Join(dir, "server.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	_, cov, err := Build(context.Background(), dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cov.CapabilitiesDiscovered != 0 {
		t.Fatalf("fixture is expected to resolve no MCP capability, got %d", cov.CapabilitiesDiscovered)
	}
	if len(cov.LimitsHit) == 0 {
		t.Fatal("want a LimitsHit entry for zero resolved registrations, got none")
	}
	if !strings.Contains(cov.LimitsHit[0], "MCP SDK import was found") {
		t.Errorf("want the reason to name the known MCP SDK import, got %q", cov.LimitsHit[0])
	}
	if cov.Complete() {
		t.Error("want a tree with a recognized MCP SDK import and no resolved registration to stay incomplete")
	}
}

func TestBuild_SymlinkAndFileCountersBalance(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "handler.py"), []byte("def handler(name):\n    return name\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}

	_, cov, err := Build(context.Background(), dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cov.FilesParsed != 1 {
		t.Fatalf("want the real file parsed, got FilesParsed=%d", cov.FilesParsed)
	}
	if cov.FilesDiscovered != 2 {
		t.Fatalf("want the symlink counted alongside the real file in FilesDiscovered, got %d", cov.FilesDiscovered)
	}
	if cov.FilesSkipped != 1 {
		t.Fatalf("want exactly the symlink counted as skipped, got %d", cov.FilesSkipped)
	}
	if unaccounted := cov.FilesDiscovered - cov.FilesParsed - cov.FilesFailed - cov.FilesSkipped; unaccounted != 0 {
		t.Fatalf("counters must balance exactly, got discovered=%d parsed=%d failed=%d skipped=%d (unaccounted=%d)",
			cov.FilesDiscovered, cov.FilesParsed, cov.FilesFailed, cov.FilesSkipped, unaccounted)
	}
	for _, g := range cov.Gaps() {
		if strings.Contains(g, "never accounted for") {
			t.Errorf("want no spurious unaccounted-file gap, got %q", g)
		}
	}
}

func hasSubstring(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
