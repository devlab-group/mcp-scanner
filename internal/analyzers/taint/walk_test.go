package taint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/internal/source/language"
)

func TestFileFor_CapsReadAtGraphMaxBytes(t *testing.T) {
	dir := t.TempDir()
	const capBytes = 4096
	const realSize = capBytes * 8

	var b strings.Builder
	b.WriteString("function helperRun(cmd) { return cmd; }\n")
	for b.Len() < realSize {
		b.WriteString("// padding padding padding padding padding\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "big.js"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	g := graph.New(dir)
	g.Files["big.js"] = &graph.File{Path: "big.js", Language: string(language.JavaScript), MaxBytes: capBytes}

	c := newCtx(context.Background(), g)
	defer c.closeAll()

	pf := c.fileFor("big.js")
	if pf == nil {
		t.Fatal("fileFor returned nil for a file well within ParseTimeout")
	}
	if len(pf.src) != capBytes {
		t.Fatalf("want the read capped at graph.File.MaxBytes (%d bytes), got %d", capBytes, len(pf.src))
	}
	if c.sizeCapped != 1 || c.sizeCap != capBytes {
		t.Fatalf("want the cap hit recorded on ctx for taintCoverage to report, got sizeCapped=%d sizeCap=%d", c.sizeCapped, c.sizeCap)
	}
}

func TestFileFor_UncappedFileReadsInFull(t *testing.T) {
	dir := t.TempDir()
	src := "function helperRun(cmd) { return cmd; }\n"
	if err := os.WriteFile(filepath.Join(dir, "small.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	g := graph.New(dir)
	g.Files["small.js"] = &graph.File{Path: "small.js", Language: string(language.JavaScript)}

	c := newCtx(context.Background(), g)
	defer c.closeAll()

	pf := c.fileFor("small.js")
	if pf == nil {
		t.Fatal("fileFor returned nil for a small, well-formed file")
	}
	if len(pf.src) != len(src) {
		t.Fatalf("want the whole file read (%d bytes), got %d", len(src), len(pf.src))
	}
	if c.sizeCapped != 0 {
		t.Fatalf("want no cap recorded for a file under the limit, got sizeCapped=%d", c.sizeCapped)
	}
}

func TestFileFor_UnreadableFileIsCounted(t *testing.T) {
	dir := t.TempDir()
	g := graph.New(dir)
	// Recorded in the graph as parsed by the walk, and gone by the time
	// taint reopens it
	g.Files["vanished.js"] = &graph.File{Path: "vanished.js", Language: string(language.JavaScript)}
	// A language no adapter in this build claims
	g.Files["notes.txt"] = &graph.File{Path: "notes.txt", Language: "cobol"}

	c := newCtx(context.Background(), g)
	defer c.closeAll()

	for _, path := range []string{"vanished.js", "notes.txt", "never-in-the-graph.js"} {
		if pf := c.fileFor(path); pf != nil {
			t.Fatalf("%s: want no parsed file", path)
		}
	}
	if c.unreadable != 3 {
		t.Fatalf("want all three branches counted, got unreadable=%d", c.unreadable)
	}
	// The cached nil must not be counted a second time
	c.fileFor("vanished.js")
	if c.unreadable != 3 {
		t.Fatalf("want a cached failure counted once, got unreadable=%d", c.unreadable)
	}

	cov := taintCoverage(g, c)
	if cov.CapabilitiesSkipped != 0 {
		t.Fatalf("a file that could not be read is not a skip, got CapabilitiesSkipped=%d", cov.CapabilitiesSkipped)
	}
	found := false
	for _, l := range cov.LimitsHit {
		if strings.Contains(l, "could not be re-read or re-parsed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want the unreadable files reported as a limit, got LimitsHit=%+v", cov.LimitsHit)
	}
	if len(cov.Gaps()) == 0 {
		t.Fatal("want Coverage.Gaps() to report the limit, got none")
	}
}

func TestFileFor_SizeCapKeepsTheLargest(t *testing.T) {
	dir := t.TempDir()
	src := strings.Repeat("// padding\n", 4096)
	for _, name := range []string{"a.js", "b.js"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g := graph.New(dir)
	g.Files["a.js"] = &graph.File{Path: "a.js", Language: string(language.JavaScript), MaxBytes: 8192}
	g.Files["b.js"] = &graph.File{Path: "b.js", Language: string(language.JavaScript), MaxBytes: 2048}

	c := newCtx(context.Background(), g)
	defer c.closeAll()
	c.fileFor("a.js")
	c.fileFor("b.js")

	if c.sizeCapped != 2 || c.sizeCap != 8192 {
		t.Fatalf("want both files counted and the largest cap kept, got sizeCapped=%d sizeCap=%d", c.sizeCapped, c.sizeCap)
	}
}

func TestFileAliases_ConflictingBindingIsNotASink(t *testing.T) {
	dir := t.TempDir()
	src := `const { execSync } = require("node:child_process");
let run = execSync;
run = (cmd) => cmd.length;
const shell = execSync;
const label = "execSync";
`
	if err := os.WriteFile(filepath.Join(dir, "server.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	g := graph.New(dir)
	g.Files["server.js"] = &graph.File{Path: "server.js", Language: string(language.JavaScript)}

	c := newCtx(context.Background(), g)
	defer c.closeAll()
	if pf := c.fileFor("server.js"); pf == nil {
		t.Fatal("fileFor returned nil for a well-formed file")
	}

	if got, ok := c.aliases[fileAlias{file: "server.js", name: "shell"}]; !ok || got != "execSync" {
		t.Fatalf("want shell recorded as an alias of execSync, got %q (present=%v)", got, ok)
	}
	for _, name := range []string{"run", "label"} {
		if got, ok := c.aliases[fileAlias{file: "server.js", name: name}]; ok {
			t.Fatalf("want %s left out of the alias table, got %q", name, got)
		}
	}
	// The table is scoped to the file that bound the name
	if _, ok := c.aliases[fileAlias{file: "other.js", name: "shell"}]; ok {
		t.Fatal("want the alias confined to the file that declared it")
	}
}

func TestAliasedSinkText_InRepoCalleeWins(t *testing.T) {
	g := graph.New("")
	g.Symbols["helpers.js:run:3"] = &graph.Symbol{
		ID: "helpers.js:run:3", Kind: graph.KindFunction, Name: "run",
		File: "helpers.js", Line: 3, EndLine: 5, Params: []string{"cmd"},
	}
	c := newCtx(context.Background(), g)
	defer c.closeAll()
	c.aliases[fileAlias{file: "server.js", name: "run"}] = "execSync"
	c.aliases[fileAlias{file: "server.js", name: "shell"}] = "execSync"

	if _, ok := c.aliasedSinkText("server.js", "run"); ok {
		t.Fatal("want the in-repo run() followed, not resolved to a sink")
	}
	if got, ok := c.aliasedSinkText("server.js", "shell"); !ok || got != "execSync" {
		t.Fatalf("want shell still resolved to execSync, got %q (ok=%v)", got, ok)
	}
}
