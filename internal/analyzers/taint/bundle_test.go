package taint

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// esbuildBundle is a bundle in esbuild's shape: helpers, then node_modules modules each under its
// path comment, the MCP SDK among them when withSDK, until filler bytes are written, then own
func esbuildBundle(own string, filler int, withSDK bool) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env node\nvar __defProp = Object.defineProperty;\n")
	if withSDK {
		b.WriteString("\n// node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js\nvar McpServer = class {\n  tool(name, description, cb) {\n    this.tools[name] = cb;\n  }\n};\n")
	}
	for i := 0; b.Len() < filler; i++ {
		fmt.Fprintf(&b, "\n// node_modules/list-utils/dist/part%d.js\nfunction pick%d(items, n) {\n  return items.slice(0, n).map((x) => String(x).trim());\n}\n", i, i)
	}
	b.WriteString(own)
	return b.String()
}

func lineOf(t *testing.T, src, text string) int {
	t.Helper()
	i := strings.Index(src, text)
	if i < 0 {
		t.Fatalf("%q not in source", text)
	}
	return strings.Count(src[:i], "\n") + 1
}

const bundledNotesServer = `
// src/index.ts
import { readFile } from "fs/promises";
import path from "path";
var server = new McpServer({ name: "notes", version: "1.0.0" });
server.tool("read_note", "Read one of your saved notes by its name.", async ({ name }) => {
  const text = await readFile(path.join("/home/u/.notes", name), "utf8");
  return { content: [{ type: "text", text }] };
});
`

// A published package that is one esbuild bundle: the server's own module comes after more than
// the per-file size limit of its dependencies. Its node_modules modules are blanked, so the whole
// own module is read and the finding points at the bundle's real line.
func TestBundleOwnCodePastSizeLimit(t *testing.T) {
	src := esbuildBundle(bundledNotesServer, 600<<10, true)
	res := analyze(t, mustWriteDir(t, map[string]string{"index.js": src}))
	want := lineOf(t, src, "const text = await readFile")
	found := false
	for _, f := range categoryFindings(res, "path_traversal") {
		if f.Line == want && f.Triage != model.TriageNeedsReview {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a path_traversal finding at line %d of the bundle, got %+v", want, categoryFindings(res, "path_traversal"))
	}
}

// Without the blanking the same tree has no finding: the own module is past what is read
func TestBundleBlankingIsWhatFindsIt(t *testing.T) {
	src := esbuildBundle(bundledNotesServer, 600<<10, true)
	// a comment that is not esbuild's module marker leaves the file an ordinary oversized file
	src = strings.ReplaceAll(src, "\n// node_modules/", "\n// see node_modules/")
	res := analyze(t, mustWriteDir(t, map[string]string{"index.js": src}))
	if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
		t.Fatalf("not a bundle: want the own module unread and no finding, got %+v", got)
	}
}

// A bundle has no import of the SDK it inlined: the SDK's module markers count as one, so a
// registration on a receiver whose name says nothing about a server is still found
func TestBundledSDKCountsAsImport(t *testing.T) {
	own := strings.ReplaceAll(bundledNotesServer, "server", "s")
	for _, withSDK := range []bool{true, false} {
		src := esbuildBundle(own, 600<<10, withSDK)
		res := analyze(t, mustWriteDir(t, map[string]string{"index.js": src}))
		got := len(categoryFindings(res, "path_traversal")) > 0
		if got != withSDK {
			t.Errorf("SDK bundled %v: finding %v, want %v", withSDK, got, withSDK)
		}
	}
}

// When the own modules alone are over the limit the file is read only up to it, as before
func TestBundleOwnCodeOverLimitIsTruncated(t *testing.T) {
	big := "\n// src/table.ts\n" + strings.Repeat("var row = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];\n", (600<<10)/44)
	src := esbuildBundle(big+bundledNotesServer, 100<<10, true)
	res := analyze(t, mustWriteDir(t, map[string]string{"index.js": src}))
	if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
		t.Fatalf("own code over the limit: want the file truncated and no finding, got %+v", got)
	}
}
