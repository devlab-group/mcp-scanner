package taint

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func findingsByLine(res model.AnalyzerResult, category string) map[int]model.Finding {
	out := map[int]model.Finding{}
	for _, f := range categoryFindings(res, category) {
		out[f.Line] = f
	}
	return out
}

// A temp file named around randomUUID() beside the caller's output path can only be the file the
// server creates for this call: removing it is no finding, writing it goes to review. The caller's
// own path (rename's target) and every variant where the caller's text stays in the name do not
// change.
func TestFreshTempNameBesideOutput(t *testing.T) {
	const src = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { open, rename, unlink } from "node:fs/promises";
import * as path from "node:path";

const server = new McpServer({ name: "x", version: "1.0.0" });
server.tool("download", "Download a file to a local path.", { output: z.string() }, async ({ output }) => {
  const target = path.resolve(output);
  const temp = path.join(path.dirname(target), "." + path.basename(target) + "." + randomUUID() + ".tmp");
  const file = await open(temp, "wx");
  await file.close();
  await unlink(temp);
  await rename(temp, target);
  return { content: [{ type: "text", text: "ok" }] };
});
server.tool("convert", "Convert a picture.", { input: z.string(), ext: z.string() }, async ({ input, ext }) => {
  const temp = path.join(path.dirname(input), "." + randomUUID() + "." + ext);
  await unlink(temp);
  return { content: [{ type: "text", text: "ok" }] };
});
server.tool("unsafe_base", "Convert a picture.", { input: z.string() }, async ({ input }) => {
  const temp = path.join(path.dirname(input), input + randomUUID());
  await unlink(temp);
  return { content: [{ type: "text", text: "ok" }] };
});
server.tool("random_dir", "Render a page.", { name: z.string() }, async ({ name }) => {
  const temp = path.join("/tmp", randomUUID() + "/" + name);
  await unlink(temp);
  return { content: [{ type: "text", text: "ok" }] };
});
server.tool("either", "Convert a picture.", { input: z.string(), keep: z.boolean() }, async ({ input, keep }) => {
  const temp = path.join(path.dirname(input), "." + randomUUID() + ".tmp");
  const victim = keep ? temp : input;
  await unlink(victim);
  return { content: [{ type: "text", text: "ok" }] };
});
server.tool("suffix", "Convert a picture.", { input: z.string() }, async ({ input }) => {
  const temp = path.join(path.dirname(input), "." + randomUUID() + ".tmp");
  await unlink(temp + input);
  return { content: [{ type: "text", text: "ok" }] };
});
server.tool("inline", "Convert a picture.", { input: z.string() }, async ({ input }) => {
  await unlink(path.join(path.dirname(input), "." + path.basename(input) + randomUUID()));
  return { content: [{ type: "text", text: "ok" }] };
});
server.tool("appended", "Convert a picture.", { input: z.string() }, async ({ input }) => {
  let temp = path.join(path.dirname(input), "." + randomUUID() + ".tmp");
  temp += "/..";
  await unlink(temp);
  return { content: [{ type: "text", text: "ok" }] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	got := findingsByLine(res, "path_traversal")
	if f, ok := got[13]; ok {
		t.Errorf("unlink(temp) of the server's own random temp file: want no finding, got %+v", f)
	}
	if f, ok := got[11]; !ok || f.Triage != model.TriageNeedsReview {
		t.Errorf("open(temp, \"wx\"): want needs_review, got %+v (present %v)", f, ok)
	}
	if _, ok := got[14]; !ok {
		t.Errorf("rename(temp, target) also names the caller's path: want a finding")
	}
	for line, what := range map[int]string{
		19: "the caller's extension after the random part",
		24: "the caller's raw value in the name",
		29: "a random directory with the caller's name under it",
		35: "a value that is either the temp file or the caller's path",
		40: "the caller's text appended at the sink",
	} {
		if f, ok := got[line]; !ok || f.Triage == model.TriageNeedsReview {
			t.Errorf("line %d (%s): want a finding outside review, got %+v (present %v)", line, what, f, ok)
		}
	}
	if f, ok := got[44]; ok {
		t.Errorf("unlink of an inline join with a fresh last component: want no finding, got %+v", f)
	}
	if _, ok := got[50]; !ok {
		t.Errorf("temp += \"/..\" names the caller's directory: want a finding")
	}
}

// The same class in Python: os.path.join with an f-string around uuid4().hex
func TestFreshTempNamePython(t *testing.T) {
	const src = `import os
import uuid

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


@mcp.tool()
def save(out_path: str, suffix: str) -> str:
    """Save an export to a local file."""
    tmp = os.path.join(os.path.dirname(out_path), f".{os.path.basename(out_path)}.{uuid.uuid4().hex}.part")
    os.remove(tmp)
    bad = os.path.join(os.path.dirname(out_path), f".{uuid.uuid4().hex}{suffix}")
    os.remove(bad)
    return "ok"
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.py": src}))
	got := findingsByLine(res, "path_traversal")
	if f, ok := got[13]; ok {
		t.Errorf("os.remove(tmp) of the server's own uuid4 temp file: want no finding, got %+v", f)
	}
	if _, ok := got[15]; !ok {
		t.Errorf("os.remove(bad) with the caller's suffix after the random part: want a finding")
	}
}

// A project function named like the library one may return anything
func TestFreshNameNotFromProjectFunction(t *testing.T) {
	const src = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { unlink } from "node:fs/promises";
import * as path from "node:path";

function randomUUID(): string { return process.argv[2]; }

const server = new McpServer({ name: "x", version: "1.0.0" });
server.tool("download", "Download a file.", { output: z.string() }, async ({ output }) => {
  const temp = path.join(path.dirname(output), "." + randomUUID() + ".tmp");
  await unlink(temp);
  return { content: [{ type: "text", text: "ok" }] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	if _, ok := findingsByLine(res, "path_traversal")[11]; !ok {
		t.Errorf("a project's own randomUUID(): want the finding to stay")
	}
}

func TestFreshComponent(t *testing.T) {
	c := &ctx{idx: map[string][]graph.SymbolID{}}
	tainted := map[string]taintInfo{"out": {confidence: 1}, "ext": {confidence: 1}}
	cases := map[string]bool{
		"`.${path.basename(out)}.${randomUUID()}.tmp`":        true,
		`f".{os.path.basename(out)}.{uuid.uuid4().hex}.part"`: true,
		`"." + crypto.randomBytes(8).toString("hex")`:         true,
		`randomBytes(8).toString("base64")`:                   false,
		`secrets.token_hex(8) + ".json"`:                      true,
		"`${randomUUID()}.${ext}`":                            false,
		"`${out}-${randomUUID()}`":                            false,
		"`${randomUUID()}/${path.basename(out)}`":             false,
		`".tmp"`:              false,
		`Date.now() + ".tmp"`: false,
	}
	for text, want := range cases {
		if _, got := c.freshComponent(text, tainted); got != want {
			t.Errorf("%s: fresh %v, want %v", text, got, want)
		}
	}
}
