package taint

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A complete pattern closes a path only when the check really stands on it: a plain if that
// rejects every mismatch, not inside another branch, on the value the sink reads, with nothing
// reshaping that value after the test. Otherwise the check sends the finding to review, as any
// check the scanner does not verify.
func TestRegexCheckMustStandOnThePath(t *testing.T) {
	js := `import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const BASE = "/srv/notes";
const server = new McpServer({ name: "t", version: "1" });
%s
server.tool("show", "Shows one entry", { name: z.string(), force: z.boolean().optional(), limit: z.number().optional() }, async ({ name, force, limit }) => {
%s
  return { content: [{ type: "text", text: "ok" }] };
});
`
	py := `import os
import re
import subprocess
from contextlib import suppress
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("t")


@mcp.tool()
def show(name: str, strict: bool = False) -> str:
    """Shows one entry."""
%s
`
	shellJS := "  const out = execSync(`git log ${name}`).toString();"
	shellPy := `    return subprocess.run(f"git log {name}", shell=True, capture_output=True, text=True).stdout`
	for _, c := range []struct {
		name, lang, helper, body, category, want string
	}{
		// closes: the check is the whole reason to leave, on the value the sink reads
		{"plain check", "js", "", "  if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(\"letters and digits only\");\n" + shellJS, "command_injection", "context"},
		{"or-joined checks that all reject", "js", "", "  if (!name || name.length > 64 || !/^[A-Za-z0-9_]+$/.test(name)) {\n    throw new Error(\"bad\");\n  }\n" + shellJS, "command_injection", "context"},
		{"a log line before the throw", "js", "", "  if (!/^[A-Za-z0-9_]+$/.test(name)) {\n    console.error(\"bad name\", name);\n    throw new Error(\"bad\");\n  }\n" + shellJS, "command_injection", "context"},
		{"check and sink in one try", "js", "", "  try {\n    if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(\"bad\");\n    const out = execSync(`git log ${name}`).toString();\n  } catch (e) {\n    return { content: [], isError: true };\n  }", "command_injection", "context"},
		{"python and-or words in the message", "py", "", "    if not re.fullmatch(r\"[A-Za-z0-9_]+\", name):\n        raise ValueError(\"letters and digits only, or underscores\")\n" + shellPy, "command_injection", "context"},
		{"leading dash pasted after a folder", "py", "", "    if not re.fullmatch(r\"[A-Za-z0-9_-]+\", name):\n        raise ValueError(\"bad\")\n" + `    return subprocess.run(f"cat /srv/{name}", shell=True, capture_output=True, text=True).stdout`, "command_injection", "context"},

		// does not close: the check can be skipped, does not reject, or tests another value
		{"a flag skips the check", "js", "", "  if (!/^[A-Za-z0-9_]+$/.test(name) && !force) throw new Error(\"bad\");\n" + shellJS, "command_injection", "needs_review"},
		{"negation over an or-group", "js", "", "  if (!(/^[A-Za-z0-9_]+$/.test(name) || force)) throw new Error(\"bad\");\n" + shellJS, "command_injection", "needs_review"},
		{"else-if after another branch", "js", "", "  if (force) {\n    console.log(\"forced\");\n  } else if (!/^[A-Za-z0-9_]+$/.test(name)) {\n    throw new Error(\"bad\");\n  }\n" + shellJS, "command_injection", "needs_review"},
		{"check only warns", "js", "", "  if (!/^[A-Za-z0-9_]+$/.test(name)) console.warn(\"odd name\");\n  if (limit > 100) throw new Error(\"too many\");\n" + shellJS, "command_injection", "needs_review"},
		{"try that swallows the rejection", "js", "", "  try {\n    if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(\"bad\");\n  } catch (e) {\n    console.error(e);\n  }\n" + shellJS, "command_injection", "needs_review"},
		{"decoded after the check", "js", "", "  if (!/^[A-Za-z0-9%]+$/.test(name)) throw new Error(\"bad\");\n  const file = decodeURIComponent(name);\n  const text = fs.readFileSync(path.join(BASE, file), \"utf8\");", "path_traversal", "needs_review"},
		{"decoded before a check of the raw value", "js", "", "  const file = decodeURIComponent(name);\n  if (!/^[A-Za-z0-9%]+$/.test(name)) throw new Error(\"bad\");\n  const text = fs.readFileSync(path.join(BASE, file), \"utf8\");", "path_traversal", "needs_review"},
		{"reassigned after the check", "js", "", "  if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(\"bad\");\n  name = name.split(\"_\").join(\"/\");\n  const text = fs.readFileSync(path.join(BASE, name), \"utf8\");", "path_traversal", "needs_review"},
		{"validator that accepts more", "js", "function isSafeName(v) {\n  return /^[A-Za-z0-9_]+$/.test(v) || v.startsWith(\"refs/\");\n}", "  if (!isSafeName(name)) throw new Error(\"bad\");\n" + shellJS, "command_injection", "needs_review"},
		{"leading dash where a word starts", "js", "", "  if (!/^[A-Za-z0-9_-]+$/.test(name)) throw new Error(\"bad\");\n" + shellJS, "command_injection", "needs_review"},
		{"check inside a branch", "py", "", "    if strict:\n        if not re.fullmatch(r\"[A-Za-z0-9_]+\", name):\n            raise ValueError(\"bad\")\n" + shellPy, "command_injection", "needs_review"},
		{"basename tested, full path used", "py", "", "    base = os.path.basename(name)\n    if not re.fullmatch(r\"[A-Za-z0-9_]+\\.md\", base):\n        raise ValueError(\"bad\")\n" + `    return subprocess.run(f"pandoc {name}", shell=True, capture_output=True, text=True).stdout`, "command_injection", "needs_review"},
		{"rejection suppressed", "py", "", "    with suppress(ValueError):\n        if not re.fullmatch(r\"[A-Za-z0-9_]+\", name):\n            raise ValueError(\"bad\")\n" + shellPy, "command_injection", "needs_review"},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"server.ts": fmt.Sprintf(js, c.helper, c.body)}
			if c.lang == "py" {
				files = map[string]string{"server.py": fmt.Sprintf(py, c.body)}
			}
			if got := bestTriage(t, files, c.category); got != c.want {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}

// The same in Go, read straight from the lines: the guard search does not yet see a check after
// the argument is taken from the request, so the scan cannot show it
func TestRegexCheckMustStandOnThePathGo(t *testing.T) {
	head := []string{
		`	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {`,
		`		branch := req.GetString("branch", "")`,
	}
	tail := []string{
		`		out, err := exec.Command("sh", "-c", "git log "+branch).Output()`,
		`		return mcp.NewToolResultText(string(out)), err`,
		`	})`,
	}
	for _, c := range []struct {
		name  string
		check []string
		own   bool
		want  bool
	}{
		{"rejecting block", []string{"\t\tif !branchRe.MatchString(branch) {", "\t\t\treturn nil, fmt.Errorf(\"bad branch\")", "\t\t}"}, true, true},
		{"error return in a helper", []string{"\t\tif !branchRe.MatchString(branch) {", "\t\t\treturn nil, fmt.Errorf(\"bad branch\")", "\t\t}"}, false, true},
		{"plain return in a helper", []string{"\t\tif !branchRe.MatchString(branch) {", "\t\t\treturn defaultLog, nil", "\t\t}"}, false, false},
		{"block that only logs", []string{"\t\tif !branchRe.MatchString(branch) {", "\t\t\tlog.Printf(\"odd branch %s\", branch)", "\t\t}", "\t\tif len(branch) > 100 {", "\t\t\treturn nil, fmt.Errorf(\"too long\")", "\t\t}"}, true, false},
		{"check inside a switch case", []string{"\t\tswitch mode {", "\t\tcase \"strict\":", "\t\t\tif !branchRe.MatchString(branch) {", "\t\t\t\treturn nil, fmt.Errorf(\"bad branch\")", "\t\t\t}", "\t\t}"}, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ls := append(append(append([]string{}, head...), c.check...), tail...)
			check := 0
			for i, l := range ls {
				if strings.Contains(l, "MatchString") {
					check = i + 1
				}
			}
			sink := len(head) + len(c.check) + 1
			gi := &guardIndex{files: map[string][]string{"main.go": ls}}
			gi.hit = guardHit{file: "main.go", line: check, value: "branch", fn: 1, own: c.own, roots: []string{"req"}}
			path := []model.FlowStep{
				{Kind: "source", Symbol: "req", File: "main.go", Line: 1},
				{Kind: "transform", Symbol: `"git log "+branch`, File: "main.go", Line: sink},
				{Kind: "sink", Symbol: "exec.Command", File: "main.go", Line: sink},
			}
			if got := gi.closesPath(path); got != c.want {
				t.Fatalf("closesPath = %v, want %v", got, c.want)
			}
		})
	}
}

// A decoding step before the test counts against the test only when the test reads the raw value:
// file = decodeURIComponent(name) and then a test of file sees what the decoding made
func TestDecodingBeforeTheTest(t *testing.T) {
	ls := []string{
		`server.tool("show", "Shows one entry", { name: z.string() }, async ({ name }) => {`,
		`  const file = decodeURIComponent(name);`,
		`  if (!/^[A-Za-z0-9_]+$/.test(%s)) throw new Error("bad");`,
		`  const text = fs.readFileSync(path.join(BASE, file), "utf8");`,
	}
	path := []model.FlowStep{
		{Kind: "source", Symbol: "name", File: "server.ts", Line: 1},
		{Kind: "unknown", Symbol: "decodeURIComponent", File: "server.ts", Line: 2},
		{Kind: "transform", Symbol: "path.join(BASE, file)", File: "server.ts", Line: 4},
		{Kind: "sink", Symbol: "fs.readFileSync", File: "server.ts", Line: 4},
	}
	for _, c := range []struct {
		tested string
		want   bool
	}{{"file", true}, {"name", false}} {
		lines := append([]string{}, ls...)
		lines[2] = fmt.Sprintf(lines[2], c.tested)
		gi := &guardIndex{files: map[string][]string{"server.ts": lines}}
		gi.hit = guardHit{file: "server.ts", line: 3, value: c.tested, fn: 1, own: true, roots: []string{"name"}}
		if got := gi.closesPath(path); got != c.want {
			t.Errorf("test of %s: closesPath = %v, want %v", c.tested, got, c.want)
		}
	}
}
