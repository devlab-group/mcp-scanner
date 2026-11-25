package taint

import (
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func TestWeighPattern(t *testing.T) {
	cases := []struct {
		name     string
		t        regexTest
		category string
		complete bool
		useless  bool
	}{
		{"hex id fullmatch", regexTest{pattern: `[a-f0-9]{32}`, mode: modeFull}, "path_traversal", true, false},
		{"anchored slug", regexTest{pattern: `^[a-z0-9_-]+$`}, "path_traversal", true, false},
		{"dot and slash allowed", regexTest{pattern: `^[\w./-]+$`}, "path_traversal", false, true},
		{"start anchor only", regexTest{pattern: `[a-z]+`, mode: modeStart}, "path_traversal", false, true},
		{"search without anchors", regexTest{pattern: `[a-z0-9]+`}, "command_injection", false, true},
		{"structure keeps dots apart", regexTest{pattern: `^[a-z0-9]+(\.[a-z0-9]+)*$`}, "path_traversal", true, false},
		{"one slash between names", regexTest{pattern: `^[a-z0-9]+(/[a-z0-9]+)?$`}, "path_traversal", false, false},
		{"name with a fixed extension", regexTest{pattern: `^[\w-]+\.json$`}, "path_traversal", true, false},
		{"slug before a shell", regexTest{pattern: `^[a-z0-9][a-z0-9_-]*$`}, "command_injection", true, false},
		{"space allowed before a shell", regexTest{pattern: `^[a-z ]+$`}, "command_injection", false, false},
		{"leading dash allowed", regexTest{pattern: `^[a-zA-Z0-9-]+$`}, "argument_injection", false, true},
		{"no leading dash", regexTest{pattern: `^[a-z0-9][a-z0-9-]*$`}, "argument_injection", true, false},
		{"identifier for SQL", regexTest{pattern: `^[A-Za-z_][A-Za-z0-9_]*$`}, "sql_injection", true, false},
		{"fixed origin", regexTest{pattern: `^https://api\.github\.com/`}, "ssrf", true, false},
		{"origin without the slash", regexTest{pattern: `^https://api\.github\.com`}, "ssrf", false, false},
		{"multiline flag", regexTest{pattern: `^[a-z]+$`, flags: "m"}, "path_traversal", false, false},
		{"lookahead is not read", regexTest{pattern: `^(?!\.)[\w.]+$`}, "path_traversal", false, false},
	}
	for _, c := range cases {
		got := weighPattern(c.t, c.category)
		if got.complete != c.complete || got.ineffective != c.useless {
			t.Errorf("%s: complete=%v ineffective=%v (%s), want complete=%v ineffective=%v", c.name, got.complete, got.ineffective, got.why, c.complete, c.useless)
		}
	}
}

func TestFindRegexTest(t *testing.T) {
	file := []string{`ID = re.compile(r"[0-9a-f]{8}")`, `const NAME_RE = /^[a-z]+$/i;`, `var addrRe = regexp.MustCompile("^[a-z0-9.-]+$")`}
	for _, c := range []struct {
		line, value, pattern string
		mode                 regexMode
	}{
		{`    if not re.fullmatch(r"[a-f0-9]{32}", snap_id):`, "snap_id", `[a-f0-9]{32}`, modeFull},
		{`    if not ID.match(key):`, "key", `[0-9a-f]{8}`, modeStart},
		{`  if (!/^[\w-]+$/.test(name)) throw new Error("x");`, "name", `^[\w-]+$`, modeSearch},
		{`  if (!NAME_RE.test(n)) return;`, "n", `^[a-z]+$`, modeSearch},
		{`  if (!slug.match(/^[a-z0-9-]+$/)) {`, "slug", `^[a-z0-9-]+$`, modeSearch},
		{`	if !addrRe.MatchString(host) {`, "host", `^[a-z0-9.-]+$`, modeSearch},
		{`        if (!id.matches("[0-9]+")) throw new IllegalArgumentException();`, "id", `[0-9]+`, modeFull},
	} {
		got, ok := findRegexTest(c.line, c.value, file)
		if !ok || got.pattern != c.pattern || got.mode != c.mode {
			t.Errorf("findRegexTest(%q) = %+v, %v; want pattern %q mode %d", c.line, got, ok, c.pattern, c.mode)
		}
		if !rejectsOnMismatch(c.line, c.value) {
			t.Errorf("%q: the test is negated, so the exit rejects non-matching values", c.line)
		}
	}
	if rejectsOnMismatch(`  if (/\.\./.test(name)) throw new Error("x");`, "name") {
		t.Error("a test that exits on a match is a denylist, not an allowlist")
	}
}

func triagedPathFinding(t *testing.T, files map[string]string, category string) model.Finding {
	t.Helper()
	res := run(t, testutil.WriteTree(t, files))
	requireTraced(t, res)
	for _, f := range res.Findings {
		if f.Category == category {
			return f
		}
	}
	t.Fatalf("no %s finding: %+v", category, res.Findings)
	return model.Finding{}
}

const pyNotes = `import os
import re
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("t")
NOTES = os.path.expanduser("~/notes")


@mcp.tool()
def note(key: str) -> str:
    """Returns a note"""
    if not %s:
        raise ValueError("bad key")
    with open(os.path.join(NOTES, key)) as fh:
        return fh.read()
`

func TestCompleteAllowlistClosesThePath(t *testing.T) {
	f := triagedPathFinding(t, map[string]string{"server.py": strings.Replace(pyNotes, "%s", `re.fullmatch(r"[0-9]{1,6}", key)`, 1)}, "path_traversal")
	if f.Triage != model.TriageContext || !strings.Contains(f.TriageReason, "path separator") {
		t.Fatalf("triage = %s (%s), want context: the pattern cannot spell a path", f.Triage, f.TriageReason)
	}
}

func TestPatternThatAdmitsDotsDoesNotStopThePath(t *testing.T) {
	f := triagedPathFinding(t, map[string]string{"server.py": strings.Replace(pyNotes, "%s", `re.fullmatch(r"[\w./-]+", key)`, 1)}, "path_traversal")
	if f.Triage == model.TriageNeedsReview || f.Triage == model.TriageContext {
		t.Fatalf("triage = %s (%s): a pattern that accepts ../x is no guard", f.Triage, f.TriageReason)
	}
	if !strings.Contains(f.TriageReason, `"../x"`) {
		t.Fatalf("reason should name the accepted value: %s", f.TriageReason)
	}
}

func TestUnreadablePatternStillGoesToReview(t *testing.T) {
	f := triagedPathFinding(t, map[string]string{"server.py": strings.Replace(pyNotes, "%s", `KEY_RE.fullmatch(key)`, 1) + "\nKEY_RE = load_policy().key_pattern\n"}, "path_traversal")
	if f.Triage != model.TriageNeedsReview {
		t.Fatalf("triage = %s, want needs_review when the pattern is not in the code", f.Triage)
	}
}

func TestPredicateFunctionWithOnePattern(t *testing.T) {
	src := `import { exec } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "t", version: "1" });
function isTicketKey(v: string): boolean {
  return /^[A-Z][A-Z0-9]+-[0-9]+$/.test(v);
}
server.tool("open_ticket", "Opens a ticket in the browser", { key: z.string() }, async ({ key }) => {
  if (!isTicketKey(key)) {
    throw new Error("bad key");
  }
  exec("open https://tracker.example.com/browse/" + key);
  return { content: [] };
});
`
	f := triagedPathFinding(t, map[string]string{"server.ts": src}, "command_injection")
	if f.Triage != model.TriageContext {
		t.Fatalf("triage = %s (%s), want context: the predicate's pattern has no shell syntax", f.Triage, f.TriageReason)
	}
}
