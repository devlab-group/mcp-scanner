package taint

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A handler that checks the argument and stops when the check fails: the finding is not dropped,
// but it is not a plain potential either: whether the check holds is still open
func TestGuard_CheckWithEarlyExitGoesToReview(t *testing.T) {
	const head = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "x", version: "1" });
`
	cases := []struct {
		name, src string
		want      model.Triage
	}{
		{"an anchored host pattern with throw", head + `
server.tool("links", "Lists the links of a wiki page", async ({ url }: { url: string }) => {
  if (!url.match(/^https?:\/\/[a-z]+\.wikipedia\.org\/wiki\//)) {
    throw new Error("Not a valid Wikipedia URL");
  }
  const response = await fetch(url + "?action=raw");
  return { content: [{ type: "text", text: await response.text() }] };
});
`, model.TriageNeedsReview},
		{"a validator on a derived value with return", head + `
server.tool("show", "Shows a document", async ({ url }: { url: string }) => {
  const normalized = url.trim();
  const validation = validateUrl(normalized);
  if (!validation.valid) {
    return { content: [{ type: "text", text: "bad url" }], isError: true };
  }
  const response = await fetch("" + normalized + "?raw=1");
  return { content: [{ type: "text", text: await response.text() }] };
});
`, model.TriageNeedsReview},
		// The pair: a check whose failure does not stop the handler protects nothing
		{"a check that only logs stays potential", head + `
server.tool("links", "Lists the links of a page", async ({ url }: { url: string }) => {
  if (!url.match(/^https:\/\/docs\.example\.com\//)) {
    console.log("unexpected host");
  }
  const response = await fetch(url + "?action=raw");
  return { content: [{ type: "text", text: await response.text() }] };
});
`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": tc.src}))
			var got []model.Finding
			for _, f := range res.Findings {
				if f.Category == "ssrf" {
					got = append(got, f)
				}
			}
			if len(got) == 0 {
				t.Fatalf("want an ssrf finding, got %+v", res.Findings)
			}
			for _, f := range got {
				// "" is what the analyzer leaves for the scanner to mark potential
				if f.Triage != tc.want {
					t.Fatalf("want triage %s, got %s (%s)", tc.want, f.Triage, f.TriageReason)
				}
			}
		})
	}
}

// The check can sit in a project function the value passes through: buildMeta(id) throws when id
// contains "..". The pair: the same helper without the check leaves the finding a plain one.
func TestGuard_CheckInsideAHelperOnThePath(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { promises as fs } from "fs";
import * as path from "path";
const server = new McpServer({ name: "x", version: "1" });
const ROOT = "/srv/docs";

const buildMeta = (id: string) => {
  %s
  const normalized = id.replace(/^\/+/, "");
  return { path: normalized + ".md" };
};

server.tool("doc", "Returns a document", async ({ id }: { id: string }) => {
  const meta = buildMeta(id);
  const text = await fs.readFile(path.join(ROOT, meta.path), "utf8");
  return { content: [{ type: "text", text }] };
});
`
	for _, tc := range []struct {
		name, check string
		want        string
	}{
		{"denylist check with throw", `if (id.includes("..")) {
    throw new Error("no traversal");
  }`, "needs_review"},
		{"no check", `// nothing`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.check)}))
			fs := categoryFindings(res, "path_traversal")
			if len(fs) == 0 {
				t.Fatalf("want a path_traversal finding, got %+v", res.Findings)
			}
			for _, f := range fs {
				if string(f.Triage) != tc.want {
					t.Fatalf("want triage %q, got %q (%s)", tc.want, f.Triage, f.TriageReason)
				}
			}
		})
	}
}

// exec on an API client's object is matched by name only; child_process.exec is not
func TestExecOnAnotherObjectGoesToReview(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
%s
const server = new McpServer({ name: "x", version: "1" });
server.tool("run", "Runs a command in the session", async ({ cmd }: { cmd: string }) => {
  const out = await %s("echo " + cmd);
  return { content: [{ type: "text", text: String(out) }] };
});
`
	for _, tc := range []struct {
		name, imp, call, want string
	}{
		{"remote API client", `import { Client } from "@example/sdk";
const client = new Client();`, "client.browsers.process.exec", "needs_review"},
		{"child_process namespace", `import * as cp from "child_process";`, "cp.exec", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.imp, tc.call)}))
			fs := categoryFindings(res, "command_injection")
			if len(fs) == 0 {
				t.Fatalf("want a command_injection finding, got %+v", res.Findings)
			}
			if string(fs[0].Triage) != tc.want {
				t.Fatalf("want triage %q, got %q (%s)", tc.want, fs[0].Triage, fs[0].TriageReason)
			}
		})
	}
}

// A branch check followed by a plain return is not the guard; the containment check that throws is
func TestGuard_PrefersTheCheckThatRejects(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFile } from "fs/promises";
import * as path from "path";
const server = new McpServer({ name: "x", version: "1" });

async function loadImage(source: string, root: string) {
  const m = source.match(/^data:.*?;base64,(.+)$/);
  if (m) {
    return m[1];
  }
  const resolvedRoot = path.resolve(root);
  const resolvedPath = path.resolve(resolvedRoot, source);
  const relativePath = path.relative(resolvedRoot, resolvedPath);
  const escapes = relativePath.startsWith("..") || path.isAbsolute(relativePath);
  if (escapes) {
    throw new Error("image source must be inside the working directory");
  }
  return (await readFile(resolvedPath)).toString("base64");
}

server.tool("image", "Creates an image", async ({ source }: { source: string }) => {
  const data = await loadImage(source, process.cwd());
  return { content: [{ type: "text", text: data }] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	fs := categoryFindings(res, "path_traversal")
	if len(fs) == 0 {
		t.Fatalf("want a path_traversal finding to judge, got %+v", res.Findings)
	}
	for _, f := range fs {
		if f.Triage == "needs_review" && !strings.Contains(f.TriageReason, "startsWith") {
			t.Fatalf("the reason must cite the check that rejects, got %q", f.TriageReason)
		}
	}
}

// Query(**filters) with no receiver and no SQL text is a constructor, not a database handle's
// method; db.Query(q) with the caller's value stays a plain finding
func TestBareCallNamedLikeAMethodSinkGoesToReview(t *testing.T) {
	tmpl := `from mcp.server.fastmcp import FastMCP
from weave.query import Query
mcp = FastMCP("x")

@mcp.tool()
def search(name: str) -> str:
    """Searches traces"""
    return str(%s)
`
	for _, tc := range []struct{ name, call, want string }{
		// a receiver-less call named like a method sink, its argument a string: review
		{"constructor", `Query("name = " + name)`, "needs_review"},
		{"method on a handle", `db.Query("SELECT * FROM t WHERE n = '" + name + "'")`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": fmt.Sprintf(tmpl, tc.call)}))
			fs := categoryFindings(res, "sql_injection")
			if len(fs) == 0 {
				t.Fatalf("want a finding, got %+v", res.Findings)
			}
			if string(fs[0].Triage) != tc.want {
				t.Fatalf("want triage %q, got %q (%s)", tc.want, fs[0].Triage, fs[0].TriageReason)
			}
		})
	}
}

// imap.fetch([uid]) fetches a message, not a URL; the global fetch with the caller's URL stays SSRF
func TestFetchMethodOnAnotherObjectGoesToReview(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "x", version: "1" });
server.tool("get", "Gets one item", async ({ id }: { id: string }) => {
  const r = await %s;
  return { content: [{ type: "text", text: String(r) }] };
});
`
	for _, tc := range []struct{ name, call, want string }{
		{"mail client", `imap.fetch([id], { bodies: "" })`, "needs_review"},
		{"global fetch", `fetch(id + "?raw=1")`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.call)}))
			fs := categoryFindings(res, "ssrf")
			if len(fs) == 0 {
				t.Fatalf("want an ssrf finding, got %+v", res.Findings)
			}
			if string(fs[0].Triage) != tc.want {
				t.Fatalf("want triage %q, got %q (%s)", tc.want, fs[0].Triage, fs[0].TriageReason)
			}
		})
	}
}
