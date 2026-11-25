package taint

import (
	"fmt"
	"testing"
)

// Content from a location the code fixes - a literal URL of the server's own host, a literal path
// of its own files - is context; content from an address the caller or the operator's setting
// chooses, or from a folder the server writes, stays a question
func TestStoredContentByItsLocation(t *testing.T) {
	js := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { z } from "zod";
const server = new McpServer({ name: "t", version: "1" });
const API = "https://api.example.com/v1";
const UPSTREAM = process.env.UPSTREAM ?? "https://api.example.com/v1";
server.tool("go", "Does it", { url: z.string() }, async ({ url }) => {
%s
  return { content: [] };
});
`
	for _, c := range []struct {
		name, body, category, want string
	}{
		{"next link from a literal host", "  const first = await (await fetch(\"https://api.example.com/v1/items\")).json();\n  await fetch(first.next);", "ssrf", "context"},
		{"next link from a constant host", "  const first = await (await fetch(API + \"/items\")).json();\n  await fetch(first.next);", "ssrf", "context"},
		{"content from the caller's address", "  const manifest = await (await fetch(url)).json();\n  execSync(manifest.build);", "command_injection", "kept"},
		{"content from an address built on the caller's value", "  const manifest = await (await fetch(API + \"/\" + url)).json();\n  execSync(manifest.build);", "command_injection", "kept"},
		{"build step from the package's own file", "  const cfg = fs.readFileSync(path.join(__dirname, \"build.json\"), \"utf8\");\n  execSync(\"make \" + cfg);", "command_injection", "context"},
		{"next link from a host the operator configures", "  const first = await (await fetch(UPSTREAM + \"/items\")).json();\n  await fetch(first.next);", "ssrf", "needs_review"},
		{"literal file in a folder the server clones into", "  execSync(\"git clone \" + JSON.stringify(url) + \" /srv/work/repo\");\n  const cfg = fs.readFileSync(\"/srv/work/repo/build.txt\", \"utf8\");\n  execSync(\"make \" + cfg);", "command_injection", "kept"},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := fmt.Sprintf(js, c.body)
			got := bestTriage(t, map[string]string{"server.ts": src}, c.category)
			if c.want == "kept" {
				// a finding from the caller's value stays as traced or for review, never context
				if got == "context" || got == "" {
					t.Fatalf("triage %q, want the finding kept", got)
				}
				return
			}
			if got != c.want {
				t.Fatalf("triage %q, want %q", got, c.want)
			}
		})
	}
}
