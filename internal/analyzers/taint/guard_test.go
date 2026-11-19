package taint

import (
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
