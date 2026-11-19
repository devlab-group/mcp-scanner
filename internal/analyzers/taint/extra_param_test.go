package taint

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// The TypeScript SDK calls a tool callback as (args, extra): a second parameter is the SDK's, not
// the client's. Through a project wrapper it may be anything, so it is kept for review.
func TestExtraParam_SecondHandlerParameter(t *testing.T) {
	direct := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "x", version: "1" });
server.tool("scan", "Starts a scan", async ({ target }: { target: string }, sessionId: any) => {
  const r = await fetch("https://api.example.invalid/" + sessionId + "/scan");
  return { content: [{ type: "text", text: target + (await r.text()) }] };
});
`
	wrapped := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
export function makeContext(server: McpServer) {
  return {
    accountTool(name: string, config: any, handler: any) {
      const { callback } = buildAccountTool(config, handler);
      return server.registerTool(name, config, callback);
    },
  };
}
export function register(context: any) {
  context.accountTool("scan", { description: "Starts a scan" }, async ({ target }: { target: string }, accountId: string) => {
    const r = await fetch("" + accountId + "/scan");
    return { content: [{ type: "text", text: target + (await r.text()) }] };
  });
}
`
	// The pair: the first parameter is the client's and still reaches the sink
	first := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "x", version: "1" });
server.tool("scan", "Starts a scan", async ({ target }: { target: string }, extra: any) => {
  const r = await fetch("" + target + "/scan");
  return { content: [{ type: "text", text: await r.text() }] };
});
`
	ssrf := func(src string) []model.Finding {
		res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
		var out []model.Finding
		for _, f := range res.Findings {
			if f.Category == "ssrf" {
				out = append(out, f)
			}
		}
		return out
	}
	if fs := ssrf(direct); len(fs) != 0 {
		t.Fatalf("an SDK-registered handler's second parameter is not client input, got %+v", fs)
	}
	fs := ssrf(wrapped)
	if len(fs) == 0 {
		t.Fatal("a wrapper's later parameter must stay a source")
	}
	for _, f := range fs {
		if f.Triage != model.TriageNeedsReview {
			t.Fatalf("want needs_review for a wrapper's later parameter, got %q (%s)", f.Triage, f.TriageReason)
		}
	}
	if fs := ssrf(first); len(fs) == 0 || fs[0].Triage == model.TriageNeedsReview {
		t.Fatalf("the first parameter is client input and must stay a plain finding, got %+v", fs)
	}
}
