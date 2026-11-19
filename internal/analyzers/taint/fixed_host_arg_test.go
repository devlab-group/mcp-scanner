package taint

import (
	"fmt"
	"testing"
)

// A client method builds a relative API path and the request is made by a helper that resolves it
// against the configured base: the caller's value changes the path on that host, not the host
func TestFixedHostArg_RelativePathPassedToHelper(t *testing.T) {
	const tmpl = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "x", version: "1" });
const BASE = process.env.API_BASE;

async function getStream(url: string) {
  const r = await fetch(new URL(url, BASE));
  return r.text();
}

server.tool("logs", "Gets an application's logs", async ({ name }: { name: string }) => {
  const text = await getStream(%s);
  return { content: [{ type: "text", text }] };
});
`
	cases := []struct {
		name, arg string
		want      int
	}{
		{"relative API path", "`/api/v1/applications/${name}/logs`", 0},
		// The pair: the caller's whole value as the URL still reaches fetch
		{"caller's whole URL", "name", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, tc.arg)}))
			n := 0
			for _, f := range res.Findings {
				if f.Category == "ssrf" {
					n++
				}
			}
			if n != tc.want {
				t.Fatalf("want %d ssrf finding(s), got %d: %+v", tc.want, n, res.Findings)
			}
		})
	}
}
