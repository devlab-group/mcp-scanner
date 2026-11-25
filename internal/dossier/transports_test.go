package dossier

import (
	"strings"
	"testing"
)

// The transports a server starts, by the SDK calls its files make
func TestServerTransports(t *testing.T) {
	for _, c := range []struct {
		name, file, src, want string
	}{
		{"js stdio", "server.ts", `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
const server = new McpServer({ name: "t", version: "1" });
await server.connect(new StdioServerTransport());
`, "stdio"},
		{"js stdio and http", "server.ts", `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "t", version: "1" });
await server.connect(new StdioServerTransport());
await server.connect(new StreamableHTTPServerTransport({ sessionIdGenerator: undefined }));
`, "http,stdio"},
		{"python default run", "server.py", `from mcp.server.fastmcp import FastMCP
mcp = FastMCP("t")
if __name__ == "__main__":
    mcp.run()
`, "stdio"},
		{"python named transport", "server.py", `from mcp.server.fastmcp import FastMCP
mcp = FastMCP("t")
if __name__ == "__main__":
    mcp.run(transport="streamable-http")
`, "http"},
		{"python sse app", "server.py", `from mcp.server.fastmcp import FastMCP
mcp = FastMCP("t")
app = mcp.sse_app()
`, "sse"},
		{"no transport in the code", "server.py", `from mcp.server.fastmcp import FastMCP
mcp = FastMCP("t")
`, ""},
		{"another object's run", "server.py", `from mcp.server.fastmcp import FastMCP
import jobs
mcp = FastMCP("t")
jobs.run()
`, ""},
	} {
		d := buildTree(t, map[string]string{c.file: c.src})
		if len(d.Servers) == 0 {
			t.Errorf("%s: no server found", c.name)
			continue
		}
		if got := strings.Join(d.Servers[0].Transports, ","); got != c.want {
			t.Errorf("%s: transports %q, want %q", c.name, got, c.want)
		}
	}
}
