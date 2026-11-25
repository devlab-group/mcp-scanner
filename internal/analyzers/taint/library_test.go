package taint

import (
	"strings"
	"testing"
)

// execute or query on an object the code builds from a client library of another service's API -
// not a database driver, query engine or data store - with no SQL text on the path is that
// library's method: the finding stays, as context. A database library, a module whose name says
// nothing, SQL text, the project's own module or a relative import keeps it as it was.
func TestSQLByNameOnAnotherLibrarysObject(t *testing.T) {
	py := func(imp, body string) map[string]string {
		return map[string]string{"server.py": "from mcp.server.fastmcp import FastMCP\n" + imp + "\n\nmcp = FastMCP(\"payments\")\nclient = DefaultClient()\n\n\n" +
			"@mcp.tool()\ndef refund(order_id: str) -> str:\n    \"\"\"Refund an order.\"\"\"\n" + body + "\n"}
	}
	const call = "    request = RefundRequest(order_id=order_id)\n    return str(client.execute(request))"
	ts := func(imp, body string) map[string]string {
		return map[string]string{"server.ts": "import { McpServer } from \"@modelcontextprotocol/sdk/server/mcp.js\";\nimport { z } from \"zod\";\n" + imp + "\nconst server = new McpServer({ name: \"t\", version: \"1\" });\nconst billing = new Client();\n" +
			"server.tool(\"refund\", \"Refund an order\", { id: z.string() }, async ({ id }) => {\n" + body + "\n  return { content: [] };\n});\n"}
	}
	withPkg := func(files map[string]string, path, src string) map[string]string {
		files[path] = src
		return files
	}
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"payments SDK client", py("from payments_sdk import DefaultClient, RefundRequest", call), "context"},
		{"payments SDK client, multi-line import", py("from payments_sdk import (\n    DefaultClient,\n    RefundRequest,\n)", call), "context"},
		{"JS billing client", ts("import { Client } from \"@acme/billing-sdk\";", "  await billing.execute(id);"), "context"},
		{"a module whose name says nothing", py("from backends import DefaultClient, RefundRequest", call), "needs_review"},
		{"warehouse SDK client", py("from snowflake_sdk import DefaultClient, RefundRequest", call), "needs_review"},
		{"SQL text on the path", py("from payments_sdk import DefaultClient", "    return str(client.execute(f\"SELECT * FROM refunds WHERE id = '{order_id}'\"))"), "potential"},
		{"the project's own module", withPkg(py("from payments_sdk import DefaultClient, RefundRequest", call), "payments_sdk.py", "class DefaultClient:\n    pass\n"), "needs_review"},
		{"a relative import", py("from .sdk import DefaultClient, RefundRequest", call), "needs_review"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := bestTriage(t, c.files, "sql_injection"); got != c.want {
				t.Fatalf("triage %q, want %q", got, c.want)
			}
			if c.want != "context" {
				return
			}
			res := analyze(t, mustWriteDir(t, c.files))
			for _, f := range categoryFindings(res, "sql_injection") {
				if f.Severity != "LOW" || !strings.Contains(f.TriageReason, "not a database driver") {
					t.Errorf("context finding: severity %s, reason %q", f.Severity, f.TriageReason)
				}
			}
		})
	}
}
