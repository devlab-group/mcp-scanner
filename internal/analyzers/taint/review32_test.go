package taint

import (
	"fmt"
	"testing"
)

// Findings the code review of iteration 32 showed the scanner missed, each beside the shape the
// fix must keep clean
func TestReviewIteration32(t *testing.T) {
	for _, c := range []struct {
		name, file, src, category, want string
	}{
		{"f-string per element joined into SQL", "server.py", `import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
DB = sqlite3.connect("x.db")

@mcp.tool()
def pick(keys: list[str]) -> str:
    """Picks rows"""
    joined = ", ".join(f"'{k}'" for k in keys)
    return str(DB.execute("SELECT * FROM t WHERE k IN (" + joined + ")").fetchall())
`, "sql_injection", "potential"},
		{"placeholder per element stays clean", "server.py", `import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
DB = sqlite3.connect("x.db")

@mcp.tool()
def pick(keys: list[str]) -> str:
    """Picks rows"""
    marks = ", ".join("?" for k in keys)
    return str(DB.execute("SELECT * FROM t WHERE k IN (" + marks + ")", keys).fetchall())
`, "sql_injection", ""},
		{"parameter shadows a module instance of a project class", "server.py", `import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

class Journal:
    def execute(self, line: str) -> None:
        print(line)

conn = Journal()

def run(conn, where: str):
    return conn.execute("SELECT * FROM e WHERE " + where).fetchall()

@mcp.tool()
def events(where: str) -> str:
    """Filters events"""
    return str(run(sqlite3.connect("x.db"), where))
`, "sql_injection", "potential"},
		{"for variable shadows a module dict", "server.py", `import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
pool = {}

@mcp.tool()
def scan(where: str) -> str:
    """Runs a filter on each database"""
    out = []
    for pool in [sqlite3.connect("a.db")]:
        out.append(pool.execute("SELECT * FROM e WHERE " + where).fetchall())
    return str(out)
`, "sql_injection", "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := bestTriage(t, map[string]string{c.file: c.src}, c.category); got != c.want {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}

// A TypeScript constructor parameter property is its own binding: another class's Map field of
// the same name says nothing about it
func TestConstructorPropertyIsNotTheOtherClassesMap(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { Pool } from "pg";
class Memo {
  private store = new Map<string, number>();
  drop(k: string): void {
    this.store.delete(k);
  }
}
class Accounts {
  %s
  find(name: string) {
    return this.store.query("SELECT * FROM a WHERE name = '" + name + "'");
  }
}
const memo = new Memo();
const accounts = new Accounts(new Pool());
const server = new McpServer({ name: "x", version: "1" });
server.tool("find", "Find an account", { name: z.string() }, async ({ name }) => {
  memo.drop(name);
  await accounts.find(name);
  return { content: [{ type: "text", text: "ok" }] };
});
`
	if got := bestTriage(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, "constructor(private store: Pool) {}")}, "sql_injection"); got != "potential" {
		t.Fatalf("want potential, got %q", got)
	}
}

// With the m flag an anchored pattern limits nothing: one matching line is enough for .test()
func TestZodMultilinePatternIsNoCheck(t *testing.T) {
	for _, c := range []struct{ flags, want string }{{"m", "potential"}, {"", ""}} {
		src := fmt.Sprintf(`import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { execSync } from "child_process";
const S = z.object({ unit: z.string().regex(/^[a-z0-9-]+$/%s) });
const server = new Server({ name: "x", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: "st", description: "Status", inputSchema: { type: "object", properties: { unit: { type: "string" } } } }] }));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { unit } = S.parse(request.params.arguments);
  return { content: [{ type: "text", text: execSync("systemctl status " + unit).toString() }] };
});
`, c.flags)
		if got := bestTriage(t, map[string]string{"server.ts": src}, "command_injection"); got != c.want {
			t.Fatalf("flags %q: want %q, got %q", c.flags, c.want, got)
		}
	}
}

// A schema key that also names a nested field is not cleared by the top-level pattern
func TestRegistrationPatternIgnoresRepeatedKey(t *testing.T) {
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { execSync } from "child_process";
const server = new McpServer({ name: "x", version: "1" });
server.tool("run", "Run", { id: z.string().regex(/^[a-z]+$/), opts: z.object({ id: z.string() }) }, async ({ opts: { id } }) => {
  return { content: [{ type: "text", text: execSync("show " + id).toString() }] };
});
`
	if got := bestTriage(t, map[string]string{"server.ts": src}, "command_injection"); got == "" {
		t.Fatalf("the nested id must not be cleared by the top-level pattern")
	}
}
