package taint

import (
	"fmt"
	"testing"
)

// like("%x") inside a SQLAlchemy statement is a literal, not %-formatting of SQL text; real
// formatting and text() still count as raw SQL
func TestSQLAlchemyLiteralPercentIsNotFormatting(t *testing.T) {
	tmpl := `from mcp.server.fastmcp import FastMCP
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from models import File, Symbol
mcp = FastMCP("x")
engine = None

@mcp.tool()
def count(repo: str) -> str:
    """Counts symbols"""
    with Session(engine) as session:
        return str(session.execute(%s).scalar())
`
	for _, c := range []struct{ name, stmt, want string }{
		{"like with a percent literal", `select(func.count(Symbol.id)).join(File, Symbol.file_id == File.id).where(File.repo == repo, Symbol.name.like("%Controller"))`, ""},
		{"percent formatting", `text("SELECT * FROM f WHERE repo = '%s'" % repo)`, "potential"},
		{"concatenation", `text("SELECT * FROM f WHERE repo = '" + repo + "'")`, "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := bestTriage(t, map[string]string{"server.py": fmt.Sprintf(tmpl, c.stmt)}, "sql_injection"); got != c.want {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}

// NAME.method(...) where the file binds NAME only to instances of a project class that defines
// method is that method: followed into, not matched as a library sink by its name
func TestProjectInstanceMethodIsFollowed(t *testing.T) {
	tmpl := `import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

class Console:
    def execute(self, line: str) -> str:
        %s

%s

@mcp.tool()
def run_line(line: str) -> str:
    """Sends a line to the console"""
    return SESSION.execute(line)
`
	for _, c := range []struct{ name, body, bind, category, want string }{
		{"project method, no sink inside", `return line.upper()`, "SESSION = Console()", "sql_injection", ""},
		{"project method with a shell inside", `return subprocess.run(line, shell=True, capture_output=True, text=True).stdout`, "SESSION = Console()", "command_injection", "potential"},
		{"name also bound to something else", `return line.upper()`, "SESSION = None\nSESSION = Console()", "sql_injection", "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := bestTriage(t, map[string]string{"server.py": fmt.Sprintf(tmpl, c.body, c.bind)}, c.category); got != c.want {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}

// A receiver bound only to a built-in container (new Map(), {}) has the language's methods, not a
// project method of the same name in another class
func TestBuiltinContainerMethodsAreNotProjectMethods(t *testing.T) {
	ts := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { promises as fs } from "fs";
class Store {
  async delete(key: string): Promise<void> {
    await fs.rm("/var/cache/" + key, { force: true });
  }
}
class Pool {
  %s
  drop(name: string): void {
    this.items.delete(name);
  }
}
const pool = new Pool();
const server = new McpServer({ name: "x", version: "1" });
server.tool("drop", "Drop a cached item", { name: z.string() }, async ({ name }) => {
  pool.drop(name);
  return { content: [{ type: "text", text: "ok" }] };
});
`
	for _, c := range []struct{ name, field, want string }{
		{"Map field", "private items = new Map<string, number>();", ""},
		{"field of a project type", "private items = new Store();", "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := bestTriage(t, map[string]string{"server.ts": fmt.Sprintf(ts, c.field)}, "path_traversal"); got != c.want {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}

// An inline zod schema entry limited by an anchored class rules out what the class cannot spell
func TestRegistrationPatternLimitsTheArgument(t *testing.T) {
	tmpl := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { readFileSync } from "fs";
const server = new McpServer({ name: "x", version: "1" });
server.tool("blob", "Read a cached blob", { sha: %s }, async ({ sha }) => {
  const out = readFileSync("/var/cache/" + sha).toString();
  return { content: [{ type: "text", text: out }] };
});
`
	for _, c := range []struct{ name, entry, want string }{
		{"hex", `z.string().regex(/^[a-f0-9]{64}$/)`, ""},
		{"word characters and hyphen", `z.string().regex(/^[\w-]+$/)`, ""},
		{"dot allowed", `z.string().regex(/^[a-z0-9.]+$/)`, "potential"},
		{"multiline flag", `z.string().regex(/^[a-f0-9]+$/m)`, "potential"},
		{"widened by or", `z.string().regex(/^[a-f0-9]+$/).or(z.string())`, "potential"},
		{"not anchored", `z.string().regex(/[a-f0-9]+/)`, "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := bestTriage(t, map[string]string{"server.ts": fmt.Sprintf(tmpl, c.entry)}, "path_traversal"); got != c.want {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}

func TestClassSpecials(t *testing.T) {
	for _, c := range []struct {
		class     string
		path, cmd bool
	}{
		{"a-f0-9", true, true}, {`\w-`, true, true}, {"A-Za-z0-9._-", false, true}, {`a-z\s`, false, false},
		{"^a-z", false, false}, {"a-z;", false, false}, {"a-Z", false, false}, {`a-z\/`, false, true},
	} {
		if p, s := pathSafeClass(c.class), shellSafeClass(c.class); p != c.path || s != c.cmd {
			t.Errorf("%q: path %v cmd %v, want %v %v", c.class, p, s, c.path, c.cmd)
		}
	}
}
