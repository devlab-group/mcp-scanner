package taint

import (
	"strings"
	"testing"
)

// A receiver a project factory builds - every return of the function constructs one project
// class - calls that class's method. When the method hands the argument to a sink of the kind its
// name matched, the finding stays at the call, with the inner sink on its path; a method that
// reaches no sink is followed like any other call. A factory that returns more than one class, or
// a library object, leaves the receiver unknown, as before.
func TestFactoryBuiltReceiverCallsTheProjectMethod(t *testing.T) {
	const head = "import json\nimport sqlite3\nfrom pathlib import Path\n\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP(\"journal\")\n\n\n"
	backend := "class LocalBackend:\n    def __init__(self, root):\n        self._root = Path(root)\n\n    def write_text(self, key, text):\n        target = self._root / key\n        target.write_text(text, encoding=\"utf-8\")\n\n\n"
	memory := "class MemoryBackend:\n    def __init__(self):\n        self._items = {}\n\n    def write_text(self, key, text):\n        self._items[key] = text\n\n\n"
	tool := func(body string) string {
		return "@mcp.tool()\ndef archive(day: str, summary: str) -> str:\n    \"\"\"Store the summary of a day.\"\"\"\n" + body + "    return \"stored\"\n"
	}
	const call = "    backend = get_backend()\n    backend.write_text(f\"summaries/{day}.json\", json.dumps({\"s\": summary}))\n"
	for _, c := range []struct {
		name, src, category, want string
		line                      int // the call's line when the finding must stay there
	}{
		{"factory of a class that writes the file", head + backend + "def get_backend():\n    return LocalBackend(Path.home() / \".journal\")\n\n\n" + tool(call), "path_traversal", "potential", 27},
		{"factory of a class that writes the file, the argument as its text", head + backend + "def get_backend():\n    return LocalBackend(Path.home() / \".journal\")\n\n\n" + tool("    backend = get_backend()\n    backend.write_text(\"summaries/today.json\", summary)\n"), "path_traversal", "", 0},
		{"factory of two classes, one writes the file", head + backend + memory + "def get_backend(local=True):\n    if local:\n        return LocalBackend(Path.home())\n    return MemoryBackend()\n\n\n" + tool(call), "path_traversal", "potential", 37},
		{"factory of a class that keeps it in memory", head + memory + "def get_backend():\n    return MemoryBackend()\n\n\n" + tool(call), "path_traversal", "", 0},
		{"factory of two classes, neither writes a file", head + memory + strings.Replace(memory, "MemoryBackend", "OtherBackend", 1) + "def get_backend(local=True):\n    if local:\n        return MemoryBackend()\n    return OtherBackend()\n\n\n" + tool(call), "path_traversal", "needs_review", 0},
		{"factory of a library connection", head + "def get_db():\n    return sqlite3.connect(\"j.db\")\n\n\n" + tool("    db = get_db()\n    db.execute(f\"DELETE FROM notes WHERE day = '{day}'\")\n"), "sql_injection", "potential", 0},
		{"factory of a project database class", head + "class Database:\n    def __init__(self, path):\n        self.conn = sqlite3.connect(path)\n\n    def execute(self, sql):\n        return self.conn.execute(sql)\n\n\n" +
			"def get_db():\n    return Database(\"j.db\")\n\n\n" + tool("    db = get_db()\n    db.execute(f\"DELETE FROM notes WHERE day = '{day}'\")\n"), "sql_injection", "potential", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"server.py": c.src}
			if got := bestTriage(t, files, c.category); got != c.want {
				t.Fatalf("triage %q, want %q", got, c.want)
			}
			if c.line == 0 {
				return
			}
			res := analyze(t, mustWriteDir(t, files))
			for _, f := range categoryFindings(res, c.category) {
				if f.Line == c.line && strings.Contains(f.Description, "the project's own write_text") {
					return
				}
			}
			t.Fatalf("want the finding at the call, line %d, naming the project's own method; got %+v", c.line, categoryFindings(res, c.category))
		})
	}
}
