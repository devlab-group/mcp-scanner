package taint

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

func TestOperationCategory(t *testing.T) {
	lit := func(v string) graph.Arg { return graph.Arg{Text: `"` + v + `"`, Literal: true, Value: v} }
	cases := []struct {
		name     string
		id       language.ID
		callee   string
		args     []graph.Arg
		resolved bool
		imports  []string
		want     string
	}{
		{"node argv process", language.TypeScript, "execFile", []graph.Arg{lit("npm"), {Text: `["test"]`}}, false, nil, "command_injection"},
		{"child_process exec", language.JavaScript, "child_process.exec", []graph.Arg{{Text: "cmd"}}, false, nil, "command_injection"},
		{"aliased child_process exec", language.JavaScript, "cp.exec", []graph.Arg{{Text: "cmd"}}, false, nil, "command_injection"},
		{"RegExp exec runs nothing", language.JavaScript, "pattern.exec", []graph.Arg{{Text: "text"}}, false, nil, ""},
		{"SQL exec on a database receiver", language.TypeScript, "this.sql.exec", []graph.Arg{{Text: "query"}}, false, nil, "sql_injection"},
		{"Go os/exec helper is not a process", language.Go, "exec.LookPath", []graph.Arg{lit("git")}, false, nil, ""},
		{"Go exec.Command", language.Go, "exec.Command", []graph.Arg{lit("git"), lit("status")}, false, nil, "command_injection"},
		{"Python builtin exec evaluates code", language.Python, "exec", []graph.Arg{{Text: "code"}}, false, nil, "eval"},
		{"Python subprocess", language.Python, "subprocess.run", []graph.Arg{{Text: `["ls"]`}}, false, nil, "command_injection"},
		{"pathlib write", language.Python, "(base / name).write_text", []graph.Arg{{Text: "text"}}, false, nil, "path_traversal"},
		{"fs promises rm", language.TypeScript, "fs.rm", []graph.Arg{{Text: "dir"}}, false, nil, "path_traversal"},
		{"fetch", language.TypeScript, "fetch", []graph.Arg{{Text: "url"}}, false, nil, "ssrf"},
		{"the project's own fetch", language.TypeScript, "fetch", []graph.Arg{{Text: "url"}}, true, nil, ""},
		{"a project method named query is followed, not matched", language.Python, "self.query", []graph.Arg{{Text: "q"}}, true, nil, ""},
		{"httpx client post with httpx imported", language.Python, "client.post", []graph.Arg{{Text: "url"}}, false, []string{"httpx"}, "ssrf"},
		{"post on something else", language.Python, "client.post", []graph.Arg{{Text: "url"}}, false, []string{"slack_sdk"}, ""},
		{"Go url.Query is not SQL", language.Go, "parsedURL.Query", nil, false, nil, ""},
		{"a tool object's execute is not SQL", language.TypeScript, "tool.execute", []graph.Arg{{Text: "args"}}, false, nil, ""},
		{"cursor execute is SQL", language.Python, "cursor.execute", []graph.Arg{{Text: "q"}}, false, nil, "sql_injection"},
		{"docker-py run needs the SDK import", language.Python, "client.containers.run", []graph.Arg{lit("alpine")}, false, nil, ""},
		{"docker-py run with the SDK", language.Python, "client.containers.run", []graph.Arg{lit("alpine")}, false, []string{"docker"}, "command_injection"},
	}
	for _, c := range cases {
		got, ok := OperationCategory(c.id, c.callee, c.args, c.resolved, c.imports)
		if c.want == "" {
			if ok {
				t.Errorf("%s: OperationCategory(%q) = %q, want no operation", c.name, c.callee, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("%s: OperationCategory(%q) = %q, %v; want %q", c.name, c.callee, got, ok, c.want)
		}
	}
}
