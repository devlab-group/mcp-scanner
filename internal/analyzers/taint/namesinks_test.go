package taint

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

func categoryCount(t *testing.T, files map[string]string, category string) int {
	t.Helper()
	res := run(t, testutil.WriteTree(t, files))
	requireTraced(t, res)
	n := 0
	for _, f := range res.Findings {
		if f.Category == category {
			n++
		}
	}
	return n
}

const tsHandler = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { helpers } from "./helpers.js";
const server = new McpServer({ name: "t", version: "1" });
server.tool("go", "Does it", { x: z.string() }, async ({ x }) => {
  %s
  return { content: [] };
});
`

// A method name on another kind of object: an object-literal command, a pattern's exec and an
// object built as a tool are no sinks; a receiver known only by its name goes to review
func TestNameOnlySinksOnOtherObjects(t *testing.T) {
	for _, c := range []struct{ name, body, category, want string }{
		{"tool object execute", "const tool = helpers.pick(); await tool.execute({ x });", "sql_injection", ""},
		{"remote API query", "await helpers.service.searchanalytics().query({ requestBody: { q: x } });", "sql_injection", ""},
		{"imported pattern exec", "const m = helpers.TAG_RE.exec(x);", "command_injection", ""},
		{"tool built by its class", "const tool = new helpers.SearchTool(); await tool.execute(x);", "sql_injection", ""},
		{"connector known by its name only", "await helpers.connector.execute([\"ls\", x]);", "sql_injection", "needs_review"},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"server.ts": strings.Replace(tsHandler, "%s", c.body, 1), "helpers.ts": "export const helpers: any = {};\n"}
			if got := bestTriage(t, files, c.category); got != c.want {
				t.Fatalf("triage %q, want %q", got, c.want)
			}
		})
	}
}

// The same code with a differently named receiver gives the same result: what the receiver is
// built from decides, not its name
func TestReceiverNameDoesNotDecide(t *testing.T) {
	goSrc := `package main

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/patrickmn/go-cache"
)

var shared = cache.New(5*time.Minute, 10*time.Minute)

func main() {
	s := server.NewMCPServer("t", "1")
	s.AddTool(mcp.NewTool("fetch", mcp.WithDescription("Fetches a page")), handle)
	server.ServeStdio(s)
}

func handle(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target := req.GetString("url", "")
	%s
	return mcp.NewToolResultText("ok"), nil
}
`
	get := "resp, err := %[1]s.Get(target)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tdefer resp.Body.Close()\n\tio.ReadAll(resp.Body)"
	pySrc := `from falkordb import FalkorDB
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("t")


@mcp.tool()
def find_person(name: str) -> str:
    """Finds a person in the graph."""
    %[1]s = FalkorDB().select_graph("social")
    return str(%[1]s.query("MATCH (p:Person {name: '" + name + "'}) RETURN p").result_set)
`
	for _, c := range []struct {
		name, lang, recv, setup, category, want string
	}{
		{"http client named c", "go", "c", "c := &http.Client{Timeout: 10 * time.Second}", "ssrf", "potential"},
		{"http client named hc", "go", "hc", "hc := &http.Client{Timeout: 10 * time.Second}", "ssrf", "potential"},
		{"cache named c", "go", "c", "c := cache.New(time.Minute, time.Minute)", "ssrf", ""},
		{"package cache", "go", "shared", "", "ssrf", ""},
		{"unknown receiver named c", "go", "c", "c := pick()", "ssrf", "needs_review"},
		{"graph database named graph", "py", "graph", "", "sql_injection", "potential"},
		{"graph database named kg", "py", "kg", "", "sql_injection", "potential"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var files map[string]string
			if c.lang == "go" {
				body := fmt.Sprintf(get, c.recv)
				if c.setup != "" {
					body = c.setup + "\n\t" + body
				}
				files = map[string]string{"main.go": fmt.Sprintf(goSrc, body) + "\nfunc pick() interface{ Get(string) (*http.Response, error) } { return nil }\n"}
			} else {
				files = map[string]string{"server.py": fmt.Sprintf(pySrc, c.recv)}
			}
			if got := bestTriage(t, files, c.category); got != c.want {
				t.Fatalf("triage %q, want %q", got, c.want)
			}
		})
	}
}

func TestSQLTextKeepsAGenericReceiver(t *testing.T) {
	body := "helpers.service.execute(`SELECT * FROM users WHERE name = '${x}'`);"
	if n := categoryCount(t, map[string]string{"server.ts": strings.Replace(tsHandler, "%s", body, 1), "helpers.ts": "export const helpers: any = {};\n"}, "sql_injection"); n == 0 {
		t.Fatal("SQL text on the path keeps the finding whatever the receiver is called")
	}
}

func TestGoValuesGetIsALookup(t *testing.T) {
	src := `package main

import (
	"context"
	"net/url"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("t", "1")
	s.AddTool(mcp.NewTool("p", mcp.WithDescription("Reads a parameter")), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, _ := req.Params.Arguments["name"].(string)
		values, _ := url.ParseQuery("a=1")
		return mcp.NewToolResultText(values.Get(name)), nil
	})
}
`
	if n := categoryCount(t, map[string]string{"main.go": src}, "ssrf"); n != 0 {
		t.Fatalf("url.Values.Get is a lookup, got %d ssrf findings", n)
	}
}

// A closure sees the variables of the function around it, and a docstring is not a signature: the
// receiver's origin is read from the code that builds it
func TestReceiverOriginAcrossClosureAndDocstring(t *testing.T) {
	goSrc := `package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("t", "1")
	c := &http.Client{Timeout: 10 * time.Second}
	s.AddTool(mcp.NewTool("status", mcp.WithDescription("Reports a status page")), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		host := req.GetString("host", "")
		resp, err := c.Get(fmt.Sprintf("https://%s/status", host))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return mcp.NewToolResultText(string(b)), nil
	})
	_ = server.ServeStdio(s)
}
`
	if got := bestTriage(t, map[string]string{"main.go": goSrc}, "ssrf"); got != "potential" {
		t.Errorf("client of the enclosing function: triage %q, want potential", got)
	}
	pySrc := `from falkordb import FalkorDB
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("t")
store = FalkorDB(host="127.0.0.1", port=6380).select_graph("catalog")


@mcp.tool()
def find_item(title: str) -> str:
    """Looks up a catalog item by its title"""
    result = store.query("MATCH (i:Item {title: '" + title + "'}) RETURN i.price")
    return str(result.result_set)
`
	if got := bestTriage(t, map[string]string{"server.py": pySrc}, "sql_injection"); got != "potential" {
		t.Errorf("module-level graph database: triage %q, want potential", got)
	}
}
