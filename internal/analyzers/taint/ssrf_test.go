package taint

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Check tainted URL arguments for SSRF. Clear taint after a fixed host, and
// exclude request bodies and lookups on non-clients.
func TestTaint_SSRFReportsOnlyAControllableHost(t *testing.T) {
	const py = "import asyncio\nimport urllib.request\n\nimport httpx\nimport httpx as hx\nimport requests\nfrom aiohttp import ClientSession\nfrom mcp.server.fastmcp import FastMCP\n\n" +
		"mcp = FastMCP(\"net\")\nBASE = \"https://api.example.com\"\nROOT = \"https://api.example.com/v1/\"\nNOTES = {\"a\": \"1\"}\nclient = httpx.AsyncClient()\n\n\n" +
		"@mcp.tool()\nasync def run(target: str) -> str:\n    \"\"\"Looks something up.\"\"\"\n    %s\n    return \"\"\n"
	const js = "const axios = require(\"axios\");\nconst ax = require(\"axios\");\n\nconst api = axios.create({ baseURL: \"https://api.example.com\" });\nconst cache = new Map();\n\n" +
		"class Svc {\n  constructor() {\n    this.http = axios.create();\n  }\n  async lookup(u) {\n    return this.http.get(u);\n  }\n}\n\n" +
		"class Field {\n  client = axios.create();\n  async lookupField(u) {\n    return this.client.get(u);\n  }\n}\n\n" +
		"async function runHandler({ target }) {\n  %s;\n  return \"\";\n}\n\nfunction register(server) {\n  server.tool(\"run\", \"Looks something up\", runHandler);\n}\n\nmodule.exports = { register };\n"
	const ts = "import axios from \"axios\";\n\nclass Svc {\n  private http = axios.create();\n  async lookup(u: string) {\n    return this.http.get(u);\n  }\n}\n\n" +
		"async function runHandler({ target }: { target: string }) {\n  %s;\n  return \"\";\n}\n\nexport function register(server: any) {\n  server.tool(\"run\", \"Looks something up\", runHandler);\n}\n"
	const goSrc = "package main\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n\t\"strings\"\n)\n\nvar client = &http.Client{}\n\n" +
		"func runHandler(ctx Context, args RunArgs) (string, error) {\n\t%s\n\treturn \"\", nil\n}\n\n" +
		"func register(s *mcp.Server) {\n\ts.AddTool(&mcp.Tool{Name: \"run\", Description: \"Looks something up\"}, runHandler)\n}\n"

	cases := []struct {
		name, file, src string
		want            bool
	}{
		{"Python module get", "server.py", fmt.Sprintf(py, `httpx.get(target)`), true},
		{"Python aliased module get", "server.py", fmt.Sprintf(py, `hx.get(target)`), true},
		{"Python module-level client", "server.py", fmt.Sprintf(py, `await client.get(target)`), true},
		{"Python async with client", "server.py", fmt.Sprintf(py, "async with httpx.AsyncClient() as c:\n        await c.get(target)"), true},
		{"Python async with imported constructor", "server.py", fmt.Sprintf(py, "async with ClientSession() as s:\n        await s.post(target)"), true},
		{"Python client built in place", "server.py", fmt.Sprintf(py, `await httpx.AsyncClient().get(target)`), true},
		{"Python url keyword", "server.py", fmt.Sprintf(py, `httpx.get(url=target)`), true},
		{"Python requests.post with a body", "server.py", fmt.Sprintf(py, `requests.post(target, json={})`), true},
		{"Python urlopen", "server.py", fmt.Sprintf(py, `urllib.request.urlopen(target)`), true},
		{"Python host interpolated", "server.py", fmt.Sprintf(py, `httpx.get(f"https://{target}/status")`), true},
		{"Python host not closed", "server.py", fmt.Sprintf(py, `httpx.get("https://api.example.com" + target)`), true},
		{"Python constant host not closed", "server.py", fmt.Sprintf(py, `httpx.get(f"{BASE}{target}")`), true},
		{"Python unclosed host through a variable", "server.py", fmt.Sprintf(py, "url = BASE + target\n    httpx.get(url)"), true},
		{"Python file scheme", "server.py", fmt.Sprintf(py, `httpx.get("file:///" + target)`), true},
		{"Python printf host", "server.py", fmt.Sprintf(py, `httpx.get("https://%%s/x" %% target)`), true},
		{"Python format host", "server.py", fmt.Sprintf(py, `httpx.get("https://{}/x".format(target))`), true},
		{"Python escape before host end", "server.py", fmt.Sprintf(py, `httpx.get(f"https://api.example.com\x2f{target}")`), true},
		{"Python f-string conversion", "server.py", fmt.Sprintf(py, `httpx.get(f"{BASE!s}/x/{target}")`), true},
		{"Python path added after an open host", "server.py", fmt.Sprintf(py, `httpx.get(f"https://api.example.com{target}" + "/items")`), true},

		{"Python local dict get", "server.py", fmt.Sprintf(py, "table = {\"a\": \"1\"}\n    table.get(target, \"none\")"), false},
		{"Python module dict get", "server.py", fmt.Sprintf(py, `NOTES.get(target)`), false},
		{"Python response json get", "server.py", fmt.Sprintf(py, "data = httpx.get(ROOT).json()\n    data.get(target)"), false},
		{"Python tainted dict get", "server.py", fmt.Sprintf(py, "args = {\"q\": target}\n    args.get(\"q\")"), false},
		{"Python query parameter", "server.py", fmt.Sprintf(py, `httpx.get(ROOT, params={"q": target})`), false},
		{"Python request body", "server.py", fmt.Sprintf(py, `requests.post(ROOT, json={"q": target})`), false},
		{"Python path after fixed host", "server.py", fmt.Sprintf(py, `httpx.get(f"https://api.example.com/items/{target}")`), false},
		{"Python path after constant host", "server.py", fmt.Sprintf(py, `httpx.get(f"{BASE}/items/{target}")`), false},
		{"Python constant root plus input", "server.py", fmt.Sprintf(py, `httpx.get(ROOT + target)`), false},
		{"Python fixed host through a variable", "server.py", fmt.Sprintf(py, "url = f\"{BASE}/items/{target}\"\n    await client.get(url)"), false},
		{"Python printf path", "server.py", fmt.Sprintf(py, `httpx.get("https://api.example.com/items/%%s" %% target)`), false},
		{"Python format path", "server.py", fmt.Sprintf(py, `httpx.get("https://api.example.com/items/{}".format(target))`), false},
		{"Python implicit concatenation", "server.py", fmt.Sprintf(py, `httpx.get(("https://api.example.com/" f"{target}"))`), false},
		{"Python query after host", "server.py", fmt.Sprintf(py, `httpx.get("https://api.example.com?q=" + target)`), false},
		{"Python httpx.Headers get", "server.py", fmt.Sprintf(py, "headers = httpx.Headers({\"a\": \"1\"})\n    headers.get(target)"), false},

		{"JavaScript module get", "server.js", fmt.Sprintf(js, `await axios.get(target)`), true},
		{"JavaScript created instance", "server.js", fmt.Sprintf(js, `await api.get(target)`), true},
		{"JavaScript module under another name", "server.js", fmt.Sprintf(js, `await ax.get(target)`), true},
		{"JavaScript instance on this", "server.js", fmt.Sprintf(js, `await new Svc().lookup(target)`), true},
		{"JavaScript class field instance", "server.js", fmt.Sprintf(js, `await new Field().lookupField(target)`), true},
		{"JavaScript fetch host not closed", "server.js", fmt.Sprintf(js, `await fetch("https://api.example.com" + target)`), true},
		{"JavaScript fetch host interpolated", "server.js", fmt.Sprintf(js, "await fetch(`https://${target}/x`)"), true},
		{"JavaScript Map get", "server.js", fmt.Sprintf(js, `cache.get(target)`), false},
		{"JavaScript path after fixed host", "server.js", fmt.Sprintf(js, "await axios.get(`https://api.example.com/items/${target}`)"), false},
		{"JavaScript request body", "server.js", fmt.Sprintf(js, `await axios.post("https://api.example.com/items", { q: target })`), false},
		{"JavaScript fetch path", "server.js", fmt.Sprintf(js, `await fetch("https://api.example.com/items/" + target)`), false},
		{"TypeScript class field instance", "server.ts", fmt.Sprintf(ts, `await new Svc().lookup(target)`), true},

		{"Go client Get", "main.go", fmt.Sprintf(goSrc, `client.Get(args.URL)`), true},
		{"Go NewRequest URL", "main.go", fmt.Sprintf(goSrc, `http.NewRequest("GET", args.URL, nil)`), true},
		{"Go Sprintf host", "main.go", fmt.Sprintf(goSrc, `http.Get(fmt.Sprintf("https://%%s/x", args.Host))`), true},
		{"Go NewRequest body", "main.go", fmt.Sprintf(goSrc, `http.NewRequest("POST", "https://api.example.com/items", strings.NewReader(args.Body))`), false},
		{"Go path after fixed host", "main.go", fmt.Sprintf(goSrc, `http.Get("https://api.example.com/items/" + args.ID)`), false},
		{"Go Sprintf path", "main.go", fmt.Sprintf(goSrc, `http.Get(fmt.Sprintf("https://api.example.com/items/%%s", args.ID))`), false},
		{"Go query values Get", "main.go", fmt.Sprintf(goSrc, `args.Query.Get("url")`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := run(t, testutil.WriteTree(t, map[string]string{tc.file: tc.src}))
			got := categoryFindings(res, "ssrf")
			if tc.want && len(got) == 0 {
				t.Fatalf("want an ssrf finding, got none among %+v (gaps %v)", res.Findings, res.Coverage.Gaps())
			}
			if !tc.want {
				requireTraced(t, res)
				if len(got) != 0 {
					t.Fatalf("want no ssrf finding, got %+v", got)
				}
			}
		})
	}
}

func TestFixesURLHost(t *testing.T) {
	cases := []struct {
		prefix string
		want   bool
	}{
		{"https://api.example.com/", true},
		{"https://api.example.com/v1/items/", true},
		{"https://api.example.com?q=", true},
		{"https://api.example.com#", true},
		{"http://localhost:8080/", true},
		{"https://user@api.example.com/", true},
		{"HTTPS://api.example.com/", true},
		{"svn+ssh://host.example/", true},
		{"https://api.example.com", false},
		{"https://api.example.com:", false},
		{"https://", false},
		{"https:///", false},
		{"file:///etc/", false},
		{"//api.example.com/", false},
		{"/items/", false},
		{"", false},
		{"1http://api.example.com/", false},
		{"ht tp://api.example.com/", false},
		{"https://api.example.com\\@evil.example/", false},
		{"https://api.example.com%2f/", false},
		{"https://api.example .com/", false},
	}
	for _, tc := range cases {
		if got := fixesURLHost(tc.prefix); got != tc.want {
			t.Errorf("fixesURLHost(%q) = %v, want %v", tc.prefix, got, tc.want)
		}
	}
}

// Read a URL's fixed prefix by unwrapping each parenthesis pair once, keeping
// deeply nested input from causing repeated walks of the same expression
func TestTaint_DeepParenthesesDoNotStallTheScan(t *testing.T) {
	const depth = 20000
	dir := testutil.WriteTree(t, map[string]string{
		"E.java": "class E { int x = " + strings.Repeat("(", depth) + "1" + strings.Repeat(")", depth) + "; }\n",
	})
	done := make(chan model.AnalyzerResult, 1)
	go func() { done <- run(t, dir) }()
	select {
	case res := <-done:
		if res.Status != model.AnalyzerCompleted {
			t.Fatalf("status = %s, want %s", res.Status, model.AnalyzerCompleted)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("taint analysis of %d nested parentheses still running after 30s", depth)
	}
}
