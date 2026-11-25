package transport

import (
	"context"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func run(t *testing.T, files map[string]string) model.AnalyzerResult {
	t.Helper()
	dir := testutil.WriteTree(t, files)
	ac := &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()}
	res := (&Analyzer{}).Analyze(context.Background(), model.Target{Kind: model.TargetSource, Path: dir}, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, errors %v, warnings %v", res.Status, res.Errors, res.Warnings)
	}
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding %s: %v", f.RuleID, err)
		}
	}
	return res
}

func only(t *testing.T, res model.AnalyzerResult, rule string) model.Finding {
	t.Helper()
	var got []model.Finding
	for _, f := range res.Findings {
		if f.RuleID == rule {
			got = append(got, f)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want one %s finding, got %d: %+v", rule, len(got), res.Findings)
	}
	return got[0]
}

func none(t *testing.T, res model.AnalyzerResult) {
	t.Helper()
	if len(res.Findings) != 0 {
		for _, f := range res.Findings {
			t.Errorf("unexpected %s %s %s at %s:%d: %s", f.RuleID, f.Severity, f.Triage, f.File, f.Line, f.Description)
		}
	}
}

const tsHead = `import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { spawn } from "node:child_process";

const server = new McpServer({ name: "t", version: "1" });
server.tool("rebuild", "Rebuilds the docs site", {}, async () => {
  spawn("make", ["docs"]);
  return { content: [{ type: "text", text: "started" }] };
});
const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
await server.connect(transport);
const app = express();
app.use(express.json());
`

func tsServer(tail string) map[string]string {
	return map[string]string{
		"package.json": `{"name":"t","type":"module"}`,
		"src/index.ts": tsHead + tail,
	}
}

func TestTSAllInterfacesWithoutAuthIsExposed(t *testing.T) {
	res := run(t, tsServer(`app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "0.0.0.0");
`))
	f := only(t, res, RuleNetworkExposed)
	if f.Severity != model.SeverityHigh || f.Triage != model.TriagePotential {
		t.Fatalf("severity/triage = %s/%s, want HIGH/potential: %s", f.Severity, f.Triage, f.Description)
	}
	if f.File != "src/index.ts" || f.Line != 16 {
		t.Fatalf("location = %s:%d, want the listen call at src/index.ts:16", f.File, f.Line)
	}
	if !strings.Contains(f.Description, "runs programs") {
		t.Fatalf("description should say what a caller gets: %s", f.Description)
	}
}

func TestTSListenWithoutHostBindsEveryInterface(t *testing.T) {
	res := run(t, tsServer(`app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
const PORT = Number(process.env.PORT ?? 8123);
app.listen(PORT, () => console.log("ready"));
`))
	only(t, res, RuleNetworkExposed)
}

func TestTSHostFromEnvironmentDefault(t *testing.T) {
	res := run(t, tsServer(`app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
const BIND = process.env.BIND_ADDRESS ?? "::";
app.listen(8123, BIND);
`))
	f := only(t, res, RuleNetworkExposed)
	if !strings.Contains(f.Description, "BIND_ADDRESS unset") {
		t.Fatalf("description should name the variable and its default: %s", f.Description)
	}
}

func TestTSLocalhostIsNotExposed(t *testing.T) {
	none(t, run(t, tsServer(`app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, process.env.HOST || "127.0.0.1");
`)))
}

func TestTSApiKeyCheckSuppresses(t *testing.T) {
	none(t, run(t, tsServer(`const KEY = process.env.SERVICE_KEY;
app.post("/mcp", (req, res) => {
  if (req.headers["x-api-key"] !== KEY) return res.status(403).end();
  return transport.handleRequest(req, res, req.body);
});
app.listen(8123, "0.0.0.0");
`)))
}

func TestTSOutgoingAuthorizationHeaderIsNotAuthentication(t *testing.T) {
	res := run(t, tsServer(`async function upstream() {
  return fetch("https://api.example.com/v1/x", { headers: { Authorization: "Bearer " + process.env.UPSTREAM_TOKEN } });
}
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "0.0.0.0");
`))
	only(t, res, RuleNetworkExposed)
}

func TestTSAuthOnlyWhenKeyIsSetGoesToReview(t *testing.T) {
	res := run(t, tsServer(`const TOKEN = process.env.MCP_TOKEN;
if (TOKEN) {
  app.use((req, res, next) => (req.headers.authorization === "Bearer " + TOKEN ? next() : res.status(401).end()));
}
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "0.0.0.0");
`))
	f := only(t, res, RuleNetworkExposed)
	if f.Triage != model.TriageNeedsReview || f.Severity != model.SeverityMedium {
		t.Fatalf("severity/triage = %s/%s, want MEDIUM/needs_review", f.Severity, f.Triage)
	}
}

func TestTSAuthInsideTransportModeBranchStillCounts(t *testing.T) {
	none(t, run(t, tsServer(`const mode = process.argv[2] ?? "stdio";
if (mode === "http") {
  app.use((req, res, next) => (req.headers.authorization ? next() : res.status(401).end()));
  app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
  app.listen(8123, "0.0.0.0");
}
`)))
}

func TestTSCorsDefaultsReachableFromPages(t *testing.T) {
	files := tsServer(`app.use(cors());
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "localhost");
`)
	files["src/index.ts"] = `import cors from "cors";
` + files["src/index.ts"]
	res := run(t, files)
	f := only(t, res, RuleBrowserReachable)
	if f.Triage != model.TriagePotential {
		t.Fatalf("triage = %s, want potential", f.Triage)
	}
	for _, x := range res.Findings {
		if x.RuleID == RuleNetworkExposed {
			t.Fatalf("a localhost listen is not a network exposure: %s", x.Description)
		}
	}
}

func TestTSCorsHeaderWithoutPreflightGoesToReview(t *testing.T) {
	res := run(t, tsServer(`app.use((req, res, next) => { res.setHeader("Access-Control-Allow-Origin", "*"); next(); });
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "127.0.0.1");
`))
	f := only(t, res, RuleBrowserReachable)
	if f.Triage != model.TriageNeedsReview {
		t.Fatalf("triage = %s, want needs_review: an SDK transport needs a JSON body a simple request cannot send", f.Triage)
	}
}

func TestStdioServerWithSideHTTPPageIsNotAnEndpoint(t *testing.T) {
	none(t, run(t, map[string]string{
		"package.json": `{"name":"t"}`,
		"index.js": `const http = require("node:http");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
http.createServer((req, res) => { res.setHeader("Access-Control-Allow-Origin", "*"); res.end("ok"); }).listen(9000, "0.0.0.0");
const server = new McpServer({ name: "t", version: "1" });
server.connect(new StdioServerTransport());
`,
	}))
}

func TestHarmlessToolsAreContext(t *testing.T) {
	res := run(t, map[string]string{
		"package.json": `{"name":"t"}`,
		"index.ts": `import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
const server = new McpServer({ name: "t", version: "1" });
server.tool("add", "Adds two numbers", {}, async ({ a, b }) => ({ content: [{ type: "text", text: String(a + b) }] }));
const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
const app = express();
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123);
`,
	})
	f := only(t, res, RuleNetworkExposed)
	if f.Triage != model.TriageContext || f.Severity != model.SeverityLow {
		t.Fatalf("severity/triage = %s/%s, want LOW/context", f.Severity, f.Triage)
	}
}

func TestTestFilesAreNotEndpoints(t *testing.T) {
	files := tsServer(`app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "127.0.0.1");
`)
	files["test/e2e.test.ts"] = tsHead + `app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(0, "0.0.0.0");
`
	none(t, run(t, files))
}

const pyHead = `import os
import subprocess
from mcp.server.fastmcp import FastMCP

`

const pyTool = `

@mcp.tool()
def restart(service: str) -> str:
    """Restarts one of the app's services"""
    return subprocess.run(["systemctl", "restart", "app-worker"], capture_output=True, text=True).stdout
`

func TestPyFastMCPHostFromEnvDefault(t *testing.T) {
	res := run(t, map[string]string{
		"pyproject.toml": "[project]\nname='t'\n",
		"server.py": pyHead + `mcp = FastMCP("t", host=os.getenv("BIND", "0.0.0.0"))` + pyTool + `
if __name__ == "__main__":
    mcp.run(transport="streamable-http")
`,
	})
	f := only(t, res, RuleNetworkExposed)
	if f.Triage != model.TriagePotential {
		t.Fatalf("triage = %s, want potential", f.Triage)
	}
}

func TestPyRunWithoutHostIsLocal(t *testing.T) {
	none(t, run(t, map[string]string{
		"server.py": pyHead + `mcp = FastMCP("t")` + pyTool + `
if __name__ == "__main__":
    mcp.run(transport="sse")
`,
	}))
}

func TestPyUvicornAllInterfaces(t *testing.T) {
	res := run(t, map[string]string{
		"server.py": pyHead + `import uvicorn
mcp = FastMCP("t")` + pyTool + `
app = mcp.streamable_http_app()
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)
`,
	})
	only(t, res, RuleNetworkExposed)
}

func TestPyFastMCPAuthSuppresses(t *testing.T) {
	none(t, run(t, map[string]string{
		"server.py": pyHead + `import uvicorn
from fastmcp.server.auth import JWTVerifier
verifier = JWTVerifier(jwks_uri="https://login.example.com/jwks")
mcp = FastMCP("t", auth=verifier)` + pyTool + `
if __name__ == "__main__":
    uvicorn.run(mcp.http_app(), host="0.0.0.0")
`,
	}))
}

func TestPyCorsMiddlewareEveryOrigin(t *testing.T) {
	res := run(t, map[string]string{
		"server.py": pyHead + `import uvicorn
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
mcp = FastMCP("t")` + pyTool + `
app = mcp.streamable_http_app()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_headers=["*"], expose_headers=["Mcp-Session-Id"])
uvicorn.run(app, port=9000)
`,
	})
	f := only(t, res, RuleBrowserReachable)
	if f.Triage != model.TriagePotential {
		t.Fatalf("triage = %s, want potential", f.Triage)
	}
}

func TestStatefulSessionWithoutExposedHeaderGoesToReview(t *testing.T) {
	res := run(t, map[string]string{
		"server.py": pyHead + `import uvicorn
from starlette.middleware.cors import CORSMiddleware
mcp = FastMCP("t")` + pyTool + `
app = mcp.streamable_http_app()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_headers=["*"])
uvicorn.run(app, port=9000)
`,
	})
	if f := only(t, res, RuleBrowserReachable); f.Triage != model.TriageNeedsReview {
		t.Fatalf("triage = %s, want needs_review: a page cannot read the session id", f.Triage)
	}
	ts := tsServer(`app.use(cors());
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "127.0.0.1");
`)
	ts["src/index.ts"] = "import cors from \"cors\";\n" + strings.Replace(ts["src/index.ts"], "sessionIdGenerator: undefined", "sessionIdGenerator: () => crypto.randomUUID()", 1)
	if f := only(t, run(t, ts), RuleBrowserReachable); f.Triage != model.TriageNeedsReview {
		t.Fatalf("TS stateful transport: triage = %s, want needs_review", f.Triage)
	}
}

func TestOriginAllowlistRefusesOtherSites(t *testing.T) {
	files := tsServer(`app.use((req, res, next) => {
  if (req.headers.origin && !["http://localhost:5173"].includes(req.headers.origin)) return res.status(403).end();
  next();
});
app.use(cors({ origin: true }));
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "127.0.0.1");
`)
	files["src/index.ts"] = "import cors from \"cors\";\n" + files["src/index.ts"]
	none(t, run(t, files))
}

func TestProjectNamedKeyHeaderAndBytesHeaderAreAuthentication(t *testing.T) {
	none(t, run(t, tsServer(`app.use((req, res, next) => (req.headers["x-mcp-api-key"] === process.env.MCP_KEY ? next() : res.status(401).end()));
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "0.0.0.0");
`)))
	none(t, run(t, map[string]string{"server.py": pyHead + `import hmac
import uvicorn
mcp = FastMCP("t")` + pyTool + `


class Guard:
    def __init__(self, app, token):
        self.app, self.token = app, token

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and not hmac.compare_digest(dict(scope["headers"]).get(b"authorization", b""), self.token):
            return
        await self.app(scope, receive, send)


uvicorn.run(Guard(mcp.streamable_http_app(), b"Bearer x"), host="0.0.0.0")
`}))
}

func TestLocalhostOriginRegexIsNotEveryOrigin(t *testing.T) {
	none(t, run(t, map[string]string{"server.py": pyHead + `import uvicorn
from starlette.middleware.cors import CORSMiddleware
mcp = FastMCP("t")` + pyTool + `
app = mcp.streamable_http_app()
app.add_middleware(CORSMiddleware, allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$", allow_headers=["*"])
uvicorn.run(app, port=9000)
`}))
}

const goHead = `package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("t", "1")
	s.AddTool(mcp.NewTool("uptime", mcp.WithDescription("Reports the host uptime")), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, _ := exec.CommandContext(ctx, "uptime").Output()
		return mcp.NewToolResultText(string(out)), nil
	})
`

func TestGoAddressFromPortVariable(t *testing.T) {
	res := run(t, map[string]string{
		"go.mod": "module t\n",
		"main.go": goHead + `	port := os.Getenv("PORT")
	addr := ":" + port
	_ = server.NewSSEServer(s).Start(addr)
	_ = http.ListenAndServe
}
`,
	})
	only(t, res, RuleNetworkExposed)
}

func TestGoLocalhostIsNotExposed(t *testing.T) {
	none(t, run(t, map[string]string{
		"go.mod": "module t\n",
		"main.go": goHead + `	_ = server.NewStreamableHTTPServer(s).Start("localhost:9000")
	_ = http.ListenAndServe
	_ = os.Getenv
}
`,
	}))
}

func TestGoListenAndServeWithHandler(t *testing.T) {
	res := run(t, map[string]string{
		"go.mod": "module t\n",
		"main.go": goHead + `	h := server.NewStreamableHTTPServer(s)
	_ = os.Getenv
	_ = http.ListenAndServe(":3000", h)
}
`,
	})
	only(t, res, RuleNetworkExposed)
}

func TestClassifyAddresses(t *testing.T) {
	cases := []struct {
		v    hostVal
		want bind
	}{
		{literalVal(":8080"), bindAll},
		{literalVal("0.0.0.0:8080"), bindAll},
		{literalVal("[::]:8080"), bindAll},
		{literalVal("localhost:8080"), bindLocal},
		{literalVal("127.0.0.1:1"), bindLocal},
		{literalVal("%s:%d"), bindUnknown},
		{hostVal{state: valAbsent}, bindAll},
		{unknownVal(), bindUnknown},
	}
	for _, c := range cases {
		if got := classifyGoAddr(c.v); got != c.want {
			t.Errorf("classifyGoAddr(%+v) = %d, want %d", c.v, got, c.want)
		}
	}
	if classifyHost(hostVal{state: valAbsent}, bindAll) != bindAll || classifyHost(hostVal{state: valAbsent}, bindLocal) != bindLocal {
		t.Error("an absent host takes the API's default")
	}
	if classifyHost(literalVal("::1"), bindAll) != bindLocal || classifyHost(literalVal("10.0.0.5"), bindLocal) != bindAll {
		t.Error("loopback and a LAN address are classified by the address itself")
	}
}

func TestCredentialNames(t *testing.T) {
	for name, want := range map[string]bool{
		"OPENAI_API_KEY": true, "githubToken": true, "DB_PASSWORD": true, "SUPABASE_SERVICE_KEY": true,
		"DANGEROUS_KEYWORDS": false, "AUTOMATION_KEYBOARD_PROVIDER": false, "MAX_TOKENS": false,
		"TOKEN_LIMIT": false, "API_KEY_HEADER": false, "PASSWORD_FILE": false, "MONKEY_COUNT": false,
	} {
		if got := credentialName(name); got != want {
			t.Errorf("credentialName(%q) = %v, want %v", name, got, want)
		}
	}
	if !privateKeyName("WALLET_PRIVATE_KEY") || privateKeyName("OPENAI_API_KEY") {
		t.Error("a private key is told apart from a service key")
	}
}

func jsServer(tool string) map[string]string {
	return map[string]string{
		"package.json": `{"name":"t"}`,
		"index.ts": `import express from "express";
import fs from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
const server = new McpServer({ name: "t", version: "1" });
` + tool + `
const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
const app = express();
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "0.0.0.0");
`,
	}
}

func TestSideEffectWritesGoToReview(t *testing.T) {
	f := only(t, run(t, jsServer(`server.tool("render", "Renders a chart and returns it as an image", {}, async () => {
  fs.writeFileSync("/tmp/last-chart.svg", "<svg/>");
  return { content: [] };
});`)), RuleNetworkExposed)
	if f.Severity != model.SeverityMedium || f.Triage != model.TriageNeedsReview {
		t.Fatalf("severity/triage = %s/%s, want MEDIUM/needs_review for a side-effect write", f.Severity, f.Triage)
	}
}

func TestDeclaredFileToolsAreStrong(t *testing.T) {
	f := only(t, run(t, jsServer(`server.tool("delete_note", "Deletes a note file from the vault", {}, async ({ p }) => {
  fs.unlinkSync(p);
  return { content: [] };
});`)), RuleNetworkExposed)
	if f.Severity != model.SeverityHigh {
		t.Fatalf("severity = %s, want HIGH for a tool that says it deletes files", f.Severity)
	}
}

func TestServiceCredentialIsMediumPotential(t *testing.T) {
	f := only(t, run(t, jsServer(`const KEY = process.env.WEATHER_API_KEY;
server.tool("forecast", "Returns the forecast for a city", {}, async ({ city }) => {
  const r = await fetch("https://api.weather.example/v1?city=" + city + "&key=" + KEY);
  return { content: [{ type: "text", text: await r.text() }] };
});`)), RuleNetworkExposed)
	if f.Severity != model.SeverityMedium || f.Triage != model.TriagePotential {
		t.Fatalf("severity/triage = %s/%s, want MEDIUM/potential for a service key", f.Severity, f.Triage)
	}
}

func TestCompiledCopyIsNotASecondFinding(t *testing.T) {
	files := jsServer(`server.tool("run", "Runs the build", {}, async () => { require("node:child_process").execFile("make", []); return { content: [] }; });`)
	files["dist/index.js"] = files["index.ts"]
	res := run(t, files)
	if n := len(res.Findings); n != 1 || res.Findings[0].File != "index.ts" {
		t.Fatalf("want one finding on the source file, got %d: %+v", n, res.Findings)
	}
}

func TestLaunchedExampleIsTheServer(t *testing.T) {
	tool := `server.tool("run", "Runs the build", {}, async () => { execFile("make", []); return { content: [] }; });`
	src := strings.Replace(jsServer(tool)["index.ts"], `import fs from "node:fs";`, `import { execFile } from "node:child_process";`, 1)
	launched := run(t, map[string]string{"package.json": `{"name":"t","bin":{"t":"build/examples/agentServer.js"}}`, "src/examples/agentServer.ts": src})
	if f := only(t, launched, RuleNetworkExposed); f.Triage != model.TriagePotential {
		t.Fatalf("an example the package starts is the shipped server: triage %s", f.Triage)
	}
	sample := run(t, map[string]string{"package.json": `{"name":"t","main":"build/index.js"}`, "src/examples/agentServer.ts": src})
	if f := only(t, sample, RuleNetworkExposed); f.Triage != model.TriageNeedsReview {
		t.Fatalf("an example nothing starts goes to review: triage %s", f.Triage)
	}
}

func TestDispatchInAnImportedModule(t *testing.T) {
	res := run(t, map[string]string{
		"package.json": `{"name":"t","type":"module"}`,
		"server-remote.mjs": `import http from "node:http";
import { handle } from "./protocol.mjs";
http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  let body = "";
  for await (const c of req) body += c;
  res.end(JSON.stringify(await handle(JSON.parse(body))));
}).listen(9000, "127.0.0.1");
`,
		"protocol.mjs": `import { execFile } from "node:child_process";
export async function handle(msg) {
  if (msg.method === "tools/call") {
    return new Promise((ok) => execFile("kubectl", ["get", "pods"], (e, out) => ok(out)));
  }
  return {};
}
`,
	})
	f := only(t, res, RuleBrowserReachable)
	if f.Triage != model.TriagePotential {
		t.Fatalf("triage = %s, want potential: a hand-written server parses any body", f.Triage)
	}
}

func TestAnotherServersAuthDoesNotGuardThisOne(t *testing.T) {
	files := tsServer(`app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "0.0.0.0");
`)
	files["tools/proxy/index.ts"] = `export function relay(req) { return fetch("https://x.example", { headers: { authorization: req.headers.authorization } }); }`
	only(t, run(t, files), RuleNetworkExposed)
}

func TestImportedMiddlewareGuards(t *testing.T) {
	files := tsServer(`app.use(requireKey);
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "0.0.0.0");
`)
	files["src/index.ts"] = `import { requireKey } from "./auth/key.js";
` + files["src/index.ts"]
	files["src/auth/key.ts"] = `export function requireKey(req, res, next) { if (req.headers["x-api-key"] !== process.env.SERVER_KEY) return res.status(401).end(); next(); }`
	none(t, run(t, files))
}

func TestHostFromCommandLineFlagDefaults(t *testing.T) {
	res := run(t, tsServer(`import { program } from "commander";
program.option("-p, --port <n>", "port", "8123").option("-H, --bind-host <host>", "host to bind", "0.0.0.0");
const options = program.parse().opts();
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(Number(options.port), options.bindHost);
`))
	only(t, res, RuleNetworkExposed)
	py := run(t, map[string]string{"server.py": pyHead + `import argparse
import uvicorn
p = argparse.ArgumentParser()
p.add_argument("--host", default="0.0.0.0")
args = p.parse_args()
mcp = FastMCP("t")` + pyTool + `
uvicorn.run(mcp.sse_app(), host=args.host)
`})
	only(t, py, RuleNetworkExposed)
	goRes := run(t, map[string]string{"go.mod": "module t\n", "main.go": goHead + `	addr := flag.String("listen", ":9000", "address")
	flag.Parse()
	_ = os.Getenv
	_ = http.ListenAndServe(*addr, server.NewStreamableHTTPServer(s))
}
`})
	only(t, goRes, RuleNetworkExposed)
}

func TestFixedSQLIsTheServersOwnData(t *testing.T) {
	fixed := only(t, run(t, jsServer(`server.tool("list_todos", "Lists the saved todos", {}, async () => {
  const rows = await db.query("SELECT title FROM todos ORDER BY id");
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});`)), RuleNetworkExposed)
	if fixed.Severity != model.SeverityMedium || fixed.Triage != model.TriageNeedsReview {
		t.Fatalf("fixed statements: %s/%s, want MEDIUM/needs_review", fixed.Severity, fixed.Triage)
	}
	built := only(t, run(t, jsServer(`server.tool("run_sql", "Runs a query", {}, async ({ sql }) => {
  const rows = await db.query(sql);
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});`)), RuleNetworkExposed)
	if built.Severity != model.SeverityHigh {
		t.Fatalf("a query built at run time: %s, want HIGH", built.Severity)
	}
}

func TestDeclaredFilesNeedAFileNoun(t *testing.T) {
	if declaresFiles("Read the ticket and write a comment") || !declaresFiles("Delete a note file") || !declaresFiles("save_to_folder") {
		t.Error("file work is declared by file nouns, not by read/write verbs")
	}
}

func TestReachStaysInsideThePackage(t *testing.T) {
	files := tsServer(`app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
app.listen(8123, "0.0.0.0");
`)
	// the server's only tool spawns; a sibling package of the monorepo is not part of it
	files["src/index.ts"] = strings.Replace(files["src/index.ts"], `spawn("make", ["docs"]);`, `describe();`, 1)
	files["src/index.ts"] = strings.Replace(files["src/index.ts"], `import { spawn } from "node:child_process";`, `function describe() { return "docs"; }`, 1)
	files["other/package.json"] = `{"name":"other"}`
	files["other/run.ts"] = `import { spawnSync } from "node:child_process";
export function describe() { spawnSync("rm", ["-rf", "/tmp/x"]); }`
	f := only(t, run(t, files), RuleNetworkExposed)
	if f.Severity == model.SeverityHigh {
		t.Fatalf("a same-named function in another package does not run in this server: %s", f.Description)
	}
}

func TestExampleWithItsOwnManifestIsStillAnExample(t *testing.T) {
	tool := `server.tool("run", "Runs the build", {}, async () => { execFile("make", []); return { content: [] }; });`
	src := strings.Replace(jsServer(tool)["index.ts"], `import fs from "node:fs";`, `import { execFile } from "node:child_process";`, 1)
	res := run(t, map[string]string{
		"package.json":                       `{"name":"mesh"}`,
		"examples/reviewer/package.json":     `{"name":"reviewer","scripts":{"start":"node review_server.mjs"}}`,
		"examples/reviewer/review_server.ts": src,
	})
	if f := only(t, res, RuleNetworkExposed); f.Triage != model.TriageNeedsReview {
		t.Fatalf("an example started by its own manifest is still an example: triage %s", f.Triage)
	}
}
