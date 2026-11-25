# transport

`transport` reads, from source, how a server serves MCP over HTTP, SSE or
Streamable HTTP. It answers one question: can another machine, or a web page
the user opens, call the tools without credentials? Nothing is run and no
request is sent.

## What it reads

- **The endpoint.** It recognises these as MCP served over HTTP:
  - the TypeScript SDK transports (`StreamableHTTPServerTransport`,
    `SSEServerTransport`);
  - Python FastMCP `run(transport="sse" | "streamable-http" | "http")`,
    `sse_app()`, `streamable_http_app()` and `http_app()`;
  - Go `mcp-go` (`NewSSEServer`, `NewStreamableHTTPServer`) and go-sdk
    (`NewStreamableHTTPHandler`, `NewSSEHandler`);
  - a file that dispatches `tools/call` itself behind an HTTP server.
- **The listen address.** It reads `listen(port, host)` and
  `listen({ host })`, uvicorn and FastMCP `host=`, `settings.host`, Go
  `Start(addr)`, `ListenAndServe(addr)`, `http.Server{Addr}` and `net.Listen`.
  The host is read when it is one of these:
  - a literal;
  - a same-file constant;
  - an environment variable with a literal default (`process.env.HOST ||
    "0.0.0.0"`, `os.getenv("HOST", "0.0.0.0")`, `":" + port`).

  The API's own default applies when no host is given:
  - Node's `listen(port)` and Go's `":port"` bind every interface;
  - uvicorn, FastMCP and fastify bind localhost.
- **CORS.** These count as allowing every origin:
  - `cors()` with no origin;
  - `cors({ origin: "*" | true })`;
  - an `Access-Control-Allow-Origin: *` header, set by a call or in a headers
    object or dictionary;
  - an echoed request Origin;
  - Starlette `CORSMiddleware(allow_origins=["*"])`;
  - Go `cors.AllowAll()` and `AllowedOrigins: []string{"*"}`.
- **Authentication.** These count as authentication:
  - a read of the `Authorization`, an API-key or a token request header
    (`x-api-key`, `x-mcp-api-key`, `x-<name>-token`), when the code around
    the read refuses the request (a 401 or 403, "unauthorized", a
    constant-time comparison); a header that only chooses whose token to use
    authenticates nobody;
  - SDK or framework auth: `requireBearerAuth`, FastMCP `auth=`,
    `token_verifier=`, FastAPI `HTTPBearer`, go-sdk `RequireBearerToken`, and
    similar.

  A check installed only under a condition on a credential is marked optional,
  for example `if (API_KEY) app.use(...)`.

## What the tools can do

An unauthenticated endpoint is only as dangerous as its tools. For every tool
handler in the server's package, the analyzer walks everything the handler
reaches inside that package, including callbacks written inside it. It
classifies each call with the taint analyzer's sink catalogue
(`taint.OperationCategory`) and the behavioral catalogue.

| What the tools reach | Severity | Triage |
|---|---|---|
| Run a program, evaluate code, run a query built at run time, read a sensitive path, change files when the tool says it works with files (file, folder, directory, path), or act with a private key or wallet seed | HIGH | potential |
| Act with a service credential the server reads (an API key or token named `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`) | MEDIUM | potential |
| Only read local files, read the server's own configuration (`.env`), run fixed SQL on its own database, or write files as a side effect | MEDIUM | needs_review |
| Nothing of the above | LOW | context |

Other conditions change the result:

- **Optional authentication.** A check installed only under a condition on a
  credential lowers a finding to MEDIUM and needs_review.
- **Example code.** An endpoint under `examples/` or `demo/` goes to
  needs_review unless the package manifest starts that file.
- **Tests and build copies.** Test files are not read as endpoints. A
  compiled copy under `dist/` or `build/` is skipped when its source is
  scanned too.

The listen host can also come from a command-line flag default:
commander and yargs `.option`, argparse `add_argument`, or Go `flag.String`
and `StringVar`. An HTTP server that hands requests to a local module
dispatching `tools/call` counts as an endpoint.

## Rules

| Rule | Fires when |
|---|---|
| `transport.network_exposed` | The endpoint listens on every interface, or on a named address reachable from its network, and the server's package has no authentication check. |
| `transport.browser_reachable` | The endpoint allows every origin and the package has no authentication check. This counts even on localhost, because the page runs in the user's own browser. |

No `browser_reachable` finding is reported when the server tests the request's
Origin and refuses other sites, or when Starlette `allow_origin_regex` only
admits localhost. The finding goes to needs_review when the transport keeps
sessions (Streamable HTTP with a session id generator, FastMCP without
`stateless_http`) and the server never names `Mcp-Session-Id` for CORS: a
page cannot read that header and so cannot go past `initialize`.

A `browser_reachable` finding also goes to needs_review when two things are true:

- the CORS header is set without an answer to preflight requests;
- the endpoint is an SDK transport.

Those transports reject the "simple" request a page can send without a
preflight.

## Limitations

- **Other servers.** Frameworks and transports not listed above are not read.
- **Computed addresses.** A host computed in another file, or by an
  expression other than those above, leaves the endpoint unplaced. It is then
  not reported.
- **Authentication.**
  - It is recognised only in the forms above.
  - A check counts when it is in the server file, its directory or a local
    module the server imports (two levels). One such check counts for all of
    the server's routes.
  - A named middleware that is registered under a condition is not seen as
    optional.
- **Tool reach.** It is the catalogues' view of the code. A cloud SDK call the
  catalogues do not know counts only through the credentials the server
  reads.
- **DNS rebinding.** A localhost endpoint that checks neither Host nor Origin
  is not reported yet.
