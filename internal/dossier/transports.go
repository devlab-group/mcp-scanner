package dossier

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/internal/source/targetfs"
)

// Transports a server starts, by the SDK calls the code makes: stdio, sse, http (Streamable HTTP)
const (
	transportStdio = "stdio"
	transportSSE   = "sse"
	transportHTTP  = "http"
)

var (
	// the SDKs' own transport constructors and serving calls, by the callee's last part
	transportCalls = map[string]string{
		"StdioServerTransport": transportStdio, "SSEServerTransport": transportSSE, "StreamableHTTPServerTransport": transportHTTP, "WebStandardStreamableHTTPServerTransport": transportHTTP,
		"stdio_server": transportStdio, "run_stdio_async": transportStdio,
		"sse_app": transportSSE, "run_sse_async": transportSSE,
		"streamable_http_app": transportHTTP, "run_streamable_http_async": transportHTTP, "http_app": transportHTTP, "run_http_async": transportHTTP,
		"ServeStdio": transportStdio, "NewStdioServer": transportStdio, "NewSSEServer": transportSSE, "NewSSEHandler": transportSSE,
		"NewStreamableHTTPServer": transportHTTP, "NewStreamableHTTPHandler": transportHTTP,
	}
	// run(transport="streamable-http"), the Python SDKs' own spelling
	namedTransport = map[string]string{"stdio": transportStdio, "sse": transportSSE, "streamable-http": transportHTTP, "streamable_http": transportHTTP, "http": transportHTTP}
	// &mcp.StdioTransport{} handed to a Go server's Run: the transport is an argument, not a call
	jsTransport = regexp.MustCompile(`new\s+(StdioServerTransport|SSEServerTransport|StreamableHTTPServerTransport|WebStandardStreamableHTTPServerTransport)\s*\(`)
	identOnly   = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)
	goTransport = regexp.MustCompile(`\b(StdioTransport|StreamableHTTPHandler|StreamableHTTPServer|SSEHandler|SSEServer)\b`)
)

// transportsByFile is which transports each file's calls start
func transportsByFile(g *graph.Graph) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	set := func(file, kind string) {
		if out[file] == nil {
			out[file] = map[string]bool{}
		}
		out[file][kind] = true
	}
	// JavaScript and TypeScript constructor calls are not in the call list: read their files' text
	for file, f := range g.Files {
		if f.Language != "javascript" && f.Language != "typescript" {
			continue
		}
		b, err := targetfs.ReadGraphFile(g, file)
		if err != nil {
			continue
		}
		for _, m := range jsTransport.FindAllStringSubmatch(string(b), -1) {
			set(file, transportCalls[m[1]])
		}
	}
	text := map[string]string{}
	for _, c := range g.Calls {
		last := parser.LastSegment(strings.TrimPrefix(strings.TrimSpace(c.CalleeText), "new "))
		if k := transportCalls[last]; k != "" {
			set(c.File, k)
		}
		for _, a := range c.Args {
			if last == "Run" || last == "Serve" || last == "Connect" {
				for _, m := range goTransport.FindAllString(a.Text, -1) {
					switch {
					case strings.HasPrefix(m, "Stdio"):
						set(c.File, transportStdio)
					case strings.HasPrefix(m, "SSE"):
						set(c.File, transportSSE)
					default:
						set(c.File, transportHTTP)
					}
				}
			}
		}
		if last != "run" {
			continue
		}
		// mcp.run(transport="sse"); mcp.run() on a FastMCP object starts stdio
		recv := strings.TrimSuffix(strings.TrimSpace(c.CalleeText), ".run")
		named := false
		for _, a := range c.Args {
			if a.Literal && (a.Keyword == "transport" || a.Keyword == "" && namedTransport[a.Value] != "") {
				if k := namedTransport[a.Value]; k != "" {
					set(c.File, k)
				}
				named = true
			}
		}
		if named || !strings.HasSuffix(strings.TrimSpace(c.CalleeText), ".run") || !identOnly.MatchString(recv) {
			continue
		}
		src, ok := text[c.File]
		if !ok {
			b, err := targetfs.ReadGraphFile(g, c.File)
			if err == nil {
				src = string(b)
			}
			text[c.File] = src
		}
		if regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(recv) + `\s*(?::[^=\n]+)?=\s*(?:\w+\.)*FastMCP\(`).MatchString(src) {
			set(c.File, transportStdio)
		}
	}
	return out
}

// setTransports names the transports a server starts: the calls in its own file, or, when there
// are none, in its folder. A server whose files start none has none named.
func setTransports(g *graph.Graph, servers []Server) {
	byFile := transportsByFile(g)
	byDir := map[string]map[string]bool{}
	for f, kinds := range byFile {
		d := path.Dir(f)
		if byDir[d] == nil {
			byDir[d] = map[string]bool{}
		}
		for k := range kinds {
			byDir[d][k] = true
		}
	}
	for i := range servers {
		kinds := byFile[servers[i].File]
		if len(kinds) == 0 {
			kinds = byDir[path.Dir(servers[i].File)]
		}
		for k := range kinds {
			servers[i].Transports = append(servers[i].Transports, k)
		}
		sort.Strings(servers[i].Transports)
	}
}
