package taint

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// A sink matched by its method name alone - Get, query, execute - says nothing about the object it
// is called on, and neither does that object's name: c is the usual name of an http.Client and of
// a gin.Context, graph of a Neo4j graph and of a LangGraph. What the code builds the receiver from
// does say it. receiverOrigin finds that text, and the patterns below read it: a known HTTP client
// or database is a sink whatever it is called, a known lookup or a tool object is not one, and a
// name alone sends the finding to review.
var (
	// an HTTP client: net/http's, a retrying or wrapping one, requests/httpx/aiohttp sessions, axios
	httpClientOrigin = regexp.MustCompile(`\bhttp\.Client\b|\bhttp\.DefaultClient\b|\bcleanhttp\.|\bretryablehttp\.|\bresty\.New\(|\bhttpx\.(?:Async)?Client\(|\brequests\.Session\(|\baiohttp\.ClientSession\(|\baxios\.create\(|\burllib3\.PoolManager\(|\*http\.Client\b`)
	// a lookup whose Get reads a value: url.Values, a query or header, a context, a map, a cache
	lookupOrigin = regexp.MustCompile(`\burl\.Values\b|\bParseQuery\(|\.Query\(\)|\.Header\b|\bhttp\.Header\b|\bmake\(map\[|^map\[|\bcontext\.Context\b|\b(?:gin|echo)\.Context\b|\bfiber\.Ctx\b|\bsync\.Map\b|\b(?:lru|cache|ristretto|bigcache|freecache|gocache|ttlcache|expirable)\.New\w*\(|\bviper\.`)
	// a database or graph database handle, or a connection, session or cursor of one
	dbOrigin = regexp.MustCompile(`(?i)\bfalkordb\b|\.select_graph\(|\bneo4j|\bgraphdatabase\b|\.driver\(|\.session\(|\bconnect\(|\bcreate_engine\(|\.cursor\(|\bpool\(|\bcreate_?pool\(|\bcreate_?connection\(|\bsqlite3\b|\bpsycopg|\bpymysql\b|\baiosqlite\b|\bduckdb\b|\bclickhouse|\bknex\(|\bsequelize\b|\bdatasource\(|\bsql\.Open\(|\bpgx\w*\.|\bgorm\.`)
	// an object built as a tool, an agent, a connector, a job or a chain, by its class
	toolOrigin = regexp.MustCompile(`(?:\bnew\s+|^|[=(\s.])[A-Z]\w*(?:Tool|Agent|Connector|Command|Plugin|Action|Workflow|Task|Job|Handler|Bot|Chain|Runnable|Pipeline)\w*\s*[({<]|\bStructuredTool\.from_function\(|\btool\(\{`)
)

// receiverOrigin is what the code says the receiver of a method call is made from: for a chain
// (r.URL.Query(), FalkorDB().select_graph(...)) the chain itself; for a name, the right side of its
// last assignment before the call in the same function, the type its parameter declares, or the
// right side of an assignment at the file's top level. "" when the code does not say.
func receiverOrigin(src []byte, call *sitter.Node, sinkText string) string {
	t := strings.TrimSpace(sinkText)
	i := strings.LastIndexByte(t, '.')
	if i <= 0 {
		return ""
	}
	recv := strings.TrimSpace(strings.TrimRight(t[:i], "!?"))
	if !guardIdent.MatchString(recv) {
		return recv
	}
	lines := strings.Split(string(src), "\n")
	row := int(call.StartPosition().Row)
	if row >= len(lines) {
		return ""
	}
	q := regexp.QuoteMeta(recv)
	// recv = ..., recv := ..., values, _ := ..., const recv: T = ..., self.recv = ... is not recv
	assign := regexp.MustCompile(`^\s*(?:(?:var|let|const|final|val)\s+)?(?:[\w.]+\s*,\s*)*` + q + `(?:\s*,\s*[\w.]+)*\s*(?::\s*[^=]+?)?\s*:?=\s*([^=].*)$`)
	// the call's own function first, then the functions around it, whose variables a closure sees
	upper, start := row, -1
	for fn := enclosingFunctionNode(call); ; fn = enclosingFunctionNode(fn) {
		start = -1
		if fn != nil {
			start = int(fn.StartPosition().Row)
		}
		for k := upper; k > start && k >= 0; k-- {
			l := lines[k]
			if k == row {
				// const tool = new SearchTool(); await tool.execute(x): only what precedes the call
				l = l[:min(int(call.StartPosition().Column), len(l))]
			}
			if m := assign.FindStringSubmatch(l); m != nil {
				return strings.TrimSpace(m[1])
			}
		}
		if fn == nil {
			return ""
		}
		// c *http.Client, c *gin.Context, graph: Neo4jGraph, client: httpx.AsyncClient
		if ps := fn.ChildByFieldName("parameters"); ps != nil {
			if m := regexp.MustCompile(`(?:^|[(,\s])` + q + `(?:[ \t]+|[ \t]*:[ \t]*)(\*?[A-Za-z_][\w.]*(?:\[[^\]]*\])?)`).FindStringSubmatch(ps.Utf8Text(src)); m != nil && m[1] != "" {
				return "type " + m[1]
			}
		}
		upper = start
		if enclosingFunctionNode(fn) == nil {
			break
		}
	}
	for k := 0; k < len(lines) && (start < 0 || k < start); k++ {
		if l := lines[k]; l != "" && l[0] != ' ' && l[0] != '\t' {
			if m := assign.FindStringSubmatch(l); m != nil {
				return strings.TrimSpace(m[1])
			}
		}
	}
	return ""
}
