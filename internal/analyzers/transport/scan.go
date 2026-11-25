package transport

import (
	"context"
	"io"
	"os"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/analyzers/behavioral"
	"github.com/devlab-group/mcp-scanner/internal/source/bundle"
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/inventory"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// bind is where a listen site puts the endpoint, ordered from safest to most exposed
type bind int

const (
	bindNone    bind = iota // no listen site
	bindLocal               // loopback only, or a local socket path
	bindUnknown             // a runtime value the scanner cannot read
	bindAll                 // every interface (or a named, reachable one)
)

// site is one place in the source a fact was read from
type site struct {
	File   string
	Line   int
	Detail string
}

type listenSite struct {
	site
	Bind bind
}

type corsSite struct {
	site
	// Preflight is set when the CORS layer also answers preflight requests (a CORS library, or an
	// explicit Access-Control-Allow-Headers), so a page can send the JSON POST an SDK transport
	// requires, not only a "simple" text/plain request
	Preflight bool
}

type authSite struct {
	site
	// Conditional is set when the check is only installed under a runtime condition, such as an
	// API key variable being set
	Conditional bool
}

// facts are what one file says about how the server is served
type facts struct {
	endpoints []site // the MCP protocol served over HTTP, SSE or Streamable HTTP
	servers   []site // a generic HTTP server or app created in this file
	listens   []listenSite
	cors      []corsSite
	auth      []authSite
	// jsonrpc is set when the file dispatches MCP JSON-RPC methods itself ("tools/call")
	jsonrpc bool
	// pyRunsWithoutHost are Python run/serve calls that take the host from the FastMCP settings
	pyRunsWithoutHost []site
	// pyHostSetting is the FastMCP host setting (constructor host= or settings.host)
	pyHostSetting *listenSite
	// allowHeaders is set when the file sends Access-Control-Allow-Headers itself
	allowHeaders bool
	// originChecks are tests of the request's Origin header, an allowlist in front of the route
	originChecks []site
	// statefulHTTP is set for a Streamable HTTP transport with session ids, which a page can only
	// continue when the CORS layer exposes the Mcp-Session-Id header
	statefulHTTP bool
	// sessionHeaderNamed is set when the file names Mcp-Session-Id (an exposed-headers list)
	sessionHeaderNamed bool
}

// file is one re-parsed source file
type file struct {
	path  string
	lang  language.ID
	src   []byte
	root  *sitter.Node
	g     *graph.File
	decls map[string][]*sitter.Node
	funcs map[string]bool
	// cli maps a command-line flag (by its normalized name, and for Go by the variable it sets)
	// to the literal default the flag parser gives it
	cli map[string]string
}

func (f *file) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(f.src)
}

// lit decodes a fixed string literal; a missing node is not one
func (f *file) lit(n *sitter.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	return parser.LiteralValue(n, f.src)
}

func line(n *sitter.Node) int { return int(n.StartPosition().Row) + 1 }

func (f *file) site(n *sitter.Node, detail string) site {
	return site{File: f.path, Line: line(n), Detail: detail}
}

func (f *file) imports(names ...string) bool {
	for _, imp := range f.g.Imports {
		p := strings.TrimPrefix(imp.Path, "node:")
		for _, n := range names {
			if p == n || strings.HasPrefix(p, n+"/") || strings.HasPrefix(p, n+".") {
				return true
			}
		}
	}
	return false
}

// triggers are lowercase fragments at least one of which a file must contain to be worth parsing
// again: a transport, a listen call, CORS or an authentication check
var triggers = []string{
	"listen", "uvicorn", "transport", "_app(", "access-control-allow-origin", "cors", "tools/call",
	"newsseserver", "streamablehttp", "sseserver", "settings.host", "fastmcp", "authorization",
	"api-key", "api_key", "bearer", "token_verifier", "auth_server_provider", "auth=", ".start(",
}

func worthParsing(src []byte) bool {
	low := strings.ToLower(string(src))
	for _, t := range triggers {
		if strings.Contains(low, t) {
			return true
		}
	}
	return false
}

// reader opens source files inside the scan root, the way the taint walk does
type reader struct {
	g    *graph.Graph
	root *os.Root
}

func newReader(g *graph.Graph) *reader {
	r := &reader{g: g}
	if g.Root != "" {
		if root, err := os.OpenRoot(g.Root); err == nil {
			r.root = root
		}
	}
	return r
}

func (r *reader) close() {
	if r.root != nil {
		r.root.Close()
	}
}

func (r *reader) open(path string) (*os.File, error) {
	if r.root != nil {
		return r.root.Open(path)
	}
	return os.Open(path)
}

// read returns a file's bytes as the source walk parsed them: bundles blanked, oversized files
// cut at the walk's limit
func (r *reader) read(path string, gf *graph.File) ([]byte, error) {
	fh, err := r.open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	if gf.Bundle {
		src, _, _, err := bundle.Read(fh, inventory.DefaultLimits().MaxFileSize)
		return src, err
	}
	if gf.MaxBytes > 0 {
		return io.ReadAll(io.LimitReader(fh, gf.MaxBytes))
	}
	return io.ReadAll(io.LimitReader(fh, inventory.DefaultLimits().MaxFileSize))
}

// parse re-parses one file; the caller closes the returned tree
func (r *reader) parse(ctx context.Context, path string, gf *graph.File, src []byte) (*file, *sitter.Tree, error) {
	adapter := language.ByID(language.ID(gf.Language))
	if adapter == nil {
		return nil, nil, nil
	}
	tree, err := parser.ParseTree(ctx, adapter, src)
	if err != nil {
		return nil, nil, err
	}
	return &file{path: path, lang: adapter.ID, src: src, root: tree.RootNode(), g: gf}, tree, nil
}

// walkNodes visits every named node, iteratively so a deep minified file cannot exhaust the stack
func walkNodes(root *sitter.Node, visit func(*sitter.Node)) {
	if root == nil {
		return
	}
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visit(n)
		for i := int(n.NamedChildCount()) - 1; i >= 0; i-- {
			if ch := n.NamedChild(uint(i)); ch != nil {
				stack = append(stack, ch)
			}
		}
	}
}

func firstNamed(n *sitter.Node) *sitter.Node {
	for i := range n.NamedChildCount() {
		if ch := n.NamedChild(i); ch != nil && !strings.Contains(ch.Kind(), "comment") {
			return ch
		}
	}
	return nil
}

// namedArgs lists the argument expressions of an argument-list node, without comments
func namedArgs(args *sitter.Node) []*sitter.Node {
	if args == nil {
		return nil
	}
	var out []*sitter.Node
	for i := range args.NamedChildCount() {
		if ch := args.NamedChild(i); ch != nil && !strings.Contains(ch.Kind(), "comment") {
			out = append(out, ch)
		}
	}
	return out
}

// pyArgs splits a Python call's arguments into positional ones and keyword values
func (f *file) pyArgs(call *sitter.Node) ([]*sitter.Node, map[string]*sitter.Node) {
	kw := map[string]*sitter.Node{}
	var pos []*sitter.Node
	for _, a := range namedArgs(call.ChildByFieldName("arguments")) {
		if a.Kind() == "keyword_argument" {
			kw[f.text(a.ChildByFieldName("name"))] = a.ChildByFieldName("value")
			continue
		}
		pos = append(pos, a)
	}
	return pos, kw
}

// declValue returns the one value a name is bound to in this file, or nil when the file binds it
// never or more than once to different text
func (f *file) declValue(name string) *sitter.Node {
	if f.decls == nil {
		f.indexDecls()
	}
	vs := f.decls[name]
	if len(vs) == 0 {
		return nil
	}
	first := f.text(vs[0])
	for _, v := range vs[1:] {
		if f.text(v) != first {
			return nil
		}
	}
	return vs[0]
}

func (f *file) isFunctionName(name string) bool {
	if f.decls == nil {
		f.indexDecls()
	}
	return f.funcs[name]
}

func (f *file) indexDecls() {
	f.decls, f.funcs = map[string][]*sitter.Node{}, map[string]bool{}
	add := func(name *sitter.Node, value *sitter.Node) {
		if name == nil || value == nil || name.Kind() != "identifier" {
			return
		}
		f.decls[f.text(name)] = append(f.decls[f.text(name)], value)
	}
	walkNodes(f.root, func(n *sitter.Node) {
		switch f.lang {
		case language.JavaScript, language.TypeScript:
			switch n.Kind() {
			case "variable_declarator":
				v := n.ChildByFieldName("value")
				if v != nil && isFunctionNode(v) {
					f.funcs[f.text(n.ChildByFieldName("name"))] = true
					return
				}
				add(n.ChildByFieldName("name"), v)
			case "function_declaration", "generator_function_declaration":
				f.funcs[f.text(n.ChildByFieldName("name"))] = true
			}
		case language.Python:
			switch n.Kind() {
			case "assignment":
				add(n.ChildByFieldName("left"), n.ChildByFieldName("right"))
			case "function_definition":
				f.funcs[f.text(n.ChildByFieldName("name"))] = true
			}
		case language.Go:
			switch n.Kind() {
			case "const_spec", "var_spec":
				names, values := n.ChildByFieldName("name"), n.ChildByFieldName("value")
				if names != nil && values != nil {
					if values.Kind() == "expression_list" && values.NamedChildCount() == 1 {
						values = values.NamedChild(0)
					}
					add(names, values)
				}
			case "short_var_declaration", "assignment_statement":
				l, r := n.ChildByFieldName("left"), n.ChildByFieldName("right")
				if l != nil && r != nil && l.NamedChildCount() == 1 && r.NamedChildCount() == 1 {
					add(l.NamedChild(0), r.NamedChild(0))
				}
			case "function_declaration":
				f.funcs[f.text(n.ChildByFieldName("name"))] = true
			}
		}
	})
}

// normFlag reduces --bind-address, bind_address and bindAddress to one key
func normFlag(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var longFlag = regexp.MustCompile(`--([A-Za-z][\w-]*)`)

// cliDefault is the literal default of a command-line flag the file defines
func (f *file) cliDefault(name string) (string, bool) {
	if f.cli == nil {
		f.indexCLI()
	}
	v, ok := f.cli[normFlag(name)]
	return v, ok
}

func (f *file) indexCLI() {
	f.cli = map[string]string{}
	set := func(name string, def *sitter.Node) {
		if v, ok := f.lit(def); ok && name != "" {
			f.cli[normFlag(name)] = v
		}
	}
	walkNodes(f.root, func(n *sitter.Node) {
		switch f.lang {
		case language.JavaScript, language.TypeScript:
			if n.Kind() != "call_expression" || parser.LastSegment(f.text(n.ChildByFieldName("function"))) != "option" {
				return
			}
			args := namedArgs(n.ChildByFieldName("arguments"))
			if len(args) == 0 {
				return
			}
			spec, _ := f.lit(args[0])
			if m := longFlag.FindStringSubmatch(spec); m != nil && len(args) >= 3 {
				// commander: .option("-h, --host <host>", "description", "0.0.0.0")
				set(m[1], args[2])
			} else if len(args) >= 2 && args[1].Kind() == "object" && !strings.Contains(spec, "-") {
				// yargs: .option("host", { default: "0.0.0.0" })
				set(spec, f.objectField(args[1], "default"))
			}
		case language.Python:
			if n.Kind() != "call" || parser.LastSegment(f.text(n.ChildByFieldName("function"))) != "add_argument" {
				return
			}
			pos, kw := f.pyArgs(n)
			for _, a := range pos {
				if s, ok := f.lit(a); ok && strings.HasPrefix(s, "--") {
					set(strings.TrimPrefix(s, "--"), kw["default"])
				}
			}
		case language.Go:
			if n.Kind() != "call_expression" {
				return
			}
			args := namedArgs(n.ChildByFieldName("arguments"))
			switch parser.LastSegment(f.text(n.ChildByFieldName("function"))) {
			case "StringVar":
				if len(args) >= 3 {
					name, _ := f.lit(args[1])
					set(name, args[2])
					set(strings.TrimPrefix(f.text(args[0]), "&"), args[2])
				}
			case "StringVarP":
				if len(args) >= 4 {
					name, _ := f.lit(args[1])
					set(name, args[3])
					set(strings.TrimPrefix(f.text(args[0]), "&"), args[3])
				}
			}
		}
	})
}

var jsFunctionKinds = map[string]bool{
	"arrow_function": true, "function_declaration": true, "function_expression": true, "function": true,
	"method_definition": true, "generator_function_declaration": true, "generator_function": true,
}

func isFunctionNode(n *sitter.Node) bool { return n != nil && jsFunctionKinds[n.Kind()] }

var functionKinds = map[language.ID]map[string]bool{
	language.JavaScript: jsFunctionKinds,
	language.TypeScript: jsFunctionKinds,
	language.Python:     {"function_definition": true, "lambda": true},
	language.Go:         {"function_declaration": true, "method_declaration": true, "func_literal": true},
}

var conditionKinds = map[string]bool{"if_statement": true, "ternary_expression": true, "conditional_expression": true}

// conditional reports whether the code at n only takes effect under a runtime condition about
// credentials or authentication (if (API_KEY) {...}, if settings.auth_token:): an if or ternary
// around the function holding n, or around n itself when it is not inside a function. A
// condition about something else - the transport mode, an entry-point guard - is not optional
// authentication: when it holds, the check is there.
func (f *file) conditional(n *sitter.Node) bool {
	funcs := functionKinds[f.lang]
	inFunc := false
	for p := n.Parent(); p != nil; p = p.Parent() {
		if funcs[p.Kind()] {
			inFunc = true
			continue
		}
		if !conditionKinds[p.Kind()] || !inFunc && insideAnyFunction(p, funcs) {
			// an if inside the function that holds n tests the request, not whether the check exists
			continue
		}
		cond := f.text(p.ChildByFieldName("condition"))
		if cond == "" {
			cond = f.text(p)
		}
		if behavioral.CredentialLikeName(cond) {
			return true
		}
	}
	return false
}

func insideAnyFunction(n *sitter.Node, funcs map[string]bool) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if funcs[p.Kind()] {
			return true
		}
	}
	return false
}
