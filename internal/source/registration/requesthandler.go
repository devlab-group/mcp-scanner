// requesthandler.go recognizes the low-level SDK's request-based registration form, used by
// the reference MCP servers: a ListToolsRequestSchema (or Python's @app.list_tools())
// handler returns the capabilities themselves - an array literal, or an object literal with
// a "tools"/"prompts"/"resources" array field - and a separate CallToolRequestSchema
// (@app.call_tool()) handler dispatches every call by name
package registration

import (
	"path"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// requestHandlerRole is which capability kind a setRequestHandler /
// @app.list_x()/@app.call_x() registration concerns, and which of the two
// roles the low-level form splits registration into: list (the
// capabilities themselves are declared here) or dispatch (a single handler
// fields every call by name, so it is wired up as every listed
// capability's Handler rather than read for a declaration of its own)
type requestHandlerRole struct {
	kind graph.CapabilityKind
	list bool
}

// requestHandlerSchemas maps the TypeScript SDK's schema constants, as
// referenced in a setRequestHandler call, to the role they play
var requestHandlerSchemas = map[string]requestHandlerRole{
	"listtoolsrequestschema":     {graph.CapabilityTool, true},
	"calltoolrequestschema":      {graph.CapabilityTool, false},
	"listpromptsrequestschema":   {graph.CapabilityPrompt, true},
	"getpromptrequestschema":     {graph.CapabilityPrompt, false},
	"listresourcesrequestschema": {graph.CapabilityResource, true},
	"readresourcerequestschema":  {graph.CapabilityResource, false},
}

// requestHandlerDecorators maps the Python low-level Server's decorator
// names to the same roles requestHandlerSchemas selects for the
// TypeScript SDK's setRequestHandler form
var requestHandlerDecorators = map[string]requestHandlerRole{
	"listtools":     {graph.CapabilityTool, true},
	"calltool":      {graph.CapabilityTool, false},
	"listprompts":   {graph.CapabilityPrompt, true},
	"getprompt":     {graph.CapabilityPrompt, false},
	"listresources": {graph.CapabilityResource, true},
	"readresource":  {graph.CapabilityResource, false},
}

// serverKeywordRoles maps the Python SDK 2.x low-level Server's handler keywords to the roles the
// decorator form selects
var serverKeywordRoles = map[string]requestHandlerRole{
	"on_list_tools":     {graph.CapabilityTool, true},
	"on_call_tool":      {graph.CapabilityTool, false},
	"on_list_prompts":   {graph.CapabilityPrompt, true},
	"on_get_prompt":     {graph.CapabilityPrompt, false},
	"on_list_resources": {graph.CapabilityResource, true},
	"on_read_resource":  {graph.CapabilityResource, false},
}

// classifySetRequestHandlerCall reports whether c is a
// `server.setRequestHandler(XRequestSchema, handler)` call, and which role
// it plays, keyed on the first argument's own text rather than the callee
// alone - setRequestHandler names nothing about which capability it
// concerns by itself
func classifySetRequestHandlerCall(c graph.Call) (requestHandlerRole, bool) {
	if normalize(parser.LastSegment(c.CalleeText)) != "setrequesthandler" || len(c.Args) == 0 {
		return requestHandlerRole{}, false
	}
	if c.Args[0].Literal {
		// The v2 TypeScript SDK names the method itself: setRequestHandler('tools/list', ...)
		role, ok := requestHandlerMethods[c.Args[0].Value]
		return role, ok
	}
	role, ok := requestHandlerSchemas[normalize(parser.LastSegment(c.Args[0].Text))]
	return role, ok
}

// requestHandlerMethods maps MCP method names, as the v2 TypeScript SDK's setRequestHandler takes
// them, to the same roles as the schema constants
var requestHandlerMethods = map[string]requestHandlerRole{
	"tools/list":     {graph.CapabilityTool, true},
	"tools/call":     {graph.CapabilityTool, false},
	"prompts/list":   {graph.CapabilityPrompt, true},
	"prompts/get":    {graph.CapabilityPrompt, false},
	"resources/list": {graph.CapabilityResource, true},
	"resources/read": {graph.CapabilityResource, false},
}

// classifyRequestHandlerDecorator reports whether dec is a
// @app.list_tools()/@app.call_tool()-shaped decorator (or its prompt/
// resource equivalents), and which role it plays. Checked ahead of
// classifyDecorator, which would otherwise read both "list_tools" and
// "call_tool" as two ordinary tool registrations - both contain "tool" -
// and never see the tools they actually declare or dispatch.
func classifyRequestHandlerDecorator(dec string) (requestHandlerRole, bool) {
	name := dec
	if i := strings.IndexByte(name, '('); i >= 0 {
		name = name[:i]
	}
	role, ok := requestHandlerDecorators[normalize(parser.LastSegment(name))]
	return role, ok
}

// listSite is one discovered list-side registration, waiting for every
// setRequestHandler/decorator in the graph to be classified before its
// capabilities are emitted - the dispatch side for its kind can be named
// by a call anywhere else in the tree, found before or after this one
type listSite struct {
	kind graph.CapabilityKind
	sym  *graph.Symbol // nil when even the handler itself could not be resolved
	file string
	line int
}

// requestHandlerState is collected across both the call-based
// (setRequestHandler) and decorator-based (@app.list_tools()) mechanisms
// before anything is emitted, since either can name the dispatch side for
// a kind the other named the list side for
type requestHandlerState struct {
	sites    []listSite
	dispatch map[graph.CapabilityKind]graph.SymbolID
}

func newRequestHandlerState() *requestHandlerState {
	return &requestHandlerState{dispatch: map[graph.CapabilityKind]graph.SymbolID{}}
}

// addCall records one setRequestHandler call once it has been classified,
// resolving its handler argument the same way emitDirect resolves a
// registration's handler: an inline function literal's own HandlerID when
// there is one, a named reference otherwise
func (st *requestHandlerState) addCall(g *graph.Graph, idx index, c graph.Call) {
	if callee, _, _ := strings.Cut(parser.LastSegment(c.CalleeText), "["); callee == "Server" {
		// Server[Any](...) is the same constructor with a type argument
		// The Python SDK 2.x low-level server takes its handlers as constructor keywords:
		// Server("name", on_list_tools=list_tools, on_call_tool=call_tool)
		for i := range c.Args {
			role, ok := serverKeywordRoles[c.Args[i].Keyword]
			if !ok {
				continue
			}
			sym, id := resolveHandlerArg(g, idx, &c.Args[i])
			if role.list {
				st.sites = append(st.sites, listSite{kind: role.kind, sym: sym, file: c.File, line: c.Line})
			} else if id != "" {
				st.dispatch[role.kind] = id
			}
		}
		return
	}
	role, ok := classifySetRequestHandlerCall(c)
	if !ok {
		return
	}
	var a *graph.Arg
	if len(c.Args) > 1 {
		a = &c.Args[1]
	}
	sym, id := resolveHandlerArg(g, idx, a)
	if role.list {
		st.sites = append(st.sites, listSite{kind: role.kind, sym: sym, file: c.File, line: c.Line})
		return
	}
	if id != "" {
		st.dispatch[role.kind] = id
	}
}

func (st *requestHandlerState) addDecorator(role requestHandlerRole, sym *graph.Symbol) {
	if role.list {
		st.sites = append(st.sites, listSite{kind: role.kind, sym: sym, file: sym.File, line: sym.Line})
		return
	}
	st.dispatch[role.kind] = sym.ID
}

func resolveHandlerArg(g *graph.Graph, idx index, a *graph.Arg) (*graph.Symbol, graph.SymbolID) {
	if a == nil {
		return nil, ""
	}
	id := a.HandlerID
	if id == "" {
		if resolved, ok := idx.resolve(a.Text); ok {
			id = resolved
		}
	}
	if id == "" {
		return nil, ""
	}
	return g.Symbols[id], id
}

// emit appends one graph.Capability per capability the list side's own return value
// declares, now that every setRequestHandler/decorator in the graph has been classified and
// the dispatch side is known. If the list body is dynamic or unresolved, it emits one unresolved
// capability rather than erasing the registration.
func (st *requestHandlerState) emit(g *graph.Graph) {
	for _, site := range st.sites {
		handler := st.dispatch[site.kind]
		if site.sym == nil {
			g.Capabilities = append(g.Capabilities, graph.Capability{
				Kind: site.kind, Form: "request_handler", File: site.file, Line: site.line, Handler: handler,
			})
			continue
		}
		elems := returnArrayElements(site.sym.ReturnText)
		if len(elems) == 0 {
			// return { tools: evilTools }: the list is a constant, here or in an imported module
			if text := listConstant(g, site.sym.File, site.sym.ReturnText); text != "" {
				elems = returnArrayElements(text)
			}
		}
		if len(elems) == 0 {
			g.Capabilities = append(g.Capabilities, graph.Capability{
				Kind: site.kind, Form: "request_handler",
				File: site.sym.File, Line: site.sym.Line, Handler: handler,
			})
			continue
		}
		for _, fields := range elems {
			cap := graph.Capability{
				Kind: site.kind, Form: "request_handler",
				File: site.sym.File, Line: site.sym.Line, Handler: handler,
			}
			if v, ok := literalField(fields, "name"); ok {
				cap.Name, cap.NameResolved = v, true
			}
			if v, ok := literalField(fields, "description"); ok {
				cap.Description, cap.DescriptionResolved = v, true
			}
			g.Capabilities = append(g.Capabilities, cap)
		}
	}
}

// listValueKeys is which object key, in the JS/TS low-level SDK's `return
// { tools: [...] }` shape, holds the array for each capability kind - the
// Python and bare-array forms need no such unwrapping
var listValueKeys = []string{"tools", "prompts", "resources"}

// returnArrayElements reads the top-level elements out of a list handler's return value
// text: a bare array literal (Python's `return [types.Tool(...), ...]`), or a JS/TS object
// literal whose "tools" (or "prompts"/"resources") field holds one. Nil means the shape was not
// statically recognized, allowing the caller to preserve an unresolved fallback.
func returnArrayElements(text string) []map[string]string {
	t := strings.TrimSpace(text)
	items := arrayLiteralElements(t)
	if items == nil {
		if fields := objectLiteralFields(t); fields != nil {
			for _, key := range listValueKeys {
				if v, ok := fields[key]; ok {
					items = arrayLiteralElements(strings.TrimSpace(v))
					break
				}
			}
		}
	}
	if items == nil {
		return nil
	}
	out := make([]map[string]string, 0, len(items))
	for _, item := range items {
		out = append(out, elementFields(item))
	}
	return out
}

// arrayLiteralElements does a minimal, depth-aware scan of a JS/TS/Python
// array or list literal's raw text into its top-level elements' own raw
// text - the array counterpart to objectLiteralFields (match.go)
func arrayLiteralElements(text string) []string {
	if len(text) < 2 || text[0] != '[' || text[len(text)-1] != ']' {
		return nil
	}
	var out []string
	for _, part := range parser.SplitTopLevel(text[1 : len(text)-1]) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// elementFields reads one array element as either a brace object literal
// (JS/TS: `{ name: "x", description: "y" }`) or a keyword-argument
// constructor call (Python: `types.Tool(name="x", description="y")`),
// whichever it turns out to be
func elementFields(text string) map[string]string {
	if fields := objectLiteralFields(text); fields != nil {
		return fields
	}
	return callKeywordFields(text)
}

// callKeywordFields does a minimal, depth-aware scan of a call's raw text
// for its top-level `key=value` keyword arguments - the Python
// constructor-call counterpart to objectLiteralFields, which only reads a
// brace literal
func callKeywordFields(text string) map[string]string {
	open := strings.IndexByte(text, '(')
	if open < 0 || !strings.HasSuffix(text, ")") {
		return nil
	}
	fields := map[string]string{}
	for _, part := range parser.SplitTopLevel(text[open+1 : len(text)-1]) {
		part = strings.TrimSpace(part)
		i := strings.IndexByte(part, '=')
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(part[:i])
		fields[key] = strings.TrimSpace(part[i+1:])
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// listConstant resolves the list a list handler returns by name - `return { tools: evilTools }` or
// `return evilTools` - to the array constant's text, from the handler's own file or from the module
// a relative import of that name points at
func listConstant(g *graph.Graph, file, returnText string) string {
	t := strings.TrimSpace(returnText)
	name := ""
	if isIdentifierText(t) {
		name = t
	} else if fields := objectLiteralFields(t); fields != nil {
		for _, key := range listValueKeys {
			if v, ok := fields[key]; ok {
				name = strings.TrimSpace(v)
				break
			}
		}
	}
	if name == "" || !isIdentifierText(name) || strings.Contains(name, ".") {
		return ""
	}
	f := g.Files[file]
	if f == nil {
		return ""
	}
	if v := f.ObjectConstants[name]; v != "" {
		return v
	}
	for _, imp := range f.Imports {
		if imp.Alias != name || !strings.HasPrefix(imp.Path, ".") {
			continue
		}
		for _, cand := range moduleCandidates(file, imp.Path) {
			if tf := g.Files[cand]; tf != nil {
				if v := tf.ObjectConstants[name]; v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// moduleCandidates lists the files a relative JavaScript/TypeScript import can name: the path as
// written, with its .js extension swapped for TypeScript's, with an extension added, or as a
// directory's index
func moduleCandidates(fromFile, spec string) []string {
	base := path.Join(path.Dir(fromFile), spec)
	stem := base
	for _, ext := range []string{".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"} {
		stem = strings.TrimSuffix(stem, ext)
	}
	var out []string
	for _, ext := range []string{".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx"} {
		out = append(out, stem+ext)
	}
	for _, ext := range []string{".ts", ".js"} {
		out = append(out, path.Join(stem, "index"+ext))
	}
	return append([]string{base}, out...)
}
