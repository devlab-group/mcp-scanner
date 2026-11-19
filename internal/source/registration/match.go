package registration

import (
	"path"
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

func normalize(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "_", "")
}

// mcpImportHints matches an import path against the SDKs this scanner
// targets (the Python and TypeScript modelcontextprotocol packages,
// FastMCP, mark3labs/mcp-go), closely enough to tell an MCP server apart
// from an ordinary program without claiming to recognize every SDK that
// exists
var mcpImportHints = []string{"modelcontextprotocol", "mark3labs/mcp-go", "fastmcp"}

// FileImportsMCPSDK reports whether f imports a module this build
// recognizes as an MCP SDK
func FileImportsMCPSDK(f *graph.File) bool {
	if f == nil {
		return false
	}
	for _, imp := range f.Imports {
		path := strings.ToLower(imp.Path)
		if path == "mcp" || strings.HasPrefix(path, "mcp.") || strings.HasPrefix(path, "mcp/") {
			return true
		}
		for _, hint := range mcpImportHints {
			if strings.Contains(path, hint) {
				return true
			}
		}
	}
	return false
}

// TreeImportsMCPSDK reports whether any file in the graph imports a recognized MCP SDK,
// which is what qualifies a bare `.tool(` call anywhere in it as a registration. The check is
// tree-wide because helper modules commonly receive a server object without importing its SDK.
func TreeImportsMCPSDK(g *graph.Graph) bool {
	for _, f := range g.Files {
		if FileImportsMCPSDK(f) {
			return true
		}
	}
	return false
}

func bareRegistration(inMCPTree bool, calleeText string, argc int) bool {
	return (inMCPTree || hasServerishReceiver(calleeText)) && argc >= 2
}

// hasServerishReceiver is a second way in, for a tree that registers on a server object it
// was handed and never imports an SDK itself - a module extracted out of a server, the
// shape most of this repository's own per-language fixtures take. Receiver spelling is only
// an alternative signal, so renaming a variable cannot hide a registration backed by an import.
func hasServerishReceiver(calleeText string) bool {
	lower := strings.ToLower(calleeText)
	for _, hint := range []string{"mcp", "server", "app", "fastmcp", "srv"} {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// callsLocalHelper reports whether c is a receiver-less call - `tool(...)`, not `server.tool(...)` -
// to a function the project defines itself, with no function among its arguments. A test helper
// named tool(bindir, "node", body) would otherwise register a "node" tool at every call site.
//
// parser.Resolve matches on the final identifier alone, so a resolved call through a receiver
// says nothing about which tool method runs; a bare name does. A file that imports that bare name
// from a package (not a relative path) keeps the call, since the import, not the project's own
// definition, may be what the name refers to there. A call that passes a function - inline, or
// one defined in this tree - also keeps it: that is the shape of a hand-rolled registry,
// `tool("read_note", "...", async (args) => ...)`, whose handler must still be analyzed.
func callsLocalHelper(g *graph.Graph, idx index, c graph.Call) bool {
	if !c.Resolved || c.CalleeText != parser.LastSegment(c.CalleeText) {
		return false
	}
	sym := g.Symbols[c.Callee]
	if sym == nil || sym.Name != c.CalleeText {
		return false
	}
	if f := g.Files[c.File]; f != nil {
		for _, imp := range f.Imports {
			local := imp.Alias
			if local == "" {
				local = parser.LastSegment(imp.Path)
			}
			if local == c.CalleeText && !strings.HasPrefix(imp.Path, ".") {
				return false
			}
		}
	}
	if h := classifyArgs(c.Args).Handler; h != nil {
		if h.HandlerID != "" {
			return false
		}
		if _, ok := idx.resolve(h.Text); ok {
			return false
		}
	}
	return true
}

// classifyCall recognizes direct SDK registration calls. Generic lowercase methods require
// registration arity plus either an MCP import anywhere in the tree or a server-like receiver;
// the receiver signal covers helpers handed a server object without importing its SDK.
// localHelper (see callsLocalHelper) rules the generic names out for the project's own functions.
func classifyCall(c graph.Call, inMCPTree, localHelper bool) (graph.CapabilityKind, bool) {
	seg := strings.TrimPrefix(parser.LastSegment(c.CalleeText), "new ")
	switch normalize(seg) {
	case "addtool", "registertool", "newservertool",
		// the Java SDK's new SyncToolSpecification(tool, handler) / AsyncToolSpecification
		"synctoolspecification", "asynctoolspecification":
		return graph.CapabilityTool, true
	case "addprompt", "registerprompt", "syncpromptspecification", "asyncpromptspecification":
		return graph.CapabilityPrompt, true
	case "addresource", "registerresource", "addresourcetemplate", "registerresourcetemplate",
		"syncresourcespecification", "asyncresourcespecification":
		return graph.CapabilityResource, true
	}
	if localHelper || !bareRegistration(inMCPTree, c.CalleeText, len(c.Args)) {
		return "", false
	}
	switch seg {
	case "tool":
		return graph.CapabilityTool, true
	case "prompt":
		return graph.CapabilityPrompt, true
	case "resource":
		return graph.CapabilityResource, true
	}
	return "", false
}

// classifyDecorator reports whether a decorator/annotation/attribute names a tool, prompt
// or resource registration: @mcp.tool(), @Tool, #[tool] and their prompt/resource
// equivalents
func classifyDecorator(dec string) (graph.CapabilityKind, bool) {
	callee := dec
	if before, _, ok := strings.Cut(dec, "("); ok {
		callee = before
	}
	// "#[tool(...)]" and "@Tool(...)" carry the wrapping punctuation in
	// their callee slice; strip it before reducing to the final segment
	switch normalize(parser.LastSegment(strings.Trim(callee, "#[]@ "))) {
	case "tool", "addtool", "registertool":
		return graph.CapabilityTool, true
	case "prompt", "addprompt", "registerprompt":
		return graph.CapabilityPrompt, true
	case "resource", "addresource", "registerresource", "addresourcetemplate", "registerresourcetemplate":
		return graph.CapabilityResource, true
	}
	return "", false
}

// decoratorArg scans raw text for key = "value" or a nested key: "value" entry.
// It may match text inside a string, so it supplies only an anonymous function's
// display title. Names and descriptions use parsed arguments.
func decoratorArg(dec, key string) (string, bool) {
	for idx := strings.Index(dec, key); idx != -1; {
		rest := dec[idx+len(key):]
		rest = strings.TrimLeft(rest, "\"' \t")
		if strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, ":") {
			rest = strings.TrimLeft(rest[1:], " \t")
			if len(rest) > 0 && (rest[0] == '"' || rest[0] == '\'') {
				q := rest[0]
				if end := strings.IndexByte(rest[1:], q); end >= 0 {
					return rest[1 : 1+end], true
				}
			}
		}
		next := strings.Index(dec[idx+len(key):], key)
		if next == -1 {
			break
		}
		idx += len(key) + next
	}
	return "", false
}

// objectLiteralFields does a minimal, depth-aware scan of a JS/TS/Python object or dict
// literal's raw text - "{ title: \"Echo Tool\", description: \"...\", inputSchema: {...} }"
// - for its top-level "key: value" pairs
func objectLiteralFields(text string) map[string]string {
	t := strings.TrimSpace(text)
	if len(t) < 2 || t[0] != '{' || t[len(t)-1] != '}' {
		return nil
	}
	fields := map[string]string{}
	for _, part := range parser.SplitTopLevel(t[1 : len(t)-1]) {
		part = strings.TrimSpace(part)
		i := strings.IndexByte(part, ':')
		if i < 0 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(part[:i]), `"'`)
		fields[key] = strings.TrimSpace(part[i+1:])
	}
	return fields
}

// literalField reads fields[key] as a string literal, unquoting it the
// same way any other literal argument is read
func literalField(fields map[string]string, key string) (string, bool) {
	raw, ok := fields[key]
	if !ok {
		return "", false
	}
	return parser.UnquoteString(raw)
}

// functionalOptionFields does a minimal, text-level scan of a factory call built from Go
// functional options - `mcp.NewTool("status", mcp.WithDescription("..."),
// mcp.WithString("url", mcp.Required()))` - the form mark3labs/mcp-go and similar SDKs
// build a tool descriptor with
func functionalOptionFields(callText string) (name string, nameOK bool, fields map[string]string) {
	open := strings.IndexByte(callText, '(')
	if open < 0 || !strings.HasSuffix(callText, ")") {
		return "", false, nil
	}
	args := parser.SplitTopLevel(callText[open+1 : len(callText)-1])
	if len(args) == 0 {
		return "", false, nil
	}
	if v, ok := parser.UnquoteString(strings.TrimSpace(args[0])); ok {
		name, nameOK = v, true
	}
	fields = map[string]string{}
	for _, opt := range args[1:] {
		opt = strings.TrimSpace(opt)
		oopen := strings.IndexByte(opt, '(')
		if oopen < 0 || !strings.HasSuffix(opt, ")") {
			continue
		}
		role, ok := strings.CutPrefix(parser.LastSegment(opt[:oopen]), "With")
		if !ok || role == "" {
			continue
		}
		optArgs := parser.SplitTopLevel(opt[oopen+1 : len(opt)-1])
		if len(optArgs) == 0 {
			continue
		}
		if v, ok := parser.UnquoteString(strings.TrimSpace(optArgs[0])); ok {
			fields[normalize(role)] = v
		}
	}
	return name, nameOK, fields
}

// Reasons a call shaped like a registration is set aside. Both are facts about the call itself,
// not guesses from names; each skipped call is kept in graph.SkippedRegistrations for review.
const (
	// SkipLibraryModule: the receiver is a third-party Python module bound by a plain
	// `import boto3`, so `boto3.resource("s3")` calls that module's own function
	SkipLibraryModule = "receiver is an imported third-party module, not a server object"
	// SkipNoHandler: every argument is a string literal, so the call supplies no handler and no
	// content - `api.root.add_resource("v1")` in an infrastructure library
	SkipNoHandler = "only string literal arguments: no handler or content to register"
)

func notARegistration(g *graph.Graph, c graph.Call) string {
	if len(c.Args) > 0 {
		allLiteral := true
		for _, a := range c.Args {
			if !a.Literal || a.Keyword != "" {
				allLiteral = false
				break
			}
		}
		if allLiteral {
			return SkipNoHandler
		}
	}
	if strings.HasSuffix(c.File, ".py") {
		root, _, ok := strings.Cut(c.CalleeText, ".")
		if ok && isIdentifierText(root) && importsThirdPartyModule(g, c.File, root) {
			return SkipLibraryModule
		}
	}
	return ""
}

// importsThirdPartyModule reports whether file binds name with a plain `import name` of a top-level
// package that is neither an MCP SDK nor a module of this tree. A plain import of a single name can
// only bind a module; `from app import mcp` binds an object and is recorded as "app.mcp".
func importsThirdPartyModule(g *graph.Graph, file, name string) bool {
	f := g.Files[file]
	if f == nil {
		return false
	}
	found := false
	for _, imp := range f.Imports {
		if imp.Path == name && imp.Alias == "" {
			found = true
		}
		if imp.Alias == name || strings.HasSuffix(imp.Path, "."+name) {
			return false // the same name is also bound some other way
		}
	}
	if !found || FileImportsMCPSDK(&graph.File{Imports: []graph.Import{{Path: name}}}) {
		return false
	}
	for p := range g.Files {
		base := path.Base(p)
		if base == name+".py" || strings.HasPrefix(p, name+"/") || strings.Contains(p, "/"+name+"/") {
			return false
		}
	}
	return true
}

// uriLiteral finds a URI with a scheme inside a quoted literal: "notes://{name}", 'file:///{path}'
var uriLiteral = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^"'\x60\s]*`)

// fixedResourceURI reports whether a registration's arguments spell a fixed resource URI: a
// literal URI with no "{" (no URI-template variable), or a JavaScript template literal whose
// text outside its ${...} substitutions holds a "/" (a scheme or a path) and no "{". A substitution is
// evaluated by the server when it registers the resource, so it is not a client-chosen part.
// Python f-strings are not read: there {BASE} and a template's {id} look the same.
func fixedResourceURI(args []graph.Arg) bool {
	for _, a := range args {
		if a.Literal {
			if m := uriLiteral.FindString(a.Value); m != "" && m == a.Value {
				return !strings.Contains(m, "{")
			}
			continue
		}
		t := strings.TrimSpace(a.Text)
		if len(t) < 2 || t[0] != '`' || t[len(t)-1] != '`' {
			continue
		}
		rest, ok := parser.TemplateWithSubstitutions(t[1:len(t)-1], "")
		if !ok || !strings.Contains(t, "${") {
			continue
		}
		if strings.Contains(rest, "/") { // a scheme or a path
			return !strings.Contains(rest, "{")
		}
	}
	return false
}

// resourceURI returns the first URI a registration's arguments spell, from a string literal or a
// descriptor literal (`&mcp.Resource{URI: "notes://today"}`), or "" when none is literal
func resourceURI(args []graph.Arg) string {
	for _, a := range args {
		if a.Literal {
			if m := uriLiteral.FindString(a.Value); m != "" && m == a.Value {
				return m
			}
			continue
		}
		if m := uriLiteral.FindString(a.Text); m != "" && strings.ContainsAny(a.Text, `"'`+"`") {
			return m
		}
	}
	return ""
}
