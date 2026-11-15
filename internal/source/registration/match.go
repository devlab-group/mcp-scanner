package registration

import (
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
	seg := parser.LastSegment(c.CalleeText)
	switch normalize(seg) {
	case "addtool", "registertool":
		return graph.CapabilityTool, true
	case "addprompt", "registerprompt":
		return graph.CapabilityPrompt, true
	case "addresource", "registerresource", "addresourcetemplate", "registerresourcetemplate":
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
