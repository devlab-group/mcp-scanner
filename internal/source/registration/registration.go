// Package registration finds where MCP tools, prompts and resources are registered, across
// direct SDK calls, decorators/annotations/attributes, a wrapper function that forwards
// into the SDK, and registration inside a loop - working entirely off the graph the parser
// already built, so it never re-reads source. A registration that cannot be fully resolved is
// retained with unresolved flags so coverage records uncertainty instead of dropping it.
package registration

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// argRoles is which argument plays which part in a registration call, found
// by keyword first and position second
type argRoles struct {
	Name, Desc, Handler *graph.Arg
}

func classifyArgs(args []graph.Arg) argRoles {
	var r argRoles
	var positional []*graph.Arg
	for i := range args {
		a := &args[i]
		switch normalize(a.Keyword) {
		case "name":
			r.Name = a
			continue
		case "description":
			r.Desc = a
			continue
		case "handler", "fn", "callback", "func", "handlerfunc":
			r.Handler = a
			continue
		}
		if a.Keyword == "" {
			positional = append(positional, a)
		}
	}

	// server.tool("name", "description", handler): the first two bare
	// string literals, in order
	var lits []*graph.Arg
	for _, a := range positional {
		if a.Literal {
			lits = append(lits, a)
		}
	}
	if r.Name == nil && len(lits) > 0 {
		r.Name = lits[0]
	}
	if r.Desc == nil && len(lits) > 1 {
		r.Desc = lits[1]
	}

	// add_tool(tool, handler): the last positional argument that reads like
	// a function reference, not a literal or a struct/object literal, is
	// the handler - or, just as validly, is itself an inline function
	// literal (HandlerID set - see graph.Arg), the form
	// `server.tool("x", "y", async (args) => {...})` the MCP SDKs' own
	// examples use, which does not read like an identifier at all
	if r.Handler == nil && len(positional) > 0 {
		if last := positional[len(positional)-1]; last.HandlerID != "" || (!last.Literal && isIdentifierText(last.Text)) {
			r.Handler = last
		}
	}

	// A tool descriptor built by a factory call, `add_tool(newTool(), h)`,
	// sits in the first positional slot; it is the name role even before
	// its literal value is known
	if r.Name == nil && len(positional) > 0 {
		if first := positional[0]; first != r.Handler && looksLikeCall(first.Text) {
			r.Name = first
		}
	}

	// server.tool(name, description, fn) forwarded through a wrapper: none
	// of the three are literals (they are the wrapper's own parameters),
	// so nothing above claimed them. The convention is positional either
	// way - name first, description second - so the same slots apply even
	// before their values are known.
	if r.Name == nil && len(positional) > 0 && positional[0] != r.Handler {
		r.Name = positional[0]
	}
	if r.Desc == nil && len(positional) > 1 && positional[1] != r.Handler {
		r.Desc = positional[1]
	}

	// registerTool(name, { title, description, inputSchema }, handler) - the current TypeScript
	// SDK's primary registration form - puts the description role in a config-object argument
	// rather than a bare string literal, so none of the rules above resolved it
	if r.Desc != nil && !r.Desc.Literal {
		if fields := objectLiteralFields(r.Desc.Text); fields != nil {
			if v, ok := literalField(fields, "description"); ok {
				r.Desc = &graph.Arg{Text: r.Desc.Text, Literal: true, Value: v, Keyword: "description"}
			}
			// Guarded to !looksLikeCall so this never preempts the
			// factory-return resolution above, which needs r.Name left
			// as the unresolved call text to find the literal it
			// returns
			if r.Name == nil || (!r.Name.Literal && !looksLikeCall(r.Name.Text)) {
				if v, ok := literalField(fields, "title"); ok {
					r.Name = &graph.Arg{Text: r.Desc.Text, Literal: true, Value: v, Keyword: "title"}
				}
			}
		}
	}
	return r
}

func isIdentifierText(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

func looksLikeCall(s string) bool {
	return len(s) > 0 && s[len(s)-1] == ')'
}

// index resolves a bare or dotted name reference to the one symbol in the
// graph with that name, the same flat, receiver-blind strategy the call
// graph itself resolves with: unambiguous by name is resolved, anything
// else is left alone rather than guessed at
type index map[string][]graph.SymbolID

func buildIndex(g *graph.Graph) index {
	idx := index{}
	for id, sym := range g.Symbols {
		idx[sym.Name] = append(idx[sym.Name], id)
	}
	return idx
}

func (idx index) resolve(text string) (graph.SymbolID, bool) {
	cands := idx[parser.LastSegment(text)]
	if len(cands) == 1 {
		return cands[0], true
	}
	return "", false
}

// template is a wrapper function's forwarding shape: which of its own
// parameters ends up as the SDK call's name, description and handler.
// Index -1 means that role was not a forwarded parameter.
type template struct {
	kind                         graph.CapabilityKind
	nameIdx, descIdx, handlerIdx int
	innerCall                    graph.Call
}

func asTemplate(kind graph.CapabilityKind, roles argRoles, sym *graph.Symbol) (template, bool) {
	t := template{kind: kind, nameIdx: -1, descIdx: -1, handlerIdx: -1}
	if roles.Name == nil || roles.Name.Literal {
		return t, false
	}
	idx, ok := paramIndex(sym, roles.Name.Text)
	if !ok {
		return t, false
	}
	t.nameIdx = idx
	if roles.Desc != nil && !roles.Desc.Literal {
		if di, ok := paramIndex(sym, roles.Desc.Text); ok {
			t.descIdx = di
		}
	}
	if roles.Handler != nil {
		if hi, ok := paramIndex(sym, roles.Handler.Text); ok {
			t.handlerIdx = hi
		}
	}
	return t, true
}

func paramIndex(sym *graph.Symbol, name string) (int, bool) {
	i := slices.Index(sym.Params, name)
	return i, i >= 0
}

func argAt(args []graph.Arg, i int) *graph.Arg {
	if i < 0 || i >= len(args) {
		return nil
	}
	return &args[i]
}

// Discover finds every tool, prompt and resource registration reachable
// from the graph's calls, decorators and annotations, and appends them to
// g.Capabilities
func Discover(g *graph.Graph) {
	idx := buildIndex(g)
	mcpTree := TreeImportsMCPSDK(g)
	templates := map[graph.SymbolID]template{}
	reqHandlers := newRequestHandlerState()

	// mcp.tool()(fn) and mcp.tool(name="x")(fn): a decorator applied by a plain call. The inner
	// mcp.tool(...) call on the same line is part of the same registration and is skipped below.
	decoratorCalls := map[string]bool{}
	for _, c := range g.Calls {
		if kind, inner, ok := decoratorCall(c, mcpTree); ok {
			decoratorCalls[fmt.Sprintf("%s:%d:%s", c.File, c.Line, inner)] = true
			emitDecoratorCall(g, idx, kind, c)
		}
	}

	for _, c := range g.Calls {
		if c.IsDecorator {
			// Handled below, through the definition it decorates - not
			// here, or `@mcp.tool()` is found twice: once as the
			// decorator, once as an ordinary call that happens to match
			// the same registration pattern
			continue
		}
		if decoratorCalls[fmt.Sprintf("%s:%d:%s", c.File, c.Line, c.CalleeText)] {
			continue
		}
		if _, _, ok := decoratorCall(c, mcpTree); ok {
			continue
		}
		reqHandlers.addCall(g, idx, c)
		kind, ok := classifyCall(c, mcpTree, callsLocalHelper(g, idx, c))
		if !ok {
			continue
		}
		roles := classifyArgs(c.Args)
		if normalize(parser.LastSegment(c.CalleeText)) == "newservertool" && len(c.Args) >= 3 {
			// The Go SDK's mcp.NewServerTool(name, description, handler, options...): the handler is
			// the third argument, not the last
			roles.Handler = &c.Args[2]
		}
		if c.Caller != "" {
			if sym := g.Symbols[c.Caller]; sym != nil {
				if t, isTemplate := asTemplate(kind, roles, sym); isTemplate {
					t.innerCall = c
					templates[c.Caller] = t
					continue
				}
			}
		}
		emitDirect(g, idx, kind, c, roles)
	}

	called := map[graph.SymbolID]bool{}
	for _, c := range g.Calls {
		if !c.Resolved {
			continue
		}
		t, ok := templates[c.Callee]
		if !ok {
			continue
		}
		called[c.Callee] = true
		emitWrapper(g, idx, t, c)
	}
	// A wrapper nobody calls through a resolved call is still a real
	// registration the source discovered; record it once, unresolved,
	// rather than dropping it because no call site was found
	for id, t := range templates {
		if called[id] {
			continue
		}
		emitDirect(g, idx, t.kind, t.innerCall, classifyArgs(t.innerCall.Args))
	}

	for _, sym := range g.Symbols {
		for i, dec := range sym.Decorators {
			if role, ok := classifyRequestHandlerDecorator(dec); ok {
				reqHandlers.addDecorator(role, sym)
				continue
			}
			kind, ok := classifyDecorator(dec)
			if !ok {
				continue
			}
			var args []graph.Arg
			if i < len(sym.DecoratorArgs) {
				args = sym.DecoratorArgs[i]
			}
			emitDecorator(g, kind, dec, args, sym)
		}
	}

	reqHandlers.emit(g)

	sort.SliceStable(g.Capabilities, func(i, j int) bool {
		a, b := g.Capabilities[i], g.Capabilities[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

func emitDirect(g *graph.Graph, idx index, kind graph.CapabilityKind, c graph.Call, roles argRoles) {
	form := "direct"
	if c.InLoop {
		form = "loop"
	}
	cap := graph.Capability{Kind: kind, Form: form, File: c.File, Line: c.Line}

	// A factory: the name argument is itself a call to an in-repo function
	// whose body is `return <literal>` - read the literal it returns
	if roles.Name != nil && !roles.Name.Literal && looksLikeCall(roles.Name.Text) {
		if lit := factoryReturn(g, idx, roles.Name.Text); lit != nil {
			cap.Form = "factory"
			applyLiteral(&cap, lit)
		} else if name, nameOK, fields := functionalOptionFields(roles.Name.Text); nameOK || len(fields) > 0 {
			// The factory call did not resolve in-repo - mcp.NewTool lives
			// in a dependency - but its own text still carries the tool's
			// name and any With<Role>(...) options, the way
			// mark3labs/mcp-go and the functional-options convention it
			// follows build a tool descriptor
			cap.Form = "factory"
			if nameOK {
				cap.Name, cap.NameResolved = name, true
			}
			if v, ok := fields["description"]; ok {
				cap.Description, cap.DescriptionResolved = v, true
			}
			if !cap.NameResolved {
				if v, ok := fields["title"]; ok {
					cap.Name, cap.NameResolved = v, true
				}
			}
		}
	}
	if !cap.NameResolved {
		cap.Name, cap.NameResolved = argValue(g, c.File, roles.Name)
	}
	if !cap.DescriptionResolved {
		cap.Description, cap.DescriptionResolved = argValue(g, c.File, roles.Desc)
	}
	// registerTool(name, config, handler) with `const config = { title, description }` declared in
	// the same file: the config-object rule in classifyArgs only sees an inline object literal
	if roles.Desc != nil && !roles.Desc.Literal && isIdentifierText(roles.Desc.Text) {
		if f := g.Files[c.File]; f != nil {
			if fields := objectLiteralFields(f.ObjectConstants[roles.Desc.Text]); fields != nil {
				if !cap.DescriptionResolved {
					if v, ok := literalField(fields, "description"); ok {
						cap.Description, cap.DescriptionResolved = v, true
					}
				}
				if !cap.NameResolved && (roles.Name == nil || roles.Name == roles.Desc) {
					if v, ok := literalField(fields, "title"); ok {
						cap.Name, cap.NameResolved = v, true
					}
				}
			}
		}
	}
	if roles.Handler != nil {
		cap.HandlerText = roles.Handler.Text
		if roles.Handler.HandlerID != "" {
			cap.Handler = roles.Handler.HandlerID
		} else if id, ok := idx.resolve(roles.Handler.Text); ok {
			cap.Handler = id
		}
	}
	g.Capabilities = append(g.Capabilities, cap)
}

func emitWrapper(g *graph.Graph, idx index, t template, c graph.Call) {
	cap := graph.Capability{Kind: t.kind, Form: "wrapper", File: c.File, Line: c.Line}
	cap.Name, cap.NameResolved = argValue(g, c.File, argAt(c.Args, t.nameIdx))
	cap.Description, cap.DescriptionResolved = argValue(g, c.File, argAt(c.Args, t.descIdx))
	if a := argAt(c.Args, t.handlerIdx); a != nil {
		cap.HandlerText = a.Text
		if a.HandlerID != "" {
			cap.Handler = a.HandlerID
		} else if id, ok := idx.resolve(a.Text); ok {
			cap.Handler = id
		}
	}
	g.Capabilities = append(g.Capabilities, cap)
}

func emitDecorator(g *graph.Graph, kind graph.CapabilityKind, dec string, args []graph.Arg, sym *graph.Symbol) {
	cap := graph.Capability{
		Kind: kind, Form: "decorator", File: sym.File, Line: sym.Line,
		Handler: sym.ID, HandlerText: sym.Name,
	}
	var lang language.ID
	if f := g.Files[sym.File]; f != nil {
		lang = language.ID(f.Language)
	}

	// Use a fixed argument when available. Fall back to the function's name or docstring
	// only for absent, empty or None arguments; an unreadable argument must stay unresolved.
	if v, given, ok := decoratorValue(g, sym.File, decoratorName(args, kind, lang)); ok {
		cap.Name, cap.NameResolved = v, true
	} else if !given {
		if sym.Name != "" && sym.Name != "<anonymous>" {
			// A title is a display label, so prefer the function's name for tool identity;
			// use the title only for anonymous functions
			cap.Name, cap.NameResolved = sym.Name, true
		} else if v, ok := decoratorArg(dec, "title"); ok {
			cap.Name, cap.NameResolved = v, true
		}
	}

	if v, given, ok := decoratorValue(g, sym.File, decoratorDescription(args, kind, lang)); ok {
		cap.Description, cap.DescriptionResolved = v, true
	} else if !given && sym.Doc != "" {
		cap.Description, cap.DescriptionResolved = sym.Doc, true
	} else if !given && lang == language.Python {
		// Python without a docstring has a known empty description. Rust doc comments and
		// Java framework fallbacks are not read here, so those descriptions stay unresolved.
		cap.DescriptionResolved = true
	}
	g.Capabilities = append(g.Capabilities, cap)
}

// decoratorValue returns ok for a fixed non-empty string. given is false for
// absent, empty or None arguments, and true for other values, including those
// static analysis cannot resolve.
func decoratorValue(g *graph.Graph, file string, a *graph.Arg) (v string, given, ok bool) {
	if a == nil {
		return "", false, false
	}
	v, ok = argValue(g, file, a)
	switch {
	case ok && v != "":
		return v, true, true
	case ok, a.Text == "None":
		return "", false, false
	}
	return "", true, false
}

// decoratorName selects the name keyword or the first positional argument of a
// Python tool or prompt. A Python resource's first positional argument is its URI.
func decoratorName(args []graph.Arg, kind graph.CapabilityKind, lang language.ID) *graph.Arg {
	if a := keywordOrSplat(args, "name"); a != nil {
		return a
	}
	if pos := positionalArgs(args); lang == language.Python && kind != graph.CapabilityResource && len(pos) > 0 {
		return pos[0]
	}
	return nil
}

// decoratorDescription selects the description keyword, the third positional
// argument of a Python tool or prompt, or the value of a Java @Tool annotation
// used by LangChain4j
func decoratorDescription(args []graph.Arg, kind graph.CapabilityKind, lang language.ID) *graph.Arg {
	if a := keywordOrSplat(args, "description"); a != nil {
		return a
	}
	pos := positionalArgs(args)
	switch {
	case lang == language.Python && kind != graph.CapabilityResource && len(pos) >= 3:
		return pos[2]
	case lang == language.Java && kind == graph.CapabilityTool:
		if a := keywordArg(args, "value"); a != nil {
			return a
		}
		if len(pos) > 0 {
			return pos[0]
		}
	}
	return nil
}

// keywordOrSplat finds key or an unpacked *args or **options that could supply
// it with a value static analysis cannot resolve
func keywordOrSplat(args []graph.Arg, key string) *graph.Arg {
	if a := keywordArg(args, key); a != nil {
		return a
	}
	for i := range args {
		if args[i].Keyword == "" && strings.HasPrefix(args[i].Text, "*") {
			return &args[i]
		}
	}
	return nil
}

func positionalArgs(args []graph.Arg) []*graph.Arg {
	var out []*graph.Arg
	for i := range args {
		if args[i].Keyword == "" && !strings.HasPrefix(args[i].Text, "*") {
			out = append(out, &args[i])
		}
	}
	return out
}

func keywordArg(args []graph.Arg, key string) *graph.Arg {
	for i := range args {
		if normalize(args[i].Keyword) == key {
			return &args[i]
		}
	}
	return nil
}

// argValue resolves a literal or a name in the file's string constant map
func argValue(g *graph.Graph, file string, a *graph.Arg) (string, bool) {
	if a == nil {
		return "", false
	}
	if a.Literal {
		return a.Value, true
	}
	if f := g.Files[file]; f != nil {
		v, ok := f.Constants[a.Text]
		return v, ok
	}
	return "", false
}

func applyLiteral(cap *graph.Capability, lit []graph.Arg) {
	for _, a := range lit {
		switch normalize(a.Keyword) {
		case "name":
			if a.Literal {
				cap.Name, cap.NameResolved = a.Value, true
			}
		case "description":
			if a.Literal {
				cap.Description, cap.DescriptionResolved = a.Value, true
			}
		}
	}
}

func factoryReturn(g *graph.Graph, idx index, callText string) []graph.Arg {
	name := callText
	for i, r := range name {
		if r == '(' {
			name = name[:i]
			break
		}
	}
	id, ok := idx.resolve(name)
	if !ok {
		return nil
	}
	sym := g.Symbols[id]
	if sym == nil || len(sym.ReturnLiteral) == 0 {
		return nil
	}
	return sym.ReturnLiteral
}

// decoratorCall recognizes a registration decorator applied by a plain call: mcp.tool()(fn) or
// mcp.tool(name="x", description="...")(fn). It returns the kind and the inner call's callee text.
func decoratorCall(c graph.Call, inMCPTree bool) (graph.CapabilityKind, string, bool) {
	t := strings.TrimSpace(c.CalleeText)
	if !inMCPTree || !strings.HasSuffix(t, ")") || len(c.Args) != 1 || !isIdentifierText(c.Args[0].Text) {
		return "", "", false
	}
	open := strings.IndexByte(t, '(')
	if open <= 0 {
		return "", "", false
	}
	inner := t[:open]
	if !strings.Contains(inner, ".") {
		return "", "", false
	}
	switch parser.LastSegment(inner) {
	case "tool":
		return graph.CapabilityTool, inner, true
	case "prompt":
		return graph.CapabilityPrompt, inner, true
	case "resource":
		return graph.CapabilityResource, inner, true
	}
	return "", "", false
}

// emitDecoratorCall records mcp.tool(...)(fn): the name and description come from the inner
// call's arguments when given, otherwise from the function's own name and docstring, as with the
// @mcp.tool() decorator
func emitDecoratorCall(g *graph.Graph, idx index, kind graph.CapabilityKind, c graph.Call) {
	cap := graph.Capability{Kind: kind, Form: "decorator_call", File: c.File, Line: c.Line, HandlerText: c.Args[0].Text}
	var sym *graph.Symbol
	if id, ok := idx.resolve(c.Args[0].Text); ok {
		cap.Handler = id
		sym = g.Symbols[id]
	}
	if v, ok := decoratorArg(c.CalleeText, "name"); ok {
		cap.Name, cap.NameResolved = v, true
	} else if sym != nil {
		cap.Name, cap.NameResolved = sym.Name, true
	}
	if v, ok := decoratorArg(c.CalleeText, "description"); ok {
		cap.Description, cap.DescriptionResolved = v, true
	} else if sym != nil && sym.Doc != "" {
		cap.Description, cap.DescriptionResolved = sym.Doc, true
	}
	g.Capabilities = append(g.Capabilities, cap)
}
