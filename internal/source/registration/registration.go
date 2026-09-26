// Package registration finds where MCP tools, prompts and resources are registered, across
// direct SDK calls, decorators/annotations/attributes, a wrapper function that forwards
// into the SDK, and registration inside a loop - working entirely off the graph the parser
// already built, so it never re-reads source. A registration that cannot be fully resolved is
// retained with unresolved flags so coverage records uncertainty instead of dropping it.
package registration

import (
	"slices"
	"sort"

	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/internal/source/parser"
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

	for _, c := range g.Calls {
		if c.IsDecorator {
			// Handled below, through the definition it decorates - not
			// here, or `@mcp.tool()` is found twice: once as the
			// decorator, once as an ordinary call that happens to match
			// the same registration pattern
			continue
		}
		reqHandlers.addCall(g, idx, c)
		kind, ok := classifyCall(c, mcpTree)
		if !ok {
			continue
		}
		roles := classifyArgs(c.Args)
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
		for _, dec := range sym.Decorators {
			if role, ok := classifyRequestHandlerDecorator(dec); ok {
				reqHandlers.addDecorator(role, sym)
				continue
			}
			kind, ok := classifyDecorator(dec)
			if !ok {
				continue
			}
			emitDecorator(g, kind, dec, sym)
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
	if !cap.NameResolved && roles.Name != nil && roles.Name.Literal {
		cap.Name, cap.NameResolved = roles.Name.Value, true
	}
	if !cap.DescriptionResolved && roles.Desc != nil && roles.Desc.Literal {
		cap.Description, cap.DescriptionResolved = roles.Desc.Value, true
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
	if a := argAt(c.Args, t.nameIdx); a != nil && a.Literal {
		cap.Name, cap.NameResolved = a.Value, true
	}
	if a := argAt(c.Args, t.descIdx); a != nil && a.Literal {
		cap.Description, cap.DescriptionResolved = a.Value, true
	}
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

func emitDecorator(g *graph.Graph, kind graph.CapabilityKind, dec string, sym *graph.Symbol) {
	cap := graph.Capability{
		Kind: kind, Form: "decorator", File: sym.File, Line: sym.Line,
		Handler: sym.ID, HandlerText: sym.Name,
	}
	if v, ok := decoratorArg(dec, "name"); ok {
		cap.Name, cap.NameResolved = v, true
	} else if sym.Name != "" && sym.Name != "<anonymous>" {
		// The function's own name is a stronger signal than a decorator's
		// "title" kwarg (Python's @mcp.tool(annotations={"title": ...}) is
		// a cosmetic display label, not the tool's identity), so it is
		// checked first; title only fills in for an anonymous function
		// with no explicit name of its own
		cap.Name, cap.NameResolved = sym.Name, true
	} else if v, ok := decoratorArg(dec, "title"); ok {
		cap.Name, cap.NameResolved = v, true
	}
	if v, ok := decoratorArg(dec, "description"); ok {
		cap.Description, cap.DescriptionResolved = v, true
	} else if sym.Doc != "" {
		cap.Description, cap.DescriptionResolved = sym.Doc, true
	}
	g.Capabilities = append(g.Capabilities, cap)
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
