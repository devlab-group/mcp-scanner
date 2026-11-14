package taint

import (
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// The SSRF check follows tainted URLs and clears taint for fixed destination hosts.
// Request bodies and client receivers do not supply the destination URL.

// sinkArg selects the argument at a sink's fixed position. SSRF also accepts
// Python's url= keyword and excludes keywords from positional URL slots.
func sinkArg(args []graph.Arg, idx int, category string) (graph.Arg, bool) {
	if category == "ssrf" {
		for _, a := range args {
			if a.Keyword == "url" {
				return a, true
			}
		}
		if idx < len(args) && args[idx].Keyword == "" {
			return args[idx], true
		}
		return graph.Arg{}, false
	}
	if idx < len(args) {
		return args[idx], true
	}
	return graph.Arg{}, false
}

// argNode finds an argument's value node, unwrapping Python keyword arguments.
// Matching source text avoids index changes from goArgs' flattened composite
// literals and sinkValueArg's wrapper removal.
func argNode(call *sitter.Node, a graph.Arg, src []byte) *sitter.Node {
	list := call.ChildByFieldName("arguments")
	if list == nil {
		return nil
	}
	for i := range list.NamedChildCount() {
		ch := list.NamedChild(i)
		if ch != nil && ch.Kind() == "keyword_argument" {
			ch = ch.ChildByFieldName("value")
		}
		if ch != nil && ch.Utf8Text(src) == a.Text {
			return ch
		}
	}
	return nil
}

// hostFixed reports whether n has a fixed URL prefix that closes the host
// before computed text begins
func (c *ctx) hostFixed(pf *parsedFile, file string, n *sitter.Node) bool {
	if n == nil {
		return false
	}
	prefix, _ := c.urlPrefix(pf, file, unwrapAwait(n))
	return fixesURLHost(prefix)
}

func ssrfCleared(info taintInfo, fixedHost bool) taintInfo {
	if fixedHost {
		return info.clearFor("ssrf")
	}
	return info
}

// fixesURLHost requires a scheme and non-empty authority followed by /, ? or #.
// Without that delimiter, appending @evil.example or .evil.example could change
// the destination host.
func fixesURLHost(prefix string) bool {
	scheme, rest, ok := strings.Cut(prefix, "://")
	if !ok || !isURLScheme(scheme) {
		return false
	}
	end := strings.IndexAny(rest, "/?#")
	if end <= 0 {
		return false
	}
	// Reject ambiguous backslashes, percent escapes and whitespace in the authority
	return !strings.ContainsAny(rest[:end], "\\% \t\r\n")
}

func isURLScheme(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.'):
		default:
			return false
		}
	}
	return true
}

// urlPrefix returns n's known string prefix and whether it is the whole value.
// It recognizes literals, concatenation, f-strings, template strings, printf,
// str.format and same-file constants. Other forms stop the known prefix.
func (c *ctx) urlPrefix(pf *parsedFile, file string, n *sitter.Node) (string, bool) {
	// Unwrap parentheses once per level to avoid repeated LiteralValue walks of the same nesting
	if k := n.Kind(); (k == "parenthesized_expression" || k == "expression_list") && n.NamedChildCount() == 1 {
		return c.urlPrefix(pf, file, n.NamedChild(0))
	}
	if v, ok := parser.LiteralValue(n, pf.src); ok {
		return v, true
	}
	switch n.Kind() {
	case "identifier":
		if f := c.g.Files[file]; f != nil {
			if v, ok := f.Constants[n.Utf8Text(pf.src)]; ok {
				return v, true
			}
		}
	case "binary_operator", "binary_expression":
		left, op, right := n.ChildByFieldName("left"), n.ChildByFieldName("operator"), n.ChildByFieldName("right")
		if left == nil || op == nil || right == nil {
			break
		}
		switch op.Utf8Text(pf.src) {
		case "+":
			lp, whole := c.urlPrefix(pf, file, left)
			if !whole {
				return lp, false
			}
			rp, rwhole := c.urlPrefix(pf, file, right)
			return lp + rp, rwhole
		case "%":
			if v, ok := parser.LiteralValue(left, pf.src); ok {
				return upTo(v, "%"), false
			}
		}
	case "string", "template_string":
		return c.interpolatedPrefix(pf, file, n), false
	case "concatenated_string":
		var b strings.Builder
		for i := range n.NamedChildCount() {
			p, whole := c.urlPrefix(pf, file, n.NamedChild(i))
			b.WriteString(p)
			if !whole {
				return b.String(), false
			}
		}
		return b.String(), true
	}
	if slices.Contains(pf.adapter.Grammar.CallKinds, n.Kind()) {
		return templatePrefix(n, pf.src), false
	}
	return "", false
}

// interpolatedPrefix reads literal text up to the first unresolved interpolation.
// An interpolation with a known constant value extends the fixed prefix.
func (c *ctx) interpolatedPrefix(pf *parsedFile, file string, n *sitter.Node) string {
	var b strings.Builder
	for i := range n.ChildCount() {
		ch := n.Child(i)
		switch ch.Kind() {
		case "string_start", "string_end", "`":
		case "string_content", "string_fragment":
			t := ch.Utf8Text(pf.src)
			// Stop before escapes or doubled braces because their decoded text differs
			if j := strings.IndexAny(t, "\\{}"); j >= 0 {
				b.WriteString(t[:j])
				return b.String()
			}
			b.WriteString(t)
		case "interpolation":
			// Extra children indicate a conversion or format specifier
			e := ch.ChildByFieldName("expression")
			if e == nil || ch.NamedChildCount() != 1 {
				return b.String()
			}
			v, whole := c.urlPrefix(pf, file, e)
			b.WriteString(v)
			if !whole {
				return b.String()
			}
		default:
			return b.String()
		}
	}
	return b.String()
}

// templatePrefix reads Python's "...".format(...) and Go's fmt.Sprintf("...", ...)
// up to the first placeholder
func templatePrefix(call *sitter.Node, src []byte) string {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	switch fn.Kind() {
	case "attribute":
		obj, attr := fn.ChildByFieldName("object"), fn.ChildByFieldName("attribute")
		if obj != nil && attr != nil && attr.Utf8Text(src) == "format" {
			if v, ok := parser.LiteralValue(obj, src); ok {
				return upTo(v, "{")
			}
		}
	case "selector_expression":
		list := call.ChildByFieldName("arguments")
		if fn.Utf8Text(src) == "fmt.Sprintf" && list != nil && list.NamedChildCount() > 0 {
			if v, ok := parser.LiteralValue(list.NamedChild(0), src); ok {
				return upTo(v, "%")
			}
		}
	}
	return ""
}

func upTo(s, sep string) string {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i]
	}
	return s
}

// clientConstructors lists names treated as HTTP client constructors when
// reached through a module in httpClientImports or an import from one
var clientConstructors = map[string]bool{
	"Client": true, "AsyncClient": true, "Session": true, "session": true, "ClientSession": true, "create": true,
}

// httpModuleNames collects candidate names from HTTP client imports, including
// module names, aliases and imported members. Imports do not identify which
// candidate is bound, so the lookup includes each possibility.
func (c *ctx) httpModuleNames(file string) map[string]bool {
	f := c.g.Files[file]
	if f == nil {
		return nil
	}
	names := map[string]bool{}
	for _, imp := range f.Imports {
		for _, m := range httpClientImports {
			if imp.Path != m && !strings.HasPrefix(imp.Path, m+".") {
				continue
			}
			names[m] = true
			names[parser.LastSegment(imp.Path)] = true
			if imp.Alias != "" {
				names[imp.Alias] = true
			}
		}
	}
	return names
}

// httpClientReceiver recognizes an HTTP module, an inline client constructor,
// or a client assigned in the same file. Clients supplied by another file,
// parameter or factory are not recognized.
func (c *ctx) httpClientReceiver(pf *parsedFile, file string, r parser.Receiver) bool {
	names := c.httpModuleNames(file)
	if len(names) == 0 {
		return false
	}
	if r.CallText != "" {
		return isClientConstructor(r.CallText, names)
	}
	t := strings.TrimSpace(r.Text)
	return names[t] || c.httpClientBindings(pf, file, names)[bindingKey(t)]
}

// isClientConstructor matches a constructor through an HTTP module name,
// as in httpx.AsyncClient, or a directly imported name such as AsyncClient
func isClientConstructor(callee string, names map[string]bool) bool {
	segs := strings.Split(strings.Join(strings.Fields(callee), ""), ".")
	last := segs[len(segs)-1]
	if !clientConstructors[last] {
		return false
	}
	switch len(segs) {
	case 1:
		return names[last]
	case 2:
		return names[segs[0]]
	}
	return false
}

// bindingKey removes self., this. or cls. so receiver fields can match
// bindings recorded without those prefixes
func bindingKey(text string) string {
	for _, p := range []string{"self.", "this.", "cls."} {
		if rest, ok := strings.CutPrefix(text, p); ok {
			return rest
		}
	}
	return text
}

// httpClientBindings collects same-file client assignments, including ordinary
// variables, class fields, Python with aliases, and require("axios") bindings
func (c *ctx) httpClientBindings(pf *parsedFile, file string, names map[string]bool) map[string]bool {
	if b, ok := c.clientBindings[file]; ok {
		return b
	}
	bound := map[string]bool{}
	bind := func(target, value *sitter.Node) {
		if target == nil || value == nil {
			return
		}
		value = unwrapAwait(value)
		if !slices.Contains(pf.adapter.Grammar.CallKinds, value.Kind()) {
			return
		}
		callee, _, args := parser.CalleeAndArgs(pf.adapter.ID, value, pf.src)
		required := callee == "require" && len(args) == 1 && args[0].Literal && slices.Contains(httpClientImports, args[0].Value)
		if required || isClientConstructor(callee, names) {
			bound[bindingKey(target.Utf8Text(pf.src))] = true
		}
	}
	stack := []*sitter.Node{pf.root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch n.Kind() {
		case "assignment", "assignment_expression":
			bind(n.ChildByFieldName("left"), n.ChildByFieldName("right"))
		case "variable_declarator":
			bind(n.ChildByFieldName("name"), n.ChildByFieldName("value"))
		case "field_definition":
			bind(n.ChildByFieldName("property"), n.ChildByFieldName("value"))
		case "public_field_definition":
			bind(n.ChildByFieldName("name"), n.ChildByFieldName("value"))
		case "as_pattern":
			if alias := n.ChildByFieldName("alias"); alias != nil && n.NamedChildCount() > 0 {
				bind(alias, n.NamedChild(0))
			}
		}
		for i := range n.NamedChildCount() {
			stack = append(stack, n.NamedChild(i))
		}
	}
	if c.clientBindings == nil {
		c.clientBindings = map[string]map[string]bool{}
	}
	c.clientBindings[file] = bound
	return bound
}
