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

// urlHostFixed reports whether a URL expression keeps the request on a host the MCP client does
// not choose: a fixed prefix that closes the host, an untainted base followed by a path, a relative
// path, or a helper that returns one. It looks through new URL(x), which parses x and changes
// nothing about its host, and new URL(path, base), where the base decides the host only when the
// path is relative: an absolute first argument replaces the base.
func (c *ctx) urlHostFixed(pf *parsedFile, file string, n *sitter.Node, tainted map[string]taintInfo) bool {
	if n == nil {
		return false
	}
	n = unwrapAwait(n)
	if _, ok := parser.LiteralValue(n, pf.src); ok {
		// a string literal is the server's own constant
		return true
	}
	if branches, ok := conditionalBranches(n); ok {
		// ns ? `/api/collection?namespace=${ns}` : "/api/collection": the URL is one of the
		// branches, so it keeps its host when each of them does
		for _, br := range branches {
			if !c.urlHostFixed(pf, file, br, tainted) {
				return false
			}
		}
		return true
	}
	if inner, base, ok := newURLArgs(pf, n); ok {
		if base == nil {
			return c.urlHostFixed(pf, file, inner, tainted)
		}
		if !relativePathURL(pf, inner) {
			return false
		}
		if c.hostFixed(pf, file, base) {
			return true
		}
		info, found := propagatedTaint(base.Utf8Text(pf.src), tainted)
		return !found || !fromMCPInput(info)
	}
	return c.hostFixed(pf, file, n) || untaintedBaseThenPath(pf, n, tainted) || relativePathURL(pf, n) || c.helperRelativePath(pf, n)
}

// newURLArgs returns the arguments of a JavaScript new URL(input) or new URL(input, base)
func newURLArgs(pf *parsedFile, n *sitter.Node) (input, base *sitter.Node, ok bool) {
	if n.Kind() != "new_expression" {
		return nil, nil, false
	}
	ctor := n.ChildByFieldName("constructor")
	if ctor == nil {
		return nil, nil, false
	}
	switch ctor.Utf8Text(pf.src) {
	case "URL", "globalThis.URL", "url.URL":
	default:
		return nil, nil, false
	}
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return nil, nil, false
	}
	var as []*sitter.Node
	for i := range args.NamedChildCount() {
		if a := args.NamedChild(i); a != nil && a.Kind() != "comment" {
			as = append(as, a)
		}
	}
	switch len(as) {
	case 1:
		return as[0], nil, true
	case 2:
		return as[0], as[1], true
	}
	return nil, nil, false
}

func ssrfCleared(info taintInfo, fixedHost bool) taintInfo {
	if fixedHost {
		return info.clearFor("ssrf")
	}
	return info
}

// untaintedBaseThenPath reports whether a URL expression starts with an expression that carries no
// taint and is immediately followed by literal text beginning with "/": f"{endpoint}/tasks/{id}",
// `${base}/v1/${id}`, base + "/items/" + id, fmt.Sprintf("%s/items/%s", base, id). After that "/"
// the URL is in its path, so later text cannot move it to another host. This assumes the base holds
// a scheme and host, as a configured endpoint does; a base that is only "https://" would be wrong,
// and is rare enough that the gain outweighs it.
func untaintedBaseThenPath(pf *parsedFile, n *sitter.Node, tainted map[string]taintInfo) bool {
	if n == nil {
		return false
	}
	n = unwrapAwait(n)
	src := pf.src
	clean := func(e *sitter.Node) bool {
		if e == nil {
			return false
		}
		switch e.Kind() {
		case "identifier", "attribute", "member_expression", "selector_expression", "field_expression", "subscript_expression", "subscript":
		case "call_expression", "call":
			// getRefUrl() + "/read?url=" + ..., strings.TrimRight(base, "/") + "/" + ...: a call
			// handed only literals and names that carry no MCP input returns a configured or
			// constant base. Arguments that are themselves calls or other expressions are not read.
			args := e.ChildByFieldName("arguments")
			if args == nil {
				return false
			}
			for i := range args.NamedChildCount() {
				a := args.NamedChild(i)
				if a == nil || a.Kind() == "comment" {
					continue
				}
				if _, lit := parser.LiteralValue(a, src); lit {
					continue
				}
				switch a.Kind() {
				case "identifier", "attribute", "member_expression", "selector_expression", "field_expression":
				default:
					return false
				}
			}
		default:
			return false
		}
		// An operator-set base - a configured endpoint read from the environment - still fixes
		// the host; only a base the MCP client controls does not
		info, found := propagatedTaint(e.Utf8Text(src), tainted)
		return !found || !fromMCPInput(info)
	}
	// "/" starts the path; "?" and "#" end the authority just the same
	startsWithSlash := func(t string) bool { return t != "" && strings.ContainsRune("/?#", rune(t[0])) }
	switch n.Kind() {
	case "template_string", "string":
		// first meaningful child must be an interpolation, the next a fragment starting with "/"
		var parts []*sitter.Node
		for i := range n.ChildCount() {
			ch := n.Child(i)
			switch ch.Kind() {
			case "string_start", "string_end", "`":
				continue
			}
			parts = append(parts, ch)
			if len(parts) == 2 {
				break
			}
		}
		if len(parts) < 2 {
			return false
		}
		var expr *sitter.Node
		switch parts[0].Kind() {
		case "template_substitution":
			expr = parts[0].NamedChild(0)
		case "interpolation":
			if parts[0].NamedChildCount() != 1 {
				return false
			}
			expr = parts[0].ChildByFieldName("expression")
		default:
			return false
		}
		k := parts[1].Kind()
		return (k == "string_fragment" || k == "string_content") && startsWithSlash(parts[1].Utf8Text(src)) && clean(expr)
	case "binary_operator", "binary_expression":
		// Descend to the innermost left "+": its left operand starts the URL, its right operand is
		// the text right after that start
		inner := n
		for {
			if op := inner.ChildByFieldName("operator"); op == nil || op.Utf8Text(src) != "+" {
				return false
			}
			l := inner.ChildByFieldName("left")
			if l == nil {
				return false
			}
			if l.Kind() != "binary_operator" && l.Kind() != "binary_expression" {
				break
			}
			inner = l
		}
		right := inner.ChildByFieldName("right")
		if right == nil {
			return false
		}
		v, ok := parser.LiteralValue(right, src)
		return ok && startsWithSlash(v) && clean(inner.ChildByFieldName("left"))
	}
	if slices.Contains(pf.adapter.Grammar.CallKinds, n.Kind()) {
		callee, _, args := parser.CalleeAndArgs(pf.adapter.ID, n, src)
		if callee != "fmt.Sprintf" || len(args) < 2 {
			return false
		}
		format, ok := parser.UnquoteString(args[0].Text)
		if !ok || !(strings.HasPrefix(format, "%s/") || strings.HasPrefix(format, "%s?") || strings.HasPrefix(format, "%s#")) {
			return false
		}
		info, found := propagatedTaint(args[1].Text, tainted)
		return (!found || !fromMCPInput(info)) && isPlainIdentOrSelector(args[1].Text)
	}
	return false
}

// relativePathURL reports whether a URL expression starts with literal text of the form "/word":
// `/repositories/${ws}/pulls`, f"/v1/product/{id}/". A relative path is resolved against the
// client's configured base, so the rest of it cannot name another host. A bare "/" followed by an
// interpolation is not enough: "/" + "/evil.example" is a protocol-relative URL.
func relativePathURL(pf *parsedFile, n *sitter.Node) bool {
	if n == nil {
		return false
	}
	n = unwrapAwait(n)
	lead := ""
	switch n.Kind() {
	case "template_string", "string":
		for i := range n.ChildCount() {
			ch := n.Child(i)
			switch ch.Kind() {
			case "string_start", "string_end", "`":
				continue
			case "string_fragment", "string_content":
				lead = ch.Utf8Text(pf.src)
			}
			break
		}
	case "binary_operator", "binary_expression":
		inner := n
		for {
			l := inner.ChildByFieldName("left")
			if l == nil || (l.Kind() != "binary_operator" && l.Kind() != "binary_expression") {
				break
			}
			inner = l
		}
		if l := inner.ChildByFieldName("left"); l != nil {
			lead, _ = parser.LiteralValue(l, pf.src)
		}
	}
	return len(lead) >= 2 && lead[0] == '/' && lead[1] != '/' && lead[1] != '\\'
}

func fromMCPInput(info taintInfo) bool {
	return len(info.chain) > 0 && sourceClass(info.chain[0].Detail) == sourceMCPInput
}

func isPlainIdentOrSelector(t string) bool {
	if t == "" {
		return false
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
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
			// A module-level template constant is evaluated when the module loads, from the
			// server's code and configuration, so its substitutions are operator values and never
			// MCP input: `https://${DOMAIN}/admin/` fixes the host. Each substitution stands in as
			// one opaque character; a template that only has "https://" or no "/" after its host
			// still does not fix it.
			if t, ok := f.TemplateConstants[n.Utf8Text(pf.src)]; ok && len(t) >= 2 {
				if v, ok := parser.TemplateWithSubstitutions(t[1:len(t)-1], "x"); ok {
					return v, false
				}
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
		case "interpolation", "template_substitution":
			// Extra children indicate a conversion or format specifier (Python); a JavaScript
			// ${...} holds exactly one expression
			e := ch.ChildByFieldName("expression")
			if ch.Kind() == "template_substitution" {
				e = ch.NamedChild(0)
			}
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
