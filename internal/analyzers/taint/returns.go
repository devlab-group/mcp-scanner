package taint

import (
	"regexp"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Return-value summaries: what a project function's returned value still carries of one of its
// parameters. A function such as
//
//	def resolve(name):
//	    p = os.path.realpath(os.path.join(ROOT, name))
//	    if not p.startswith(ROOT + os.sep): raise ValueError()
//	    return p
//
// returns its parameter only after a containment check. Without a summary the caller saw
// resolve(name) as name itself, still tainted for path traversal.
//
// The summary walks the function's body once per parameter, seeded with that parameter as MCP
// input, in a silent mode: no findings are emitted and no further call is followed. It records the
// taint of every value returned from the function's own body (not from nested functions). When at
// least one return carries the parameter's taint and every such return is cleared for a category,
// the call's result is cleared for it. When no return carries it, nothing changes: the walk may
// have lost the flow, and dropping it would hide a real issue.

type retKey struct {
	sym   graph.SymbolID
	param string
}

// retSummary is what every return of a function that carries one parameter's taint has in common:
// the categories it is cleared for, and a review note when each of them went through the project's
// own escaping function
type retSummary struct {
	cleared map[string]bool
	review  string
}

// returnSummary builds (once) the summary of sym for param, or returns nil when no return of sym
// carries param's taint
func (c *ctx) returnSummary(sym *graph.Symbol, param string) *retSummary {
	if sym == nil {
		return nil
	}
	key := retKey{sym.ID, param}
	if v, ok := c.retSummaries[key]; ok {
		return v
	}
	c.retSummaries[key] = nil // a recursive call sees no summary
	pf, def := c.defNodeFor(sym)
	if pf == nil || def == nil {
		return nil
	}
	body := def.ChildByFieldName("body")
	if body == nil || (body.Kind() != "block" && body.Kind() != "statement_block") {
		return nil
	}
	tainted := map[string]taintInfo{param: {confidence: 1, chain: []model.FlowStep{{
		Kind: "source", Symbol: param, File: sym.File, Line: sym.Line, Detail: "tool handler argument", Resolved: true,
	}}}}
	prevCapture, prevFunc, prevSeen := c.retCapture, c.retFunc, c.retSeen
	var captured []taintInfo
	seen := 0
	c.retCapture, c.retFunc, c.retSeen = &captured, def, &seen
	c.summaryDepth++
	c.walk(pf, sym.File, tainted, body, 0, false)
	c.summaryDepth--
	c.retCapture, c.retFunc, c.retSeen = prevCapture, prevFunc, prevSeen

	if len(captured) == 0 {
		// The walk skips subtrees that mention nothing tainted, so it may never reach a return;
		// count the function's own returns from its syntax tree as well
		seen = max(seen, valueReturns(pf, def, body))
		if seen == 0 || storesParam(body.Utf8Text(pf.src), param) {
			return nil
		}
		// async createTmpFile(content, lang) { ...; writeFile(p, content); return p }: the function
		// returns values, and none of them carries the parameter. The walk may still have lost a
		// flow it does not model, so the result is not cleared, but the finding goes to a person.
		sum := &retSummary{cleared: map[string]bool{}, review: "no value " + sym.Name + " returns carries the argument the scanner followed; only a flow it does not model would make the result carry it"}
		c.retSummaries[key] = sum
		return sum
	}
	sum := &retSummary{cleared: map[string]bool{}, review: captured[0].review}
	for k, v := range captured[0].clearedFor {
		if v {
			sum.cleared[k] = true
		}
	}
	for _, info := range captured[1:] {
		for k := range sum.cleared {
			if !info.clearedFor[k] {
				delete(sum.cleared, k)
			}
		}
		if info.review == "" {
			sum.review = ""
		}
	}
	c.retSummaries[key] = sum
	return sum
}

// summaryCandidates are the definitions a call may reach for summary purposes: the one it
// resolves to, or - when the name is ambiguous, as for an interface method with one
// implementation per dialect - every same-named function or method, up to six
func (c *ctx) summaryCandidates(file, calleeText string) []*graph.Symbol {
	if sym, ok := c.resolveCallee(file, calleeText); ok {
		return []*graph.Symbol{sym}
	}
	ids := c.idx[parser.LastSegment(calleeText)]
	if len(ids) < 2 || len(ids) > 6 {
		return nil
	}
	var out []*graph.Symbol
	for _, id := range ids {
		if s := c.g.Symbols[id]; s != nil && (s.Kind == graph.KindFunction || s.Kind == graph.KindMethod) {
			out = append(out, s)
		}
	}
	if len(out) != len(ids) {
		return nil
	}
	return out
}

// summarizeCall combines the summaries of every candidate for every tainted parameter: the
// categories all of them clear, and a review note when all of them escape the value. ok is false
// when any candidate or parameter has no summary.
func (c *ctx) summarizeCall(syms []*graph.Symbol, args []graph.Arg, tainted map[string]taintInfo) (cleared []string, review string, ok bool) {
	if len(syms) == 0 {
		return nil, "", false
	}
	var all map[string]bool
	reviewAll := true
	for _, sym := range syms {
		seed := c.seedArgs(sym, args, tainted, model.FlowStep{}, 1)
		if len(seed) == 0 {
			return nil, "", false
		}
		for p := range seed {
			sum := c.returnSummary(sym, p)
			if sum == nil {
				return nil, "", false
			}
			if all == nil {
				all = map[string]bool{}
				for k := range sum.cleared {
					all[k] = true
				}
			} else {
				for k := range all {
					if !sum.cleared[k] {
						delete(all, k)
					}
				}
			}
			if sum.review == "" {
				reviewAll = false
			} else if review == "" {
				review = sum.review
			}
		}
	}
	for k := range all {
		cleared = append(cleared, k)
	}
	slices.Sort(cleared)
	if !reviewAll {
		review = ""
	}
	return cleared, review, true
}

// callResultCleared returns the categories a resolved call's result is cleared for
func (c *ctx) callResultCleared(sym *graph.Symbol, args []graph.Arg, tainted map[string]taintInfo) []string {
	cats, _, _ := c.summarizeCall([]*graph.Symbol{sym}, args, tainted)
	return cats
}

// captureReturn records the taint of a return statement's value while a summary is being built,
// for returns of the summarized function itself
func (c *ctx) captureReturn(pf *parsedFile, file string, n *sitter.Node, tainted map[string]taintInfo) {
	if c.retCapture == nil || !slices.Contains(pf.adapter.Grammar.ReturnKinds, n.Kind()) {
		return
	}
	if fn := enclosingFunctionNode(n); fn == nil || c.retFunc == nil || fn.StartByte() != c.retFunc.StartByte() {
		return
	}
	v := n.NamedChild(0)
	if v != nil && v.Kind() == "expression_list" {
		// Go: return value, err - the value is the first expression
		v = v.NamedChild(0)
	}
	if v == nil {
		return
	}
	if c.retSeen != nil {
		*c.retSeen++
	}
	if info, ok := hexOnly(v.Utf8Text(pf.src), tainted); ok {
		*c.retCapture = append(*c.retCapture, info)
		return
	}
	if info, ok := propagatedTaint(v.Utf8Text(pf.src), tainted); ok {
		if why, esc := c.escapedBy(v.Utf8Text(pf.src)); esc && info.review == "" {
			// return fmt.Sprintf("SHOW CREATE TABLE %s;", d.QuoteIdentifier(table))
			info.review = escapedReview(why)
		}
		if cats, rv, ok := c.exprSummary(pf, file, v, tainted); ok {
			// return STATE / ("skip." + re.sub(r"[^A-Za-z0-9_-]", "_", sid)), return base + clean(p):
			// the value is used only through rebuilds or cleared project functions
			info.clearedFor = mergeClearedFor(info.clearedFor, cats)
			if rv != "" && info.review == "" {
				info.review = rv
			}
		}
		*c.retCapture = append(*c.retCapture, info)
	}
}

// valueReturns counts the return statements with a value that belong to def itself, not to a
// function nested in it
func valueReturns(pf *parsedFile, def, body *sitter.Node) int {
	n := 0
	var visit func(x *sitter.Node)
	visit = func(x *sitter.Node) {
		if x == nil {
			return
		}
		if x != body && x != def && isFunctionLikeNode(x) {
			return
		}
		if slices.Contains(pf.adapter.Grammar.ReturnKinds, x.Kind()) && x.NamedChildCount() > 0 {
			n++
		}
		for i := range x.NamedChildCount() {
			visit(x.NamedChild(i))
		}
	}
	visit(body)
	return n
}

// storesParam reports whether a function body may hand param on other than by returning it: stores
// it on an object, appends it to a collection, writes it into an index, or declares a global
var storesParamRe = regexp.MustCompile(`(?:\b(?:self|this)\.[\w.]+\s*=[^=]|\.(?:append|push|add|set|put|extend|insert|update|unshift|setdefault|Store)\s*\(|\]\s*=[^=]|\bglobal\b|\bnonlocal\b|\byield\b)`)

func storesParam(body, param string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, param) && wordRegexp(param).MatchString(line) && storesParamRe.MatchString(line) {
			return true
		}
	}
	return false
}

// enclosingFunctionNode is the innermost function-like node around n
func enclosingFunctionNode(n *sitter.Node) *sitter.Node {
	for a := n.Parent(); a != nil; a = a.Parent() {
		switch a.Kind() {
		case "function_definition", "function_declaration", "method_definition", "method_declaration",
			"arrow_function", "function_expression", "func_literal", "function_item", "lambda", "lambda_expression":
			return a
		}
	}
	return nil
}

// exprSummary looks at an expression whose tainted names may all sit inside calls to project
// functions with return summaries - locate(name), os.path.join(ROOT, name_for(view)),
// f"{prefix(path)}{stamp}.json". ok when every tainted name is inside such a call; cats are the
// categories all of those calls clear, review a note when one of them only escapes the value.
func (c *ctx) exprSummary(pf *parsedFile, file string, an *sitter.Node, tainted map[string]taintInfo) (cats []string, review string, ok bool) {
	if an == nil {
		return nil, "", false
	}
	text := an.Utf8Text(pf.src)
	if _, t := mentionsAny(text, tainted, ""); !t {
		return nil, "", false
	}
	base := an.StartByte()
	type span struct{ a, b uint }
	var spans []span
	var all map[string]bool
	var visit func(n *sitter.Node)
	visit = func(n *sitter.Node) {
		if slices.Contains(pf.adapter.Grammar.CallKinds, n.Kind()) && allowlistRebuild(n.Utf8Text(pf.src)) != "" {
			// "skip." + re.sub(r"[^A-Za-z0-9_-]", "_", sid): an allowlist rebuild inside the
			// expression leaves no separator, dot or metacharacter of the value
			spans = append(spans, span{n.StartByte() - base, n.EndByte() - base})
			rebuilt := []string{"path_traversal", "command_injection", "sql_injection"}
			if all == nil {
				all = map[string]bool{}
				for _, k := range rebuilt {
					all[k] = true
				}
			} else {
				for k := range all {
					if !slices.Contains(rebuilt, k) {
						delete(all, k)
					}
				}
			}
			return
		}
		if slices.Contains(pf.adapter.Grammar.CallKinds, n.Kind()) {
			calleeText, _, args := parser.CalleeAndArgs(pf.adapter.ID, n, pf.src)
			if cl, rv, good := c.summarizeCall(c.summaryCandidates(file, calleeText), args, tainted); good && (len(cl) > 0 || rv != "") {
				spans = append(spans, span{n.StartByte() - base, n.EndByte() - base})
				if all == nil {
					all = map[string]bool{}
					for _, k := range cl {
						all[k] = true
					}
				} else {
					for k := range all {
						if !slices.Contains(cl, k) {
							delete(all, k)
						}
					}
				}
				if rv != "" && review == "" {
					review = "in " + calleeText + ": " + rv
				}
				return
			}
		}
		for i := range n.NamedChildCount() {
			if ch := n.NamedChild(i); ch != nil {
				visit(ch)
			}
		}
	}
	visit(an)
	if len(spans) == 0 {
		return nil, "", false
	}
	var b strings.Builder
	prev := uint(0)
	for _, sp := range spans {
		if sp.a < prev {
			continue
		}
		b.WriteString(text[prev:sp.a])
		b.WriteString("CLEARED")
		prev = sp.b
	}
	b.WriteString(text[prev:])
	if _, still := mentionsAny(b.String(), tainted, ""); still {
		return nil, "", false
	}
	for k := range all {
		cats = append(cats, k)
	}
	slices.Sort(cats)
	return cats, review, true
}

// argCallVerdict applies exprSummary to one sink category: cleared when every summarized call
// clears it, otherwise the note asking a person to check it when one of them only escapes the value
func (c *ctx) argCallVerdict(pf *parsedFile, file string, an *sitter.Node, tainted map[string]taintInfo, category string) (cleared bool, review string) {
	cats, rv, ok := c.exprSummary(pf, file, an, tainted)
	if !ok {
		return false, ""
	}
	if slices.Contains(cats, category) {
		return true, ""
	}
	return false, rv
}

// argCallClears reports whether argCallVerdict clears the argument outright
func (c *ctx) argCallClears(pf *parsedFile, file string, an *sitter.Node, tainted map[string]taintInfo, category string) bool {
	cl, _ := c.argCallVerdict(pf, file, an, tainted, category)
	return cl
}

// allowlistRebuild reports whether an expression rebuilds a value from an allowlist of
// characters that holds nothing but letters, digits, "_" and "-":
//
//	"".join(c if c.isalnum() or c in "-_" else "-" for c in name)
//	"".join(c for c in name if c.isalnum())
//	re.sub(r"[^A-Za-z0-9_-]", "", name)        name.replace(/[^a-zA-Z0-9_-]/g, "")
//
// Such a value carries no separator, dot, quote or shell metacharacter, so it cannot leave a
// directory, close an SQL string or add a command. It can still start with "-".
//
// It returns the text of the value being rebuilt (the comprehension's iterable, or the whole
// expression for a replace), or "" when text is not such a rebuild.
func allowlistRebuild(text string) string {
	t := strings.TrimSpace(text)
	if m := joinComprehension.FindStringSubmatch(t); m != nil {
		v, cond, repl, iter, filter := m[1], m[2], m[3], m[5], m[6]
		if (cond == "" && filter == "") || m[4] != v {
			return ""
		}
		if (cond == "" || charTestOnly(cond, v)) && (filter == "" || charTestOnly(filter, v)) && safeChars(repl) {
			return iter
		}
		return ""
	}
	if m := negatedClassReplace.FindStringSubmatch(t); m != nil {
		class, repl := m[1]+m[3], m[2]+m[4]
		if safeClass(class) && safeChars(repl) {
			return t
		}
	}
	return ""
}

var (
	joinComprehension = regexp.MustCompile(`^["']{2}\.join\(\s*\[?\s*(\w+)\s+(?:if\s+(.+?)\s+else\s+["']([^"']*)["']\s+)?for\s+(\w+)\s+in\s+(.+?)(?:\s+if\s+(.+?))?\s*\]?\s*\)$`)
	// re.sub(r"[^...]", "x", v) | v.replace(/[^...]/g, "x")
	negatedClassReplace = regexp.MustCompile(`^(?:re\.sub\(\s*r?["']\[\^([^\]]*)\]\+?["']\s*,\s*["']([^"']*)["']\s*,[^)]*\)|[\w.]+\.replace(?:All)?\(\s*/\[\^([^\]]*)\]\+?/g?\s*,\s*["'` + "`" + `]([^"'` + "`" + `]*)["'` + "`" + `]\s*\))$`)
	charTest            = regexp.MustCompile(`^(?:not\s+)?(\w+)\.(?:isalnum|isalpha|isdigit|isdecimal|isnumeric|islower|isupper)\(\)$|^(\w+)\s+in\s+["']([^"']*)["']$`)
	safeCharSet         = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
)

// charTestOnly reports whether cond only tests the loop character v with str methods and
// membership in a literal of safe characters, joined by "or"/"and"
func charTestOnly(cond, v string) bool {
	cond = strings.TrimSpace(cond)
	if strings.HasPrefix(cond, "(") && strings.HasSuffix(cond, ")") {
		cond = cond[1 : len(cond)-1]
	}
	for _, part := range regexp.MustCompile(`\s+(?:or|and)\s+`).Split(cond, -1) {
		m := charTest.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil || (m[1] != "" && m[1] != v) || (m[2] != "" && (m[2] != v || !safeChars(m[3]))) {
			return false
		}
	}
	return true
}

func safeChars(s string) bool { return safeCharSet.MatchString(s) }

// safeClass reports whether a regex character class (the part after "[^") lists only letters,
// digits, "_", "-" and ranges among them, so its negation removes everything else
func safeClass(class string) bool {
	c := strings.NewReplacer(`\w`, "", "a-z", "", "A-Z", "", "0-9", "", `\-`, "", `\d`, "").Replace(class)
	c = strings.TrimSuffix(strings.TrimPrefix(c, "-"), "-")
	return safeCharSet.MatchString(c) && !strings.Contains(c, "-")
}

// receiverNode is the object a method call is made on: locate(name) in locate(name).read_text()
func receiverNode(call *sitter.Node) *sitter.Node {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return nil
	}
	switch fn.Kind() {
	case "attribute", "member_expression":
		return fn.ChildByFieldName("object")
	case "selector_expression":
		return fn.ChildByFieldName("operand")
	}
	return nil
}

// hexCategories are what a hex-encoded value cannot carry: it holds only 0-9 and a-f
var hexCategories = []string{"path_traversal", "command_injection", "sql_injection", "argument_injection"}

// maskHexEncodings replaces every expression ending in .hex() or .hexdigest() -
// url_path.encode("utf-8").hex(), hashlib.sha256(x.encode()).hexdigest() - with a placeholder, so
// what is left shows whether any tainted name is used other than hex-encoded
func maskHexEncodings(text string) (string, bool) {
	changed := false
	for {
		i, n := -1, 0
		for _, suf := range []string{".hexdigest()", ".hex()"} {
			if j := strings.Index(text, suf); j >= 0 && (i < 0 || j < i) {
				i, n = j, len(suf)
			}
		}
		if i < 0 {
			return text, changed
		}
		// walk back over the receiver: names, dots and balanced parentheses or brackets
		start, depth := i, 0
		for start > 0 {
			ch := text[start-1]
			switch {
			case ch == ')' || ch == ']':
				depth++
			case (ch == '(' || ch == '[') && depth > 0:
				depth--
			case depth > 0, ch == '.' || ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9':
			default:
				goto done
			}
			start--
		}
	done:
		text = text[:start] + "HEXDIGITS" + text[i+n:]
		changed = true
	}
}

// hexOnly reports whether text mentions tainted names only inside hex encodings
func hexOnly(text string, tainted map[string]taintInfo) (taintInfo, bool) {
	masked, changed := maskHexEncodings(text)
	if !changed {
		return taintInfo{}, false
	}
	info, ok := mentionsAny(text, tainted, "")
	if !ok {
		return taintInfo{}, false
	}
	if _, still := mentionsAny(masked, tainted, ""); still {
		return taintInfo{}, false
	}
	info.clearedFor = mergeClearedFor(info.clearedFor, hexCategories)
	return info, true
}
