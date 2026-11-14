package parser

import (
	"bytes"
	"slices"
	"strings"
	"unsafe"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

var stringKinds = map[string]bool{
	"string": true, "string_literal": true, "interpreted_string_literal": true,
	"raw_string_literal": true, "template_string": true,
}

// LiteralValue decodes fixed strings, including Rust raw strings and Python's
// implicit concatenation, with optional parentheses; runtime expressions remain
// unresolved
func LiteralValue(n *sitter.Node, src []byte) (string, bool) {
	switch n.Kind() {
	case "concatenated_string":
		var b strings.Builder
		for _, part := range nonCommentChildren(n) {
			v, ok := LiteralValue(part, src)
			if !ok {
				return "", false
			}
			b.WriteString(v)
		}
		return b.String(), true
	case "parenthesized_expression":
		if inner := nonCommentChildren(n); len(inner) == 1 {
			return LiteralValue(inner[0], src)
		}
		return "", false
	}
	if !stringKinds[n.Kind()] {
		return "", false
	}
	text := n.Utf8Text(src)
	if v, ok := UnquoteString(text); ok {
		return v, true
	}
	return rustRawString(text)
}

// rustRawString decodes r"..." and r#"..."# forms, including closing quotes
// followed by hashes that UnquoteString does not handle
func rustRawString(text string) (string, bool) {
	t, ok := strings.CutPrefix(text, "r")
	if !ok {
		return "", false
	}
	hashes := strings.Repeat("#", len(t)-len(strings.TrimLeft(t, "#")))
	open, close := hashes+`"`, `"`+hashes
	if len(t) < len(open)+len(close) || !strings.HasPrefix(t, open) || !strings.HasSuffix(t, close) {
		return "", false
	}
	return t[len(open) : len(t)-len(close)], true
}

func nonCommentChildren(n *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	for i := range n.NamedChildCount() {
		if ch := n.NamedChild(i); ch != nil && !strings.Contains(ch.Kind(), "comment") {
			out = append(out, ch)
		}
	}
	return out
}

// AssignTargets returns the variable name(s) an assignment-shaped node
// writes to. The field is called "left" on every grammar's assignment
// expression, "name" on a declarator with an initializer (Go's var_spec,
// JS/TS/Java's variable_declarator) and "pattern" on Rust's let_declaration
// - trying all three in order needs no per-language switch.
func AssignTargets(node *sitter.Node, src []byte) []string {
	left := node.ChildByFieldName("left")
	if left == nil {
		left = node.ChildByFieldName("name")
	}
	if left == nil {
		left = node.ChildByFieldName("pattern")
	}
	if left == nil {
		return nil
	}
	return identifiersIn(left, src)
}

// AssignValue returns the expression an assignment-shaped node reads from:
// field "value" (a declarator with an initializer) or "right" (an
// assignment expression), unwrapping Go's expression_list to its first
// element for the common single-value case
func AssignValue(node *sitter.Node, src []byte) *sitter.Node {
	v := node.ChildByFieldName("value")
	if v == nil {
		v = node.ChildByFieldName("right")
	}
	if v == nil {
		return nil
	}
	if v.Kind() == "expression_list" && v.NamedChildCount() > 0 {
		return v.NamedChild(0)
	}
	return v
}

// identifiersIn collects assignment and destructuring bindings. pair_pattern
// contributes only its value. Member assignments may conservatively taint a
// property name because grammar nodes do not always distinguish it from a bind.
func identifiersIn(n *sitter.Node, src []byte) []string {
	if isIdentifierKind(n.Kind()) {
		return []string{n.Utf8Text(src)}
	}
	if n.Kind() == "pair_pattern" {
		if value := n.ChildByFieldName("value"); value != nil {
			return identifiersIn(value, src)
		}
		return nil
	}
	cursor := n.Walk()
	defer cursor.Close()
	var out []string
	for _, ch := range n.NamedChildren(cursor) {
		child := ch
		out = append(out, identifiersIn(&child, src)...)
	}
	return out
}

// isIdentifierKind reports whether kind names a bound-name node: the
// plain "identifier" every grammar here uses, or a kind ending in
// "_identifier" or "_identifier_pattern" - JS/TS's
// "property_identifier"/"shorthand_property_identifier_pattern" and
// their relatives - without enumerating every grammar's exact kind name
func isIdentifierKind(kind string) bool {
	return kind == "identifier" ||
		strings.HasSuffix(kind, "_identifier") ||
		strings.HasSuffix(kind, "_identifier_pattern")
}

// defName returns a definition node's own name, falling back to the name of
// the variable it is assigned to for an anonymous function or arrow
// function: `const h = (args) => {...}` is findable as "h"
func DefName(id language.ID, node *sitter.Node, src []byte) string {
	if n := node.ChildByFieldName("name"); n != nil {
		return n.Utf8Text(src)
	}
	if p := node.Parent(); p != nil {
		if nameField := p.ChildByFieldName("name"); nameField != nil {
			if val := p.ChildByFieldName("value"); val != nil && val.Equals(*node) {
				return nameField.Utf8Text(src)
			}
		}
		if left := p.ChildByFieldName("left"); left != nil && left.Kind() == "identifier" {
			if right := p.ChildByFieldName("right"); right != nil && right.Equals(*node) {
				return left.Utf8Text(src)
			}
		}
	}
	return ""
}

func ParamList(node *sitter.Node) *sitter.Node {
	if pl := node.ChildByFieldName("parameters"); pl != nil {
		return pl
	}
	if pl := node.ChildByFieldName("parameter"); pl != nil {
		return pl
	}
	return nil
}

// HasImplicitReceiver reports whether Python binds the first parameter as a
// method receiver. Static methods and nested plain functions return false.
func HasImplicitReceiver(id language.ID, def *sitter.Node, src []byte) bool {
	if id != language.Python || def == nil || def.Kind() != "function_definition" {
		return false
	}
	p := def.Parent()
	if p != nil && p.Kind() == "decorated_definition" {
		if pythonHasDecorator(p, src, "staticmethod") {
			return false
		}
		p = p.Parent()
	}
	if p == nil || p.Kind() != "block" {
		return false
	}
	parent := p.Parent()
	return parent != nil && parent.Kind() == "class_definition"
}

// pythonHasDecorator reports whether a decorated_definition carries the
// named decorator, matched on the decorator expression's own last segment
// so both @staticmethod and a re-exported @typing.staticmethod count
func pythonHasDecorator(decorated *sitter.Node, src []byte, name string) bool {
	cursor := decorated.Walk()
	defer cursor.Close()
	for _, ch := range decorated.NamedChildren(cursor) {
		if ch.Kind() != "decorator" || ch.NamedChildCount() == 0 {
			continue
		}
		text := strings.TrimSpace(ch.NamedChild(0).Utf8Text(src))
		if i := strings.LastIndexByte(text, '.'); i >= 0 {
			text = text[i+1:]
		}
		if text == name {
			return true
		}
	}
	return false
}

func paramNames(id language.ID, list *sitter.Node, src []byte) []string {
	if list == nil {
		return nil
	}
	if list.Kind() == "identifier" {
		return []string{list.Utf8Text(src)}
	}
	cursor := list.Walk()
	defer cursor.Close()
	var names []string
	for _, ch := range list.NamedChildren(cursor) {
		child := ch
		names = append(names, paramNamesOf(id, &child, src)...)
	}
	return names
}

// paramNamesOf returns every bound name, including Go's compact multi-name
// declarations whose tree-sitter name field repeats
func paramNamesOf(id language.ID, n *sitter.Node, src []byte) []string {
	switch id {
	case language.Go, language.Java, language.Rust:
		cursor := n.Walk()
		defer cursor.Close()
		if fields := n.ChildrenByFieldName("name", cursor); len(fields) > 0 {
			names := make([]string, len(fields))
			for i, f := range fields {
				names[i] = f.Utf8Text(src)
			}
			return names
		}
		if f := n.ChildByFieldName("pattern"); f != nil {
			return []string{f.Utf8Text(src)}
		}
	}
	if n.Kind() == "identifier" {
		return []string{n.Utf8Text(src)}
	}
	if s := firstIdentifier(n, src); s != "" {
		return []string{s}
	}
	return nil
}

// firstIdentifier finds a parameter's own name by depth-first search,
// correct whenever the name precedes any type annotation in source order
// (true for Python, JS and TS; Go/Java/Rust are handled by field name above)
func firstIdentifier(n *sitter.Node, src []byte) string {
	if n.Kind() == "identifier" {
		return n.Utf8Text(src)
	}
	cursor := n.Walk()
	defer cursor.Close()
	for _, ch := range n.NamedChildren(cursor) {
		child := ch
		if s := firstIdentifier(&child, src); s != "" {
			return s
		}
	}
	return ""
}

// ParamBindings returns every name one parameter node actually binds. Go, Java, Rust and a
// plain JS/TS identifier parameter usually bind exactly one name (Go's compact `a, b
// string` binds two - see paramNamesOf, which this defers to).
func ParamBindings(id language.ID, n *sitter.Node, src []byte) []string {
	if n == nil {
		return nil
	}
	if id == language.JavaScript || id == language.TypeScript {
		pattern := n
		if p := n.ChildByFieldName("pattern"); p != nil {
			pattern = p
		}
		if names := bindingNames(pattern, src); len(names) > 0 {
			return names
		}
	}
	return paramNamesOf(id, n, src)
}

// bindingNames recurses through a JS/TS binding pattern and returns every
// name it introduces. A rest element and a default value do not change
// what name ends up bound, only where it can come from or what it
// defaults to, so both are unwrapped rather than treated as a name of
// their own.
func bindingNames(n *sitter.Node, src []byte) []string {
	if n == nil {
		return nil
	}
	switch n.Kind() {
	case "identifier", "shorthand_property_identifier_pattern":
		return []string{n.Utf8Text(src)}
	case "pair_pattern":
		return bindingNames(n.ChildByFieldName("value"), src)
	case "object_assignment_pattern", "assignment_pattern":
		return bindingNames(n.ChildByFieldName("left"), src)
	case "rest_pattern":
		if n.NamedChildCount() > 0 {
			return bindingNames(n.NamedChild(0), src)
		}
	case "object_pattern", "array_pattern":
		var names []string
		cursor := n.Walk()
		defer cursor.Close()
		for _, ch := range n.NamedChildren(cursor) {
			child := ch
			names = append(names, bindingNames(&child, src)...)
		}
		return names
	}
	return nil
}

func leadingDoc(id language.ID, node *sitter.Node, src []byte) string {
	if id == language.Python {
		// Python SDKs use the function's docstring as a fallback; leading comments do not count
		if body := node.ChildByFieldName("body"); body != nil && body.NamedChildCount() > 0 {
			first := body.NamedChild(0)
			if first != nil && first.Kind() == "expression_statement" && first.NamedChildCount() > 0 {
				if v, ok := LiteralValue(first.NamedChild(0), src); ok {
					return strings.TrimSpace(v)
				}
			}
		}
		return ""
	}
	start := node
	if p := node.Parent(); p != nil && p.Kind() == "decorated_definition" {
		start = p
	}
	var lines []string
	for s := start.PrevSibling(); s != nil && s.Kind() == "comment"; s = s.PrevSibling() {
		lines = append([]string{stripComment(s.Utf8Text(src))}, lines...)
	}
	return strings.Join(lines, "\n")
}

func receiverType(recv *sitter.Node, src []byte) string {
	if recv.NamedChildCount() == 0 {
		return ""
	}
	decl := recv.NamedChild(0)
	if decl == nil {
		return ""
	}
	t := decl.ChildByFieldName("type")
	if t == nil {
		return ""
	}
	return strings.TrimPrefix(t.Utf8Text(src), "*")
}

func javaAnnotations(node *sitter.Node, src []byte) (texts []string, args [][]graph.Arg) {
	add := func(n *sitter.Node) {
		if n.Kind() == "annotation" || n.Kind() == "marker_annotation" {
			texts = append(texts, javaAnnotationText(n, src))
			args = append(args, javaAnnotationArgs(n, src))
		}
	}
	cursor := node.Walk()
	defer cursor.Close()
	for _, ch := range node.NamedChildren(cursor) {
		if ch.Kind() != "modifiers" {
			add(&ch)
			continue
		}
		mc := ch.Walk()
		for _, mch := range ch.NamedChildren(mc) {
			add(&mch)
		}
		mc.Close()
	}
	return texts, args
}

// javaAnnotationText reconstructs @, the annotation name and its arguments,
// omitting comments such as those in `@Tool /* c */ ("...")`
func javaAnnotationText(n *sitter.Node, src []byte) string {
	name := n.ChildByFieldName("name")
	if name == nil {
		return nodeText(n, src)
	}
	text := "@" + memberText(language.Java, name, src)
	if args := n.ChildByFieldName("arguments"); args != nil {
		text += nodeText(args, src)
	}
	return text
}

// javaAnnotationArgs reads key = value pairs as keyword arguments and a bare
// element value as a positional argument
func javaAnnotationArgs(n *sitter.Node, src []byte) []graph.Arg {
	list := n.ChildByFieldName("arguments")
	if list == nil {
		return nil
	}
	var out []graph.Arg
	for _, ch := range nonCommentChildren(list) {
		key, val := ch.ChildByFieldName("key"), ch.ChildByFieldName("value")
		if ch.Kind() != "element_value_pair" || key == nil || val == nil {
			out = append(out, javaElementValue(ch, src))
			continue
		}
		a := javaElementValue(val, src)
		a.Keyword = key.Utf8Text(src)
		out = append(out, a)
	}
	return out
}

// javaElementValue reads an annotation value. String arrays are joined with
// newlines to match LangChain4j's @Tool({"...", "..."}) description.
func javaElementValue(n *sitter.Node, src []byte) graph.Arg {
	if n.Kind() != "element_value_array_initializer" {
		return exprArg(n, src)
	}
	parts := nonCommentChildren(n)
	vals := make([]string, 0, len(parts))
	for _, p := range parts {
		v, ok := javaConstantString(p, src)
		if !ok {
			return graph.Arg{Text: n.Utf8Text(src)}
		}
		vals = append(vals, v)
	}
	return graph.Arg{Text: n.Utf8Text(src), Literal: true, Value: strings.Join(vals, "\n")}
}

// rustAttributes collects an item's outer attributes across intervening comments,
// including doc comments below #[tool]
func rustAttributes(node *sitter.Node, src []byte) (texts []string, args [][]graph.Arg) {
	for s := node.PrevSibling(); s != nil && (s.Kind() == "attribute_item" || s.IsExtra()); s = s.PrevSibling() {
		if s.IsExtra() {
			continue
		}
		texts = append(texts, rustAttributeText(s, src))
		args = append(args, rustAttributeArgs(s, src))
	}
	slices.Reverse(texts)
	slices.Reverse(args)
	return texts, args
}

// rustAttributeText reconstructs #[, the attribute path, its arguments and ],
// removing comments and spacing such as those in `#[ /* c */ rmcp :: tool ]`
func rustAttributeText(item *sitter.Node, src []byte) string {
	attr := firstNamedChild(item)
	if attr == nil {
		return nodeText(item, src)
	}
	path := firstNamedChild(attr)
	if path == nil {
		return nodeText(item, src)
	}
	text := "#[" + memberText(language.Rust, path, src)
	if a := attr.ChildByFieldName("arguments"); a != nil {
		text += nodeText(a, src)
	} else if v := attr.ChildByFieldName("value"); v != nil {
		text += " = " + nodeText(v, src)
	}
	return text + "]"
}

// rustAttributeArgs splits an attribute's token tree at top-level commas.
// It treats key = value as a keyword argument and preserves values spanning
// multiple tokens as unresolved text.
func rustAttributeArgs(item *sitter.Node, src []byte) []graph.Arg {
	attr := firstNamedChild(item)
	if attr == nil {
		return nil
	}
	tree := attr.ChildByFieldName("arguments")
	if tree == nil || tree.ChildCount() < 2 {
		return nil
	}
	var out []graph.Arg
	var group []*sitter.Node
	flush := func() {
		if len(group) == 0 {
			return
		}
		var kw string
		if len(group) > 2 && group[0].Kind() == "identifier" && group[1].Kind() == "=" {
			kw, group = group[0].Utf8Text(src), group[2:]
		}
		a := graph.Arg{Text: string(src[group[0].StartByte():group[len(group)-1].EndByte()])}
		if len(group) == 1 {
			a = exprArg(group[0], src)
		}
		a.Keyword = kw
		out = append(out, a)
		group = nil
	}
	// Skip the token tree's opening and closing brackets
	for i := uint(1); i+1 < tree.ChildCount(); i++ {
		ch := tree.Child(i)
		switch {
		case ch == nil || strings.Contains(ch.Kind(), "comment"):
		case ch.Kind() == ",":
			flush()
		default:
			group = append(group, ch)
		}
	}
	flush()
	return out
}

func attachDecorators(b budget, adapter *language.Adapter, root *sitter.Node, src []byte, locals []localSymbol) error {
	if adapter.ID != language.Python {
		// Java and Rust attach their decorator equivalents directly while
		// building the symbol (children/siblings, not a wrapping node); JS
		// and TS decorator support is not needed for the required forms
		return nil
	}
	q, err := adapter.Query("decorators")
	if err != nil {
		return err
	}
	qc := sitter.NewQueryCursor()
	defer qc.Close()
	matches := b.matches(qc, q, root, src)
	for m := matches.Next(); m != nil; m = matches.Next() {
		for _, cap := range m.Captures {
			decorated := cap.Node
			def := decorated.ChildByFieldName("definition")
			if def == nil {
				continue
			}
			target := enclosing(def.StartByte(), locals)
			if target == nil {
				continue
			}
			cursor := decorated.Walk()
			for _, ch := range decorated.NamedChildren(cursor) {
				if ch.Kind() != "decorator" {
					continue
				}
				expr := firstNamedChild(&ch)
				if expr == nil {
					continue
				}
				// Unwrap parenthesized decorator expressions such as `@(mcp.tool())`
				expr = calleeNode(expr)
				text := memberText(language.Python, expr, src)
				var args []graph.Arg
				if expr.Kind() == "call" {
					argList := expr.ChildByFieldName("arguments")
					args = genericArgs(argList, src)
					if fn := expr.ChildByFieldName("function"); fn != nil && argList != nil {
						text = memberText(language.Python, calleeNode(fn), src) + nodeText(argList, src)
					}
				}
				target.sym.Decorators = append(target.sym.Decorators, text)
				target.sym.DecoratorArgs = append(target.sym.DecoratorArgs, args)
			}
			cursor.Close()
		}
	}
	return nil
}

// returnValueNode finds the value expression of the first `return <value>`
// statement in def's body - not crossing into a nested function's own
// return, the same guarantee findFirst gives everywhere else - shared by
// returnLiteral and returnText so both read the exact same node
func returnValueNode(id language.ID, def *sitter.Node, src []byte) *sitter.Node {
	body := def.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	retKind := "return_statement"
	if id == language.Rust {
		retKind = "return_expression"
	}
	if ret := findFirst(body, retKind); ret != nil && ret.NamedChildCount() > 0 {
		val := ret.NamedChild(0)
		if val.Kind() == "expression_list" && val.NamedChildCount() > 0 {
			val = val.NamedChild(0)
		}
		return val
	}
	// A JS/TS arrow function's concise body - `async () => ({ tools: [...] })`, the more
	// idiomatic spelling and what the MCP SDKs' own examples use - has no return_statement at
	// all: the body field *is* the returned expression
	if isConciseArrowBody(id, def, body) {
		return unwrapParens(body)
	}
	return nil
}

func isConciseArrowBody(id language.ID, def, body *sitter.Node) bool {
	switch id {
	case language.JavaScript, language.TypeScript:
		return def.Kind() == "arrow_function" && body.Kind() != "statement_block"
	default:
		return false
	}
}

// unwrapParens strips a single layer of parenthesization - the parens
// `({ ... })` syntax requires around an arrow function's object-literal
// concise body - so a caller sees the value itself, not its parentheses
func unwrapParens(n *sitter.Node) *sitter.Node {
	if n.Kind() == "parenthesized_expression" && n.NamedChildCount() > 0 {
		return n.NamedChild(0)
	}
	return n
}

// returnLiteral flattens the keyed fields of a composite/dict/object literal
// returned by a function whose body is simply `return <literal>`, the same
// way exprArg flattens a call argument. It is what makes a factory function
// ("return &mcp.Tool{Name: "x"}") readable without a type checker.
func returnLiteral(id language.ID, def *sitter.Node, src []byte) []graph.Arg {
	val := returnValueNode(id, def, src)
	if val == nil {
		return nil
	}
	return literalFields(val, src)
}

// returnText is returnLiteral's raw-text counterpart: the same return
// value's source text, kept even when it is not a single flat literal
// returnLiteral can flatten - an array of them, say
func returnText(id language.ID, def *sitter.Node, src []byte) string {
	val := returnValueNode(id, def, src)
	if val == nil {
		return ""
	}
	return nodeText(val, src)
}

// findFirst does a shallow-first search for the first descendant of kind, skipping through
// wrapper nodes a grammar inserts (Go wraps a block's statements in a statement_list)
func findFirst(n *sitter.Node, kind string) *sitter.Node {
	cursor := n.Walk()
	defer cursor.Close()
	for _, ch := range n.NamedChildren(cursor) {
		child := ch
		if child.Kind() == kind {
			return &child
		}
		if slices.Contains(functionLikeKinds, child.Kind()) {
			continue
		}
		if found := findFirst(&child, kind); found != nil {
			return found
		}
	}
	return nil
}

// functionLikeKinds spans every language's function/closure node kinds, so
// findFirst never descends into a nested function while looking for the
// enclosing one's return statement
var functionLikeKinds = []string{
	"function_declaration", "method_declaration", "func_literal",
	"function_definition", "lambda",
	"function_expression", "arrow_function", "method_definition",
	"function_item", "closure_expression",
}

// literalFields flattens a Go composite literal, a Python dict literal or a
// JS/TS object literal into keyed Args
func literalFields(n *sitter.Node, src []byte) []graph.Arg {
	if n == nil {
		return nil
	}
	if n.Kind() == "unary_expression" {
		if operand := n.ChildByFieldName("operand"); operand != nil {
			return literalFields(operand, src)
		}
	}
	switch n.Kind() {
	case "composite_literal":
		body := n.ChildByFieldName("body")
		if body == nil {
			return nil
		}
		var out []graph.Arg
		c := body.Walk()
		for _, ch := range body.NamedChildren(c) {
			if ch.Kind() != "keyed_element" {
				continue
			}
			key := ch.ChildByFieldName("key")
			val := ch.ChildByFieldName("value")
			if key != nil && key.NamedChildCount() > 0 {
				key = key.NamedChild(0)
			}
			if val != nil && val.NamedChildCount() > 0 {
				val = val.NamedChild(0)
			}
			if key == nil || val == nil {
				continue
			}
			a := exprArg(val, src)
			a.Keyword = nodeText(key, src)
			out = append(out, a)
		}
		c.Close()
		return out
	case "dictionary", "object":
		var out []graph.Arg
		c := n.Walk()
		for _, ch := range n.NamedChildren(c) {
			if ch.Kind() != "pair" {
				continue
			}
			key := ch.ChildByFieldName("key")
			val := ch.ChildByFieldName("value")
			if key == nil || val == nil {
				continue
			}
			keyText := nodeText(key, src)
			if v, ok := UnquoteString(keyText); ok {
				keyText = v
			}
			a := exprArg(val, src)
			a.Keyword = keyText
			out = append(out, a)
		}
		c.Close()
		return out
	}
	return nil
}

// nodeText returns a string sharing src. Nested arguments and chained callees
// contain earlier expressions, so copying each span would require quadratic
// space. Shared strings keep the source buffer alive without copying its bytes.
// Callers must keep src immutable while any shared string survives.
func nodeText(n *sitter.Node, src []byte) string {
	return spanText(src, n.StartByte(), n.EndByte())
}

func spanText(src []byte, start, end uint) string {
	b := src[start:end]
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// copiedLen returns len(s) for allocated text, or zero when s shares src
func copiedLen(s string, src []byte) int {
	if s == "" || len(src) == 0 {
		return len(s)
	}
	p := uintptr(unsafe.Pointer(unsafe.StringData(s)))
	base := uintptr(unsafe.Pointer(unsafe.SliceData(src)))
	if p >= base && p < base+uintptr(len(src)) {
		return 0
	}
	return len(s)
}

// exprArg builds an Arg for an argument or field-value expression
func exprArg(n *sitter.Node, src []byte) graph.Arg {
	text := nodeText(n, src)
	if n.Kind() == "keyword_argument" {
		nameN := n.ChildByFieldName("name")
		valN := n.ChildByFieldName("value")
		if nameN != nil && valN != nil {
			a := exprArg(valN, src)
			a.Keyword = nodeText(nameN, src)
			return a
		}
	}
	if v, ok := LiteralValue(n, src); ok {
		return graph.Arg{Text: text, Literal: true, Value: v}
	}
	return graph.Arg{Text: text}
}

// genericArgs builds Args for every language except Go, which needs
// composite-literal flattening (see goArgs)
func genericArgs(list *sitter.Node, src []byte) []graph.Arg {
	if list == nil {
		return nil
	}
	cursor := list.Walk()
	defer cursor.Close()
	var out []graph.Arg
	for _, ch := range list.NamedChildren(cursor) {
		// Skip comments so positional argument indexes stay aligned
		if strings.Contains(ch.Kind(), "comment") {
			continue
		}
		child := ch
		out = append(out, exprArg(&child, src))
	}
	return out
}

func goArgs(list *sitter.Node, src []byte) []graph.Arg {
	if list == nil {
		return nil
	}
	cursor := list.Walk()
	defer cursor.Close()
	var out []graph.Arg
	for _, ch := range list.NamedChildren(cursor) {
		child := ch
		fields := literalFields(&child, src)
		if fields == nil {
			out = append(out, exprArg(&child, src))
			continue
		}
		out = append(out, graph.Arg{Text: nodeText(&child, src)})
		out = append(out, fields...)
	}
	return out
}

// Receiver is the callee's own receiver as either plain text or a nested call with arguments.
// Preserving the shape lets taint analysis inspect a call-shaped receiver without guessing.
type Receiver struct {
	Text     string
	CallText string
	CallArgs []graph.Arg
}

// CalleeAndArgs pulls the callee expression text, the callee's own receiver and the call's
// arguments out of a call-shaped node
func CalleeAndArgs(id language.ID, call *sitter.Node, src []byte) (calleeText string, receiver Receiver, args []graph.Arg) {
	return calleeAndArgs(id, call, src, true)
}

// calleeAndArgs extracts a receiver only when requested. For a call-shaped
// receiver, it reads the callee and arguments without descending into another
// receiver; repeating that descent at each link would make chain processing
// quadratic.
func calleeAndArgs(id language.ID, call *sitter.Node, src []byte, withReceiver bool) (calleeText string, receiver Receiver, args []graph.Arg) {
	member := func(fn *sitter.Node, field string) Receiver {
		if !withReceiver {
			return Receiver{}
		}
		return memberReceiver(id, fn, field, src)
	}
	switch id {
	case language.Go:
		fn := call.ChildByFieldName("function")
		if fn == nil {
			return "", Receiver{}, nil
		}
		fn = calleeNode(fn)
		return memberText(id, fn, src), member(fn, "operand"), goArgs(call.ChildByFieldName("arguments"), src)
	case language.Python, language.JavaScript, language.TypeScript, language.Rust:
		if call.Kind() == "new_expression" {
			// Match Java's constructor naming so catalog entries such as "new Function" apply
			ctor := call.ChildByFieldName("constructor")
			if ctor == nil {
				return "", Receiver{}, nil
			}
			return "new " + memberText(id, ctor, src), Receiver{}, genericArgs(call.ChildByFieldName("arguments"), src)
		}
		fn := call.ChildByFieldName("function")
		if fn == nil {
			if call.Kind() == "macro_invocation" {
				if m := call.ChildByFieldName("macro"); m != nil {
					return memberText(id, m, src) + "!", Receiver{}, nil
				}
			}
			return "", Receiver{}, nil
		}
		field := "object"
		if id == language.Rust {
			field = "value"
		}
		fn = calleeNode(fn)
		return memberText(id, fn, src), member(fn, field), genericArgs(call.ChildByFieldName("arguments"), src)
	case language.Java:
		if call.Kind() == "object_creation_expression" {
			t := call.ChildByFieldName("type")
			if t == nil {
				return "", Receiver{}, nil
			}
			return "new " + memberText(id, t, src), Receiver{}, genericArgs(call.ChildByFieldName("arguments"), src)
		}
		nameN := call.ChildByFieldName("name")
		if nameN == nil {
			return "", Receiver{}, nil
		}
		text := nodeText(nameN, src)
		var recv Receiver
		if obj := call.ChildByFieldName("object"); obj != nil {
			if op := tokenAfter(call, obj); op != nil {
				text = joinMember(id, obj, op, nameN, src)
			}
			if withReceiver {
				recv = asReceiver(id, obj, src)
			}
		}
		return text, recv, genericArgs(call.ChildByFieldName("arguments"), src)
	}
	return "", Receiver{}, nil
}

// memberText normalizes member access such as a.b, a?.b and a::b so comments,
// whitespace and line continuations do not hide names from pattern matching.
// Other nodes retain their source text.
func memberText(id language.ID, n *sitter.Node, src []byte) string {
	if obj, op, name, ok := memberParts(id, n); ok {
		return joinMember(id, obj, op, name, src)
	}
	return nodeText(n, src)
}

// joinMember joins an object, operator and member name. Rebuilding each link of
// a chain would copy its preceding links and require quadratic space, so it
// reuses source spans when contiguous or when whitespace follows the operator
// after a non-identifier ending. Identifier patterns cannot cross that boundary,
// and the last segment still follows the operator.
func joinMember(id language.ID, obj, op, name *sitter.Node, src []byte) string {
	objText := memberText(id, obj, src)
	if objText != "" && sharesSpan(objText, src, obj) {
		after := src[op.EndByte():name.StartByte()]
		if obj.EndByte() == op.StartByte() && len(after) == 0 ||
			len(bytes.TrimSpace(after)) == 0 && !isIdentByte(objText[len(objText)-1]) {
			return spanText(src, obj.StartByte(), name.EndByte())
		}
	}
	return objText + nodeText(op, src) + nodeText(name, src)
}

// memberParts splits member access into object, operator and name, skipping
// comments and line continuations; ok is false for other node kinds
func memberParts(id language.ID, n *sitter.Node) (obj, op, name *sitter.Node, ok bool) {
	kind := n.Kind()
	if !slices.Contains(language.ByID(id).Grammar.MemberKinds, kind) &&
		!((id == language.Java || id == language.Rust) && (kind == "scoped_identifier" || kind == "scoped_type_identifier")) {
		return nil, nil, nil, false
	}
	var parts []*sitter.Node
	c := n.Walk()
	defer c.Close()
	for more := c.GotoFirstChild(); more; more = c.GotoNextSibling() {
		if ch := c.Node(); !ch.IsExtra() {
			parts = append(parts, ch)
		}
	}
	// A Rust path that starts at the root, `::std::fs`, has no object
	if len(parts) < 3 || !parts[0].IsNamed() {
		return nil, nil, nil, false
	}
	return parts[0], parts[1], parts[len(parts)-1], true
}

// tokenAfter is the first child of parent after n that is not a comment
func tokenAfter(parent, n *sitter.Node) *sitter.Node {
	c := parent.Walk()
	defer c.Close()
	for more := c.GotoFirstChild(); more; more = c.GotoNextSibling() {
		if ch := c.Node(); !ch.IsExtra() && ch.StartByte() >= n.EndByte() {
			return ch
		}
	}
	return nil
}

// calleeNode unwraps parentheses and sequence expressions to find the function
// in calls such as `(os.system)(cmd)` and TypeScript's `(0, cp.execSync)(cmd)`
func calleeNode(fn *sitter.Node) *sitter.Node {
	for fn.Kind() == "parenthesized_expression" || fn.Kind() == "sequence_expression" {
		inner := lastNamedChild(fn)
		if inner == nil {
			return fn
		}
		fn = inner
	}
	return fn
}

// lastNamedChild is n's last named child that is not a comment
func lastNamedChild(n *sitter.Node) *sitter.Node {
	var last *sitter.Node
	c := n.Walk()
	defer c.Close()
	for more := c.GotoFirstChild(); more; more = c.GotoNextSibling() {
		if ch := c.Node(); ch.IsNamed() && !ch.IsExtra() {
			last = ch
		}
	}
	return last
}

// firstNamedChild is n's first named child that is not a comment
func firstNamedChild(n *sitter.Node) *sitter.Node {
	c := n.Walk()
	defer c.Close()
	for more := c.GotoFirstChild(); more; more = c.GotoNextSibling() {
		if ch := c.Node(); ch.IsNamed() && !ch.IsExtra() {
			return ch
		}
	}
	return nil
}

// sharesSpan reports whether s is n's own source text, taken from src rather than built
func sharesSpan(s string, src []byte, n *sitter.Node) bool {
	start, end := n.StartByte(), n.EndByte()
	return uint(len(s)) == end-start && (start == end || unsafe.StringData(s) == &src[start])
}

// isIdentByte conservatively treats non-ASCII bytes as identifier characters
// so joinMember keeps the operator adjacent to a possible identifier
func isIdentByte(b byte) bool {
	return b == '_' || b == '$' || b >= 0x80 || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9'
}

// memberReceiver reads fn's own receiver field - "object" for an
// attribute/member access, "operand" for Go's selector, "value" for Rust's
// field access - and classifies it via asReceiver
func memberReceiver(id language.ID, fn *sitter.Node, field string, src []byte) Receiver {
	obj := fn.ChildByFieldName(field)
	if obj == nil {
		return Receiver{}
	}
	return asReceiver(id, obj, src)
}

// asReceiver reads a call-shaped receiver's callee and arguments without its
// own receiver; other nodes use memberText
func asReceiver(id language.ID, obj *sitter.Node, src []byte) Receiver {
	if slices.Contains(language.ByID(id).Grammar.CallKinds, obj.Kind()) {
		callText, _, callArgs := calleeAndArgs(id, obj, src, false)
		return Receiver{CallText: callText, CallArgs: callArgs}
	}
	return Receiver{Text: memberText(id, obj, src)}
}
