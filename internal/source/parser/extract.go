package parser

import (
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

var stringKinds = map[string]bool{
	"string": true, "string_literal": true, "interpreted_string_literal": true,
	"raw_string_literal": true, "template_string": true,
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
		if body := node.ChildByFieldName("body"); body != nil && body.NamedChildCount() > 0 {
			first := body.NamedChild(0)
			if first != nil && first.Kind() == "expression_statement" && first.NamedChildCount() > 0 {
				s := first.NamedChild(0)
				if s.Kind() == "string" {
					if v, ok := UnquoteString(s.Utf8Text(src)); ok {
						return strings.TrimSpace(v)
					}
				}
			}
		}
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

func javaAnnotations(node *sitter.Node, src []byte) []string {
	var out []string
	cursor := node.Walk()
	defer cursor.Close()
	for _, ch := range node.NamedChildren(cursor) {
		switch ch.Kind() {
		case "annotation", "marker_annotation":
			out = append(out, ch.Utf8Text(src))
		case "modifiers":
			mc := ch.Walk()
			for _, mch := range ch.NamedChildren(mc) {
				if mch.Kind() == "annotation" || mch.Kind() == "marker_annotation" {
					out = append(out, mch.Utf8Text(src))
				}
			}
			mc.Close()
		}
	}
	return out
}

func rustAttributes(node *sitter.Node, src []byte) []string {
	var attrs []string
	for s := node.PrevSibling(); s != nil && s.Kind() == "attribute_item"; s = s.PrevSibling() {
		attrs = append(attrs, s.Utf8Text(src))
	}
	slices.Reverse(attrs)
	return attrs
}

func attachDecorators(adapter *language.Adapter, root *sitter.Node, src []byte, locals []localSymbol) error {
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
	matches := qc.Matches(q, root, src)
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
				if ch.Kind() == "decorator" && ch.NamedChildCount() > 0 {
					target.sym.Decorators = append(target.sym.Decorators, ch.NamedChild(0).Utf8Text(src))
				}
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
	return val.Utf8Text(src)
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
			a.Keyword = key.Utf8Text(src)
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
			keyText := key.Utf8Text(src)
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

// exprArg builds an Arg for an argument or field-value expression
func exprArg(n *sitter.Node, src []byte) graph.Arg {
	text := n.Utf8Text(src)
	if n.Kind() == "keyword_argument" {
		nameN := n.ChildByFieldName("name")
		valN := n.ChildByFieldName("value")
		if nameN != nil && valN != nil {
			a := exprArg(valN, src)
			a.Keyword = nameN.Utf8Text(src)
			return a
		}
	}
	if stringKinds[n.Kind()] {
		if v, ok := UnquoteString(text); ok {
			return graph.Arg{Text: text, Literal: true, Value: v}
		}
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
		out = append(out, graph.Arg{Text: child.Utf8Text(src)})
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
	switch id {
	case language.Go:
		fn := call.ChildByFieldName("function")
		if fn == nil {
			return "", Receiver{}, nil
		}
		return fn.Utf8Text(src), memberReceiver(id, fn, "operand", src), goArgs(call.ChildByFieldName("arguments"), src)
	case language.Python, language.JavaScript, language.TypeScript, language.Rust:
		if call.Kind() == "new_expression" {
			// Match Java's constructor naming so catalog entries such as "new Function" apply
			ctor := call.ChildByFieldName("constructor")
			if ctor == nil {
				return "", Receiver{}, nil
			}
			return "new " + ctor.Utf8Text(src), Receiver{}, genericArgs(call.ChildByFieldName("arguments"), src)
		}
		fn := call.ChildByFieldName("function")
		if fn == nil {
			if call.Kind() == "macro_invocation" {
				if m := call.ChildByFieldName("macro"); m != nil {
					return m.Utf8Text(src) + "!", Receiver{}, nil
				}
			}
			return "", Receiver{}, nil
		}
		field := "object"
		if id == language.Rust {
			field = "value"
		}
		return fn.Utf8Text(src), memberReceiver(id, fn, field, src), genericArgs(call.ChildByFieldName("arguments"), src)
	case language.Java:
		if call.Kind() == "object_creation_expression" {
			t := call.ChildByFieldName("type")
			if t == nil {
				return "", Receiver{}, nil
			}
			return "new " + t.Utf8Text(src), Receiver{}, genericArgs(call.ChildByFieldName("arguments"), src)
		}
		nameN := call.ChildByFieldName("name")
		if nameN == nil {
			return "", Receiver{}, nil
		}
		text := nameN.Utf8Text(src)
		var recv Receiver
		if obj := call.ChildByFieldName("object"); obj != nil {
			text = obj.Utf8Text(src) + "." + text
			recv = asReceiver(id, obj, src)
		}
		return text, recv, genericArgs(call.ChildByFieldName("arguments"), src)
	}
	return "", Receiver{}, nil
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

// asReceiver classifies one receiver node: a call-shaped node recurses
// through CalleeAndArgs itself, so a caller sees exactly what it would for
// an ordinary call to that same expression; anything else is a plain text
// span
func asReceiver(id language.ID, obj *sitter.Node, src []byte) Receiver {
	if slices.Contains(language.ByID(id).Grammar.CallKinds, obj.Kind()) {
		callText, _, callArgs := CalleeAndArgs(id, obj, src)
		return Receiver{CallText: callText, CallArgs: callArgs}
	}
	return Receiver{Text: obj.Utf8Text(src)}
}

func inLoop(forKinds []string, node *sitter.Node, enc *localSymbol) bool {
	var limit uint
	if enc != nil {
		limit = enc.start
	}
	for p := node.Parent(); p != nil; p = p.Parent() {
		if p.StartByte() < limit {
			return false
		}
		if slices.Contains(forKinds, p.Kind()) {
			return true
		}
	}
	return false
}
