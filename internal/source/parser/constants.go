package parser

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// runtimeRebinders lists names that may mutate module globals without a visible
// assignment, as in globals()["X"] = ..., exec("X = ...") or setattr(module, "X", ...)
var runtimeRebinders = map[string]bool{
	"globals": true, "vars": true, "exec": true, "eval": true, "setattr": true,
	"__dict__": true, "__import__": true,
}

// pythonModuleConstants resolves module-level NAME = "literal" assignments
// only when the name has no other binding anywhere in the file. Local bindings,
// regardless of order, invalidate it; star imports and recognized runtime
// rebinding names invalidate all candidates. Uncertain values stay unresolved
// so coverage reports a gap instead of claiming the wrong text was analyzed.
func pythonModuleConstants(root *sitter.Node, src []byte) map[string]string {
	candidates := map[string]string{}
	for _, stmt := range nonCommentChildren(root) {
		if stmt.Kind() != "expression_statement" || stmt.NamedChildCount() != 1 {
			continue
		}
		asg := stmt.NamedChild(0)
		if asg.Kind() != "assignment" {
			continue
		}
		left, right := asg.ChildByFieldName("left"), asg.ChildByFieldName("right")
		if left == nil || right == nil || left.Kind() != "identifier" {
			continue
		}
		if v, ok := LiteralValue(right, src); ok {
			candidates[left.Utf8Text(src)] = v
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	bindings := map[string]int{}
	dynamic := false
	// Carry binding context downward to avoid repeated Node.Parent searches from the root.
	// Treat every identifier inside an assignment target as bound, even a read-only subscript
	// index: rejecting an uncertain constant is safer than resolving it incorrectly.
	var walk func(n *sitter.Node, bind bool)
	walk = func(n *sitter.Node, bind bool) {
		var binder *sitter.Node
		switch n.Kind() {
		case "wildcard_import":
			dynamic = true
		case "identifier":
			name := n.Utf8Text(src)
			if runtimeRebinders[name] {
				dynamic = true
			}
			if _, ok := candidates[name]; ok && bind {
				bindings[name]++
			}
		case "assignment", "augmented_assignment", "for_statement", "for_in_clause":
			binder = n.ChildByFieldName("left")
		case "named_expression", "function_definition", "class_definition":
			binder = n.ChildByFieldName("name")
		case "import_statement", "import_from_statement", "future_import_statement",
			"global_statement", "nonlocal_statement", "delete_statement",
			"as_pattern_target", "case_pattern", "parameters", "lambda_parameters",
			"type_alias_statement", "type_parameter":
			bind = true
		}
		for i := range n.ChildCount() {
			if ch := n.Child(i); ch != nil {
				walk(ch, bind || binder != nil && ch.Id() == binder.Id())
			}
		}
	}
	walk(root, false)
	if dynamic {
		return nil
	}

	out := map[string]string{}
	for name, v := range candidates {
		if bindings[name] == 1 {
			out[name] = v
		}
	}
	return out
}

// javaConstants resolves static final String fields and interface string
// constants whose names no other field in the file declares. Duplicate field
// names are ambiguous because class scope is not modeled; locals and parameters
// are outside this field-based lookup.
func javaConstants(root *sitter.Node, src []byte) map[string]string {
	candidates := map[string]string{}
	declared := map[string]int{}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n.Kind() == "field_declaration" || n.Kind() == "constant_declaration" {
			constant := n.Kind() == "constant_declaration" || hasModifiers(n, src, "static", "final")
			typ := n.ChildByFieldName("type")
			isString := typ != nil && typ.Utf8Text(src) == "String"
			cursor := n.Walk()
			decls := n.ChildrenByFieldName("declarator", cursor)
			cursor.Close()
			for _, d := range decls {
				name := d.ChildByFieldName("name")
				if name == nil {
					continue
				}
				declared[name.Utf8Text(src)]++
				if !constant || !isString {
					continue
				}
				if val := d.ChildByFieldName("value"); val != nil {
					if v, ok := javaConstantString(val, src); ok {
						candidates[name.Utf8Text(src)] = v
					}
				}
			}
		}
		for i := range n.NamedChildCount() {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	return uniqueConstants(candidates, declared)
}

// javaConstantString reads string literals and their + concatenations,
// with optional parentheses
func javaConstantString(n *sitter.Node, src []byte) (string, bool) {
	switch n.Kind() {
	case "binary_expression":
		left, op, right := n.ChildByFieldName("left"), n.ChildByFieldName("operator"), n.ChildByFieldName("right")
		if left == nil || op == nil || right == nil || op.Utf8Text(src) != "+" {
			return "", false
		}
		l, ok := javaConstantString(left, src)
		if !ok {
			return "", false
		}
		r, ok := javaConstantString(right, src)
		return l + r, ok
	case "parenthesized_expression":
		if inner := nonCommentChildren(n); len(inner) == 1 {
			return javaConstantString(inner[0], src)
		}
		return "", false
	}
	return LiteralValue(n, src)
}

func hasModifiers(n *sitter.Node, src []byte, want ...string) bool {
	for i := range n.NamedChildCount() {
		m := n.NamedChild(i)
		if m.Kind() != "modifiers" {
			continue
		}
		have := map[string]bool{}
		for j := range m.ChildCount() {
			have[m.Child(j).Utf8Text(src)] = true
		}
		for _, w := range want {
			if !have[w] {
				return false
			}
		}
		return true
	}
	return false
}

// rustConstants resolves const and static &str items with unique names in the
// file. Duplicates in nested modules also invalidate the name because module
// scope is not modeled.
func rustConstants(root *sitter.Node, src []byte) map[string]string {
	candidates := map[string]string{}
	declared := map[string]int{}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n.Kind() == "const_item" || n.Kind() == "static_item" {
			name, typ, val := n.ChildByFieldName("name"), n.ChildByFieldName("type"), n.ChildByFieldName("value")
			if name != nil {
				declared[name.Utf8Text(src)]++
				if typ != nil && typ.Kind() == "reference_type" && val != nil {
					if inner := typ.ChildByFieldName("type"); inner != nil && inner.Utf8Text(src) == "str" {
						if v, ok := LiteralValue(val, src); ok {
							candidates[name.Utf8Text(src)] = v
						}
					}
				}
			}
		}
		for i := range n.NamedChildCount() {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	return uniqueConstants(candidates, declared)
}

func uniqueConstants(candidates map[string]string, declared map[string]int) map[string]string {
	out := map[string]string{}
	for name, v := range candidates {
		if declared[name] == 1 {
			out[name] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
