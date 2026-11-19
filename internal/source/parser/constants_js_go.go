package parser

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// jsBindingContainers are JavaScript/TypeScript nodes whose identifiers bind a name rather than
// read one: parameters, destructuring patterns, imports and catch bindings. Every identifier
// inside one is counted as a binding - a default value that only reads a name is counted too,
// which can only reject a constant, never resolve a wrong one.
var jsBindingContainers = map[string]bool{
	"formal_parameters": true, "object_pattern": true, "array_pattern": true,
	"import_clause": true, "import_specifier": true, "namespace_import": true,
	"catch_clause": true,
}

// jsModuleConstants resolves top-level `const NAME = "literal"` (also exported, or `as const`) and
// `const NAME = { ... }` declarations whose name is bound exactly once anywhere in the file. Any
// other binding of the same name - a parameter, a local variable, an import, a destructured
// field - leaves it unresolved, so a shadowed name is never read as the module constant. Object
// literals are returned as their source text for callers that read single fields from them.
func jsModuleConstants(root *sitter.Node, src []byte) (map[string]string, map[string]string) {
	strs, objs := map[string]string{}, map[string]string{}
	for _, stmt := range nonCommentChildren(root) {
		decl := stmt
		if decl.Kind() == "export_statement" {
			decl = decl.ChildByFieldName("declaration")
			if decl == nil {
				continue
			}
		}
		if decl.Kind() != "lexical_declaration" || !isConstDeclaration(decl, src) {
			continue
		}
		for _, d := range nonCommentChildren(decl) {
			if d.Kind() != "variable_declarator" {
				continue
			}
			name, value := d.ChildByFieldName("name"), d.ChildByFieldName("value")
			if name == nil || value == nil || name.Kind() != "identifier" {
				continue
			}
			for value.Kind() == "as_expression" || value.Kind() == "satisfies_expression" || value.Kind() == "parenthesized_expression" {
				inner := value.NamedChild(0)
				if inner == nil {
					break
				}
				value = inner
			}
			if v, ok := LiteralValue(value, src); ok {
				strs[name.Utf8Text(src)] = v
			} else if value.Kind() == "object" || value.Kind() == "array" {
				// an array too: `export const tools = [{ name: "...", description: "..." }]`
				// is what a low-level server's tools/list handler returns
				objs[name.Utf8Text(src)] = value.Utf8Text(src)
			}
		}
	}
	if len(strs) == 0 && len(objs) == 0 {
		return nil, nil
	}

	bindings := map[string]int{}
	count := func(n *sitter.Node) {
		if n != nil && (n.Kind() == "identifier" || n.Kind() == "shorthand_property_identifier_pattern") {
			bindings[n.Utf8Text(src)]++
		}
	}
	var walk func(n *sitter.Node, binding bool)
	walk = func(n *sitter.Node, binding bool) {
		if binding {
			count(n)
		}
		switch n.Kind() {
		case "variable_declarator":
			if name := n.ChildByFieldName("name"); name != nil {
				if name.Kind() == "identifier" {
					count(name)
				} else {
					walk(name, true)
				}
			}
			if v := n.ChildByFieldName("value"); v != nil {
				walk(v, false)
			}
			return
		case "function_declaration", "generator_function_declaration", "class_declaration", "function_expression", "class":
			count(n.ChildByFieldName("name"))
		case "arrow_function":
			if p := n.ChildByFieldName("parameter"); p != nil {
				count(p)
			}
		case "assignment_expression", "augmented_assignment_expression":
			if left := n.ChildByFieldName("left"); left != nil && left.Kind() == "identifier" {
				count(left)
			}
		case "for_in_statement":
			if left := n.ChildByFieldName("left"); left != nil {
				walk(left, true)
			}
		}
		for i := range n.NamedChildCount() {
			ch := n.NamedChild(i)
			if ch == nil {
				continue
			}
			walk(ch, binding || jsBindingContainers[n.Kind()])
		}
	}
	walk(root, false)

	keep := func(m map[string]string) map[string]string {
		out := map[string]string{}
		for name, v := range m {
			if bindings[name] == 1 {
				out[name] = v
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return keep(strs), keep(objs)
}

func isConstDeclaration(decl *sitter.Node, src []byte) bool {
	if kind := decl.ChildByFieldName("kind"); kind != nil {
		return kind.Utf8Text(src) == "const"
	}
	return decl.ChildCount() > 0 && decl.Child(0).Utf8Text(src) == "const"
}

// goFileConstants resolves package-level `const name = "literal"` specs, alone or in a const
// block, whose name is declared exactly once in the file. Go constants are package-scoped and
// may live in another file of the package; those stay unresolved, which reports a gap rather
// than guessing.
func goFileConstants(root *sitter.Node, src []byte) map[string]string {
	candidates := map[string]string{}
	declared := map[string]int{}
	var walk func(n *sitter.Node, topLevel bool)
	walk = func(n *sitter.Node, topLevel bool) {
		switch n.Kind() {
		case "const_spec", "var_spec":
			names := n.ChildrenByFieldName("name", n.Walk())
			for i := range names {
				declared[names[i].Utf8Text(src)]++
			}
			if n.Kind() == "const_spec" && topLevel && len(names) == 1 {
				if vals := n.ChildByFieldName("value"); vals != nil && vals.NamedChildCount() == 1 {
					if v, ok := LiteralValue(vals.NamedChild(0), src); ok {
						candidates[names[0].Utf8Text(src)] = v
					}
				}
			}
		case "short_var_declaration", "parameter_declaration", "variadic_parameter_declaration", "range_clause":
			left := n.ChildByFieldName("left")
			if left == nil {
				left = n.ChildByFieldName("name")
			}
			if left != nil {
				var ids func(m *sitter.Node)
				ids = func(m *sitter.Node) {
					if m.Kind() == "identifier" {
						declared[m.Utf8Text(src)]++
					}
					for i := range m.NamedChildCount() {
						if ch := m.NamedChild(i); ch != nil {
							ids(ch)
						}
					}
				}
				ids(left)
			}
		}
		for i := range n.NamedChildCount() {
			ch := n.NamedChild(i)
			if ch == nil {
				continue
			}
			// Only a const declaration directly in the source file is package level
			walk(ch, n.Kind() == "source_file" || (topLevel && (n.Kind() == "const_declaration" || n.Kind() == "var_declaration")))
		}
	}
	walk(root, false)
	return uniqueConstants(candidates, declared)
}
