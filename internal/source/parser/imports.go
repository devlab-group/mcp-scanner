package parser

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/internal/source/language"
)

func collectImports(adapter *language.Adapter, root *sitter.Node, path string, src []byte) ([]graph.Import, error) {
	q, err := adapter.Query("imports")
	if err != nil {
		return nil, err
	}
	qc := sitter.NewQueryCursor()
	defer qc.Close()

	var out []graph.Import
	matches := qc.Matches(q, root, src)
	for m := matches.Next(); m != nil; m = matches.Next() {
		for _, cap := range m.Captures {
			name := q.CaptureNames()[cap.Index]
			node := cap.Node
			switch adapter.ID {
			case language.Go:
				if name == "import" {
					out = append(out, goImport(&node, path, src)...)
				}
			case language.Python:
				if name == "import" {
					out = append(out, pythonImports(&node, path, src)...)
				}
			case language.JavaScript, language.TypeScript:
				switch name {
				case "import":
					out = append(out, jsImports(&node, path, src)...)
				case "require.path":
					if v, ok := UnquoteString(node.Utf8Text(src)); ok {
						out = append(out, graph.Import{Path: v, File: path, Line: int(node.StartPosition().Row) + 1})
					}
				}
			case language.Java:
				if name == "import" {
					out = append(out, javaImport(&node, path, src))
				}
			case language.Rust:
				if name == "import" {
					out = append(out, rustImports(&node, path, src)...)
				}
			}
		}
	}
	return out, nil
}

func goImport(node *sitter.Node, path string, src []byte) []graph.Import {
	p := node.ChildByFieldName("path")
	if p == nil {
		return nil
	}
	v, ok := UnquoteString(p.Utf8Text(src))
	if !ok {
		return nil
	}
	imp := graph.Import{Path: v, File: path, Line: int(node.StartPosition().Row) + 1}
	if n := node.ChildByFieldName("name"); n != nil {
		imp.Alias = n.Utf8Text(src)
	}
	return []graph.Import{imp}
}

func joinDotted(module, name string) string {
	if module == "" {
		return name
	}
	return module + "." + name
}

func pythonImports(node *sitter.Node, path string, src []byte) []graph.Import {
	line := int(node.StartPosition().Row) + 1
	var module string
	if node.Kind() == "import_from_statement" {
		if m := node.ChildByFieldName("module_name"); m != nil {
			module = m.Utf8Text(src)
		}
	}
	cursor := node.Walk()
	defer cursor.Close()
	var out []graph.Import
	for _, ch := range node.ChildrenByFieldName("name", cursor) {
		switch ch.Kind() {
		case "aliased_import":
			nameNode := ch.ChildByFieldName("name")
			aliasNode := ch.ChildByFieldName("alias")
			imp := graph.Import{File: path, Line: line}
			if nameNode != nil {
				imp.Path = joinDotted(module, nameNode.Utf8Text(src))
			}
			if aliasNode != nil {
				imp.Alias = aliasNode.Utf8Text(src)
			}
			out = append(out, imp)
		case "dotted_name", "identifier":
			out = append(out, graph.Import{Path: joinDotted(module, ch.Utf8Text(src)), File: path, Line: line})
		case "wildcard_import":
			out = append(out, graph.Import{Path: module + ".*", File: path, Line: line})
		}
	}
	return out
}

func jsImports(node *sitter.Node, path string, src []byte) []graph.Import {
	line := int(node.StartPosition().Row) + 1
	srcNode := node.ChildByFieldName("source")
	if srcNode == nil {
		return nil
	}
	modPath, ok := UnquoteString(srcNode.Utf8Text(src))
	if !ok {
		return nil
	}
	var out []graph.Import
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		cursor := n.Walk()
		defer cursor.Close()
		for _, ch := range n.NamedChildren(cursor) {
			child := ch
			switch child.Kind() {
			case "identifier":
				if n.Kind() == "import_clause" {
					out = append(out, graph.Import{Path: modPath, Alias: child.Utf8Text(src), File: path, Line: line})
				}
			case "namespace_import":
				if id := firstIdentifier(&child, src); id != "" {
					out = append(out, graph.Import{Path: modPath, Alias: id, File: path, Line: line})
				}
			case "import_specifier":
				nameN := child.ChildByFieldName("name")
				aliasN := child.ChildByFieldName("alias")
				imp := graph.Import{Path: modPath, File: path, Line: line}
				if aliasN != nil {
					imp.Alias = aliasN.Utf8Text(src)
				} else if nameN != nil {
					imp.Alias = nameN.Utf8Text(src)
				}
				out = append(out, imp)
			default:
				walk(&child)
			}
		}
	}
	walk(node)
	if len(out) == 0 {
		out = append(out, graph.Import{Path: modPath, File: path, Line: line})
	}
	return out
}

func javaImport(node *sitter.Node, path string, src []byte) graph.Import {
	line := int(node.StartPosition().Row) + 1
	text := strings.TrimSpace(node.Utf8Text(src))
	text = strings.TrimPrefix(text, "import")
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "static")
	text = strings.TrimSpace(text)
	text = strings.TrimSuffix(text, ";")
	return graph.Import{Path: strings.TrimSpace(text), File: path, Line: line}
}

func rustImports(node *sitter.Node, path string, src []byte) []graph.Import {
	line := int(node.StartPosition().Row) + 1
	arg := node.ChildByFieldName("argument")
	if arg == nil {
		return nil
	}
	return rustUseTree(arg, "", path, line, src)
}

// rustUseTree emits one import for each name bound by a Rust use tree. Treating a group such as
// `use std::{fs, io::Read};` as one path would resolve none of its names.
func rustUseTree(n *sitter.Node, prefix, path string, line int, src []byte) []graph.Import {
	join := func(p string) string {
		if prefix == "" {
			return p
		}
		return prefix + "::" + p
	}
	switch n.Kind() {
	case "use_as_clause":
		imp := graph.Import{File: path, Line: line}
		if p := n.ChildByFieldName("path"); p != nil {
			imp.Path = join(p.Utf8Text(src))
		}
		if a := n.ChildByFieldName("alias"); a != nil {
			imp.Alias = a.Utf8Text(src)
		}
		return []graph.Import{imp}
	case "scoped_use_list", "use_list":
		list := n
		if n.Kind() == "scoped_use_list" {
			if p := n.ChildByFieldName("path"); p != nil {
				prefix = join(p.Utf8Text(src))
			}
			if list = n.ChildByFieldName("list"); list == nil {
				return nil
			}
		}
		var out []graph.Import
		cursor := list.Walk()
		defer cursor.Close()
		for _, ch := range list.NamedChildren(cursor) {
			child := ch
			out = append(out, rustUseTree(&child, prefix, path, line, src)...)
		}
		return out
	case "self":
		// `use std::fs::{self, File}` also binds fs
		return []graph.Import{{Path: prefix, File: path, Line: line}}
	}
	return []graph.Import{{Path: join(n.Utf8Text(src)), File: path, Line: line}}
}

// attachInlineHandlers sets Arg.HandlerID on any positional argument that is itself a
// function literal - `server.tool("x", "y", async (args) => {...})`, the form the MCP SDKs'
// own examples register a handler with - by matching it against the Symbol the parser
// already recorded for that literal (every function-like node becomes its own Symbol; see
// buildSymbol)
func attachInlineHandlers(call *sitter.Node, args []graph.Arg, locals []localSymbol) {
	argsList := call.ChildByFieldName("arguments")
	if argsList == nil {
		return
	}
	cursor := argsList.Walk()
	children := argsList.NamedChildren(cursor)
	cursor.Close()
	if len(children) != len(args) {
		return
	}
	for i, ch := range children {
		for _, l := range locals {
			if l.start == ch.StartByte() {
				args[i].HandlerID = l.sym.ID
				break
			}
		}
	}
}

func collectCalls(adapter *language.Adapter, root *sitter.Node, path string, src []byte, locals []localSymbol) ([]graph.Call, error) {
	q, err := adapter.Query("calls")
	if err != nil {
		return nil, err
	}
	qc := sitter.NewQueryCursor()
	defer qc.Close()

	var out []graph.Call
	matches := qc.Matches(q, root, src)
	for m := matches.Next(); m != nil; m = matches.Next() {
		for _, cap := range m.Captures {
			node := cap.Node
			calleeText, _, args := CalleeAndArgs(adapter.ID, &node, src)
			if calleeText == "" {
				continue
			}
			attachInlineHandlers(&node, args, locals)
			enc := enclosing(node.StartByte(), locals)
			var caller graph.SymbolID
			if enc != nil {
				caller = enc.sym.ID
			}
			out = append(out, graph.Call{
				Caller:      caller,
				CalleeText:  calleeText,
				File:        path,
				Line:        int(node.StartPosition().Row) + 1,
				Args:        args,
				InLoop:      inLoop(adapter.Grammar.ForKinds, &node, enc),
				IsDecorator: node.Parent() != nil && node.Parent().Kind() == "decorator",
			})
		}
	}
	return out, nil
}
