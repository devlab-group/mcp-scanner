// Package parser turns one source file into symbols, imports and calls using
// the language's tree-sitter grammar and queries. It does not resolve calls
// across files or discover MCP registrations; see Resolve and the
// registration package for those, which both operate on the whole graph
// after every file has been parsed.
package parser

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/internal/source/language"
)

// ParseTimeout bounds how long one file may spend inside tree-sitter. A progress callback enforces
// it within the cgo parse, where a Go deadline cannot preempt pathological grammar work.
const ParseTimeout = 5 * time.Second

// parseDeadline defaults to ParseTimeout; tests shorten it to avoid depending on machine speed
var parseDeadline = ParseTimeout

// ErrParseTimeout means ParseFile aborted because ParseTimeout elapsed
// before the parse finished. Distinguished from a plain parse failure so
// the caller can record it as a resource limit (Coverage.LimitsHit)
// rather than an unexplained one.
var ErrParseTimeout = errors.New("parse exceeded its per-file deadline")

// FileResult is what parsing one file produces, before cross-file resolution
type FileResult struct {
	Path     string
	Language language.ID
	Imports  []graph.Import
	Symbols  []*graph.Symbol
	Calls    []graph.Call

	// HasSyntaxErrors means tree-sitter produced a tree but part of it did
	// not parse cleanly; the result below is still the best effort from the
	// rest of the file
	HasSyntaxErrors bool
}

// localSymbol tracks a symbol's byte range in its own file, so calls and
// decorators found later in the same file can be attributed to it
type localSymbol struct {
	sym   *graph.Symbol
	start uint
	end   uint
}

// ParseTree returns a raw tree under ParseTimeout and context cancellation. The caller owns a
// non-nil returned tree and must Close it.
func ParseTree(ctx context.Context, adapter *language.Adapter, src []byte) (*sitter.Tree, error) {
	lang, err := adapter.Language()
	if err != nil {
		return nil, err
	}

	p := sitter.NewParser()
	defer p.Close()
	if err := p.SetLanguage(lang); err != nil {
		return nil, fmt.Errorf("setting language: %w", err)
	}

	deadline := time.Now().Add(parseDeadline)
	length := len(src)
	tree := p.ParseWithOptions(func(i int, _ sitter.Point) []byte {
		if i < length {
			return src[i:]
		}
		return []byte{}
	}, nil, &sitter.ParseOptions{
		ProgressCallback: func(sitter.ParseState) bool {
			return ctx.Err() != nil || time.Now().After(deadline)
		},
	})
	if tree == nil {
		if time.Now().After(deadline) {
			return nil, ErrParseTimeout
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("parse cancelled: %w", err)
		}
		return nil, fmt.Errorf("parser produced no tree")
	}
	return tree, nil
}

// ParseFile parses one file and returns its extracted FileResult. Total failure, timeout, or
// cancellation returns an error; local syntax damage may still return a result whose syntax-error
// flag becomes a coverage gap.
func ParseFile(ctx context.Context, adapter *language.Adapter, path string, src []byte) (*FileResult, error) {
	tree, err := ParseTree(ctx, adapter, src)
	if err != nil {
		return nil, err
	}
	defer tree.Close()
	root := tree.RootNode()

	res := &FileResult{Path: path, Language: adapter.ID, HasSyntaxErrors: root.HasError()}

	locals, err := collectSymbols(adapter, root, path, src)
	if err != nil {
		return nil, err
	}
	res.Symbols = make([]*graph.Symbol, 0, len(locals))
	for _, l := range locals {
		res.Symbols = append(res.Symbols, l.sym)
	}

	if adapter.HasQuery("decorators") {
		if err := attachDecorators(adapter, root, src, locals); err != nil {
			return nil, err
		}
	}

	imports, err := collectImports(adapter, root, path, src)
	if err != nil {
		return nil, err
	}
	res.Imports = imports

	calls, err := collectCalls(adapter, root, path, src, locals)
	if err != nil {
		return nil, err
	}
	res.Calls = calls

	return res, nil
}

func enclosing(pos uint, locals []localSymbol) *localSymbol {
	var best *localSymbol
	for i := range locals {
		l := &locals[i]
		if pos >= l.start && pos < l.end {
			if best == nil || (l.end-l.start) < (best.end-best.start) {
				best = l
			}
		}
	}
	return best
}

func collectSymbols(adapter *language.Adapter, root *sitter.Node, path string, src []byte) ([]localSymbol, error) {
	q, err := adapter.Query("symbols")
	if err != nil {
		return nil, err
	}
	qc := sitter.NewQueryCursor()
	defer qc.Close()

	var locals []localSymbol
	matches := qc.Matches(q, root, src)
	for m := matches.Next(); m != nil; m = matches.Next() {
		for _, cap := range m.Captures {
			name := q.CaptureNames()[cap.Index]
			node := cap.Node
			kind := graph.KindFunction
			switch name {
			case "method":
				kind = graph.KindMethod
			case "class":
				kind = graph.KindClass
			}
			sym := buildSymbol(adapter, &node, kind, path, src)
			locals = append(locals, localSymbol{sym: sym, start: node.StartByte(), end: node.EndByte()})
		}
	}
	return locals, nil
}

func buildSymbol(adapter *language.Adapter, node *sitter.Node, kind graph.SymbolKind, path string, src []byte) *graph.Symbol {
	name := DefName(adapter.ID, node, src)
	if name == "" {
		name = "<anonymous>"
	}
	line := int(node.StartPosition().Row) + 1
	params := paramNames(adapter.ID, ParamList(node), src)
	if len(params) > 0 && HasImplicitReceiver(adapter.ID, node, src) {
		// Params lines up with the arguments at a call site, and nobody
		// passes self
		params = params[1:]
	}
	sym := &graph.Symbol{
		Kind:          kind,
		Name:          name,
		File:          path,
		Line:          line,
		EndLine:       int(node.EndPosition().Row) + 1,
		Params:        params,
		Doc:           leadingDoc(adapter.ID, node, src),
		ReturnLiteral: returnLiteral(adapter.ID, node, src),
		ReturnText:    returnText(adapter.ID, node, src),
	}
	sym.ID = graph.MakeSymbolID(path, name, line)

	if kind == graph.KindMethod {
		if cls := enclosingClass(adapter.Grammar.ClassKinds, node); cls != nil {
			sym.Receiver = DefName(adapter.ID, cls, src)
		}
	}
	if adapter.ID == language.Go {
		if recv := node.ChildByFieldName("receiver"); recv != nil {
			sym.Receiver = receiverType(recv, src)
			sym.Kind = graph.KindMethod
		}
	}
	if adapter.ID == language.Java {
		sym.Decorators = javaAnnotations(node, src)
	}
	if adapter.ID == language.Rust {
		sym.Decorators = rustAttributes(node, src)
	}
	return sym
}

func enclosingClass(classKinds []string, node *sitter.Node) *sitter.Node {
	for p := node.Parent(); p != nil; p = p.Parent() {
		if slices.Contains(classKinds, p.Kind()) {
			return p
		}
	}
	return nil
}
