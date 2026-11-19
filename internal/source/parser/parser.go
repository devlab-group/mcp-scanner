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

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

// ParseTimeout is the per-file deadline shared by parsing and extraction.
// A progress callback checks it during cgo parsing, and tree-sitter queries use
// the remaining time as their timeout because Go cannot preempt that C work.
// Extraction also checks the deadline to bound work on hostile syntax trees.
const ParseTimeout = 5 * time.Second

// CopiedTextFactor sets the size-dependent budget for copied call text;
// collectCalls adds a fixed allowance. Source spans share the file buffer, but
// decoded literals and reconstructed callees allocate text that can grow faster
// than the input on deeply nested files.
const CopiedTextFactor = 4

// ErrTextLimit means extracted call text exceeded the budget in collectCalls
// and is reported by Build as a resource limit in Coverage.LimitsHit
var ErrTextLimit = errors.New("call text exceeded its per-file limit")

// MaxTreeDepth rejects deeply nested syntax trees before queries run.
// Tree-sitter stores query match depths in 16 bits and can silently lose matches
// beyond that range. This limit leaves a margin below the overflow boundary.
const MaxTreeDepth = 1 << 15

// ErrDepthLimit means the syntax tree exceeded MaxTreeDepth and is reported
// by Build as a resource limit in Coverage.LimitsHit
var ErrDepthLimit = errors.New("syntax tree exceeded the per-file depth limit")

// parseDeadline defaults to ParseTimeout; tests shorten it to avoid depending on machine speed
var parseDeadline = ParseTimeout

// ErrParseTimeout means parsing or extraction exceeded the per-file deadline
// and is reported by Build as a resource limit in Coverage.LimitsHit
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

	// Constants holds unambiguous same-file string constants from Python, Java, Rust,
	// JavaScript/TypeScript and Go
	Constants map[string]string
	// ObjectConstants holds the source text of unambiguous top-level JavaScript/TypeScript
	// `const NAME = { ... }` object literals, for callers that read fields such as description
	ObjectConstants map[string]string
}

// localSymbol tracks a symbol's byte range so calls and decorators found later
// in the file can be attributed to it
type localSymbol struct {
	sym   *graph.Symbol
	start uint
	end   uint
}

// budget shares one deadline across parsing and extraction. Extraction checks
// elapsed time; parsing also checks the scan context, as Build does between files.
type budget struct {
	deadline time.Time
}

func newBudget() budget {
	return budget{deadline: time.Now().Add(parseDeadline)}
}

func (b budget) spent() bool {
	return time.Now().After(b.deadline)
}

func (b budget) err() error {
	if b.spent() {
		return ErrParseTimeout
	}
	return nil
}

// matches gives q the remaining wall-clock budget. Time spent by the caller
// between Next calls counts toward the timeout; Next stops returning matches
// after the timeout is detected.
func (b budget) matches(qc *sitter.QueryCursor, q *sitter.Query, root *sitter.Node, src []byte) sitter.QueryMatches {
	// Zero would mean no timeout at all
	qc.SetTimeoutMicros(uint64(max(time.Until(b.deadline).Microseconds(), 1)))
	return qc.Matches(q, root, src)
}

// ParseTree returns a raw tree under ParseTimeout and context cancellation. The caller owns a
// non-nil returned tree and must Close it.
func ParseTree(ctx context.Context, adapter *language.Adapter, src []byte) (*sitter.Tree, error) {
	return parseTree(ctx, newBudget(), adapter, src)
}

func parseTree(ctx context.Context, b budget, adapter *language.Adapter, src []byte) (*sitter.Tree, error) {
	lang, err := adapter.Language()
	if err != nil {
		return nil, err
	}

	p := sitter.NewParser()
	defer p.Close()
	if err := p.SetLanguage(lang); err != nil {
		return nil, fmt.Errorf("setting language: %w", err)
	}

	length := len(src)
	tree := p.ParseWithOptions(func(i int, _ sitter.Point) []byte {
		if i < length {
			return src[i:]
		}
		return []byte{}
	}, nil, &sitter.ParseOptions{
		ProgressCallback: func(sitter.ParseState) bool {
			return ctx.Err() != nil || b.spent()
		},
	})
	if tree == nil {
		if b.spent() {
			return nil, ErrParseTimeout
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("parse cancelled: %w", err)
		}
		return nil, fmt.Errorf("parser produced no tree")
	}
	if err := checkDepth(b, tree.RootNode()); err != nil {
		tree.Close()
		return nil, err
	}
	return tree, nil
}

// checkDepth rejects trees deeper than MaxTreeDepth before a query can silently
// return incomplete matches
func checkDepth(b budget, root *sitter.Node) error {
	c := root.Walk()
	defer c.Close()
	depth := 0
	for visited := 1; ; visited++ {
		if visited%4096 == 0 && b.spent() {
			return ErrParseTimeout
		}
		if c.GotoFirstChild() {
			if depth++; depth > MaxTreeDepth {
				return ErrDepthLimit
			}
			continue
		}
		for !c.GotoNextSibling() {
			if !c.GotoParent() {
				return nil
			}
			depth--
		}
	}
}

// ParseFile parses one file and returns its extracted FileResult. Total failure, timeout, or
// cancellation returns an error; local syntax damage may still return a result whose syntax-error
// flag becomes a coverage gap.
func ParseFile(ctx context.Context, adapter *language.Adapter, path string, src []byte) (*FileResult, error) {
	b := newBudget()
	tree, err := parseTree(ctx, b, adapter, src)
	if err != nil {
		return nil, err
	}
	defer tree.Close()
	root := tree.RootNode()

	res := &FileResult{Path: path, Language: adapter.ID, HasSyntaxErrors: root.HasError()}

	locals, err := collectSymbols(b, adapter, root, path, src)
	if err != nil {
		return nil, err
	}
	res.Symbols = make([]*graph.Symbol, 0, len(locals))
	for _, l := range locals {
		res.Symbols = append(res.Symbols, l.sym)
	}

	if adapter.HasQuery("decorators") {
		if err := attachDecorators(b, adapter, root, src, locals); err != nil {
			return nil, err
		}
	}

	imports, err := collectImports(b, adapter, root, path, src)
	if err != nil {
		return nil, err
	}
	res.Imports = imports

	calls, err := collectCalls(b, adapter, root, path, src, locals)
	if err != nil {
		return nil, err
	}
	res.Calls = calls

	switch adapter.ID {
	case language.Python:
		res.Constants = pythonModuleConstants(root, src)
	case language.Java:
		res.Constants = javaConstants(root, src)
	case language.Rust:
		res.Constants = rustConstants(root, src)
	case language.JavaScript, language.TypeScript:
		res.Constants, res.ObjectConstants = jsModuleConstants(root, src)
	case language.Go:
		res.Constants = goFileConstants(root, src)
	}
	// A timed-out query ends like an exhausted one, so check the budget before returning.
	// Constant extraction does not check the deadline during its walks.
	if err := b.err(); err != nil {
		return nil, err
	}
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

func collectSymbols(b budget, adapter *language.Adapter, root *sitter.Node, path string, src []byte) ([]localSymbol, error) {
	q, err := adapter.Query("symbols")
	if err != nil {
		return nil, err
	}
	qc := sitter.NewQueryCursor()
	defer qc.Close()

	var locals []localSymbol
	matches := b.matches(qc, q, root, src)
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
		sym.Decorators, sym.DecoratorArgs = javaAnnotations(node, src)
	}
	if adapter.ID == language.Rust {
		sym.Decorators, sym.DecoratorArgs = rustAttributes(node, src)
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
