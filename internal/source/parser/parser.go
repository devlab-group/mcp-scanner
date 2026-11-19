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
	"runtime"
	"slices"
	"time"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

// ParseTimeout is the per-file CPU-time budget shared by parsing and extraction: the CPU time of
// the thread doing the work, not the time on the clock. It bounds work on hostile syntax trees.
const ParseTimeout = 5 * time.Second

// ParseWallSafety is the wall-clock limit behind the CPU budget, far above it, for a host where
// even the CPU budget would take too long; it also bounds tree-sitter queries
const ParseWallSafety = 60 * time.Second

// wallSafety defaults to ParseWallSafety; tests lower it
var wallSafety = ParseWallSafety

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

// parseDeadline defaults to ParseTimeout; tests shorten it
var parseDeadline = ParseTimeout

// ErrParseTimeout means parsing or extraction exceeded the per-file deadline
// and is reported by Build as a resource limit in Coverage.LimitsHit
var ErrParseTimeout = errors.New("parse exceeded its per-file CPU-time budget")

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
	// TemplateConstants holds the source text of unambiguous top-level JavaScript/TypeScript
	// `const NAME = \`...${x}...\`` template literals that are not fixed strings
	TemplateConstants map[string]string
}

// localSymbol tracks a symbol's byte range so calls and decorators found later
// in the file can be attributed to it
type localSymbol struct {
	sym   *graph.Symbol
	start uint
	end   uint
}

// budget bounds the work spent on one file across parsing and extraction by the CPU time of the
// thread doing it. CPU time does not grow while the thread waits for a busy machine, so the same
// file is cut at about the same point under any load; wall-clock time was not, and a loaded host
// dropped large files that an idle one parsed. Where thread CPU time is unavailable the budget is
// wall-clock time. A wall-clock deadline far above the CPU budget stays as a safety net, and is
// what bounds tree-sitter queries, which run in C and cannot report progress.
type budget struct {
	cpuStart time.Duration
	cpuOK    bool
	wallEnd  time.Time
	start    time.Time
}

func newBudget() budget {
	cpu, ok := threadCPU()
	now := time.Now()
	return budget{cpuStart: cpu, cpuOK: ok, start: now, wallEnd: now.Add(wallSafety)}
}

func (b budget) spent() bool {
	if time.Now().After(b.wallEnd) {
		return true
	}
	if b.cpuOK {
		if cpu, ok := threadCPU(); ok {
			return cpu-b.cpuStart > parseDeadline
		}
	}
	return time.Since(b.start) > parseDeadline
}

func (b budget) err() error {
	if b.spent() {
		return ErrParseTimeout
	}
	return nil
}

// maxLoadFactor caps how much longer on the clock than in CPU time a query may run
const maxLoadFactor = 4

// matches gives q a wall-clock timeout, since a query runs in C and the CPU budget cannot stop it:
// the CPU budget left, times how much longer on the clock than in CPU time this file's work has
// taken so far (1 on an idle machine, more on a loaded one, at most maxLoadFactor), within the
// wall-clock safety limit. An idle host ends a hostile query where the CPU budget ends; a loaded
// one does not cut an ordinary query short. The CPU budget is checked again by err.
func (b budget) matches(qc *sitter.QueryCursor, q *sitter.Query, root *sitter.Node, src []byte) sitter.QueryMatches {
	limit := time.Until(b.wallEnd)
	if left, ok := b.cpuLeft(); ok {
		limit = min(limit, time.Duration(float64(left)*b.loadFactor()))
	}
	// Zero would mean no timeout at all
	qc.SetTimeoutMicros(uint64(max(limit.Microseconds(), 1)))
	return qc.Matches(q, root, src)
}

// loadFactor is wall-clock time over thread CPU time spent on this file so far, between 1 and
// maxLoadFactor; 1 until enough CPU time has been spent to measure it
func (b budget) loadFactor() float64 {
	if !b.cpuOK {
		return 1
	}
	cpu, ok := threadCPU()
	used := cpu - b.cpuStart
	if !ok || used < 20*time.Millisecond {
		return 1
	}
	return min(max(float64(time.Since(b.start))/float64(used), 1), maxLoadFactor)
}

// cpuLeft is the CPU budget not used yet, or the wall-clock budget left where CPU time is unavailable
func (b budget) cpuLeft() (time.Duration, bool) {
	if b.cpuOK {
		if cpu, ok := threadCPU(); ok {
			return max(parseDeadline-(cpu-b.cpuStart), 0), true
		}
	}
	return max(parseDeadline-time.Since(b.start), 0), true
}

// ParseTree returns a raw tree under ParseTimeout and context cancellation. The caller owns a
// non-nil returned tree and must Close it.
func ParseTree(ctx context.Context, adapter *language.Adapter, src []byte) (*sitter.Tree, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
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
	// the CPU budget reads this thread's CPU time, so the work must stay on it
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
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
		res.Constants, res.ObjectConstants, res.TemplateConstants = jsModuleConstants(root, src)
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
