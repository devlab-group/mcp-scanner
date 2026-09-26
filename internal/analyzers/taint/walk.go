package taint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/internal/source/language"
	"github.com/revinand/mcp-scanner/internal/source/parser"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// maxDepth bounds interprocedural recursion. The visited set already stops
// cycles; this is a second, independent limit against a pathologically deep
// (but acyclic) call chain in a hostile tree.
const maxDepth = 8

// maxSeedsPerSymbol bounds how many distinct tainted-parameter combinations one symbol is
// walked with in a single run. Hostile fan-in cannot grow work without bound, and hitting the
// cap is recorded in Coverage.LimitsHit rather than silently dropping later traces.
const maxSeedsPerSymbol = 8

// taintInfo is what the walker knows about one tainted value: how sure it is, the ordered
// path that got it here, which sink categories a strong sanitizer upstream has already
// cleared it for, and whether it has passed through a call that removes ".." segments or
// resolves symlinks down to a real path. clearedFor maps are copied before mutation so branch
// states can share a value without changing one another.
type taintInfo struct {
	confidence float64
	chain      []model.FlowStep
	clearedFor map[string]bool

	// normalized is set by sanitizer patterns marked normalizes. It survives ordinary propagation,
	// but concatenation, recognized decoders, and worstTaint clear it because the resulting path is
	// no longer known to be normalized.
	normalized bool
}

func (t taintInfo) extend(step model.FlowStep, confidenceMult float64) taintInfo {
	chain := make([]model.FlowStep, len(t.chain), len(t.chain)+1)
	copy(chain, t.chain)
	chain = append(chain, step)
	return taintInfo{confidence: t.confidence * confidenceMult, chain: chain, clearedFor: t.clearedFor, normalized: t.normalized}
}

// clearFor returns t with categories added to clearedFor, the way a strong
// sanitizer call's covers already does in handleAssign - used by
// handleContainmentGuard (containment.go) to clear path_traversal from a
// variable a guard clause has just proven stays under its root, without
// the new flow step a real sanitizer call gets: nothing about how the
// value was computed changed here, only what later control flow proves
// about it
func (t taintInfo) clearFor(categories ...string) taintInfo {
	return taintInfo{confidence: t.confidence, chain: t.chain, clearedFor: mergeClearedFor(t.clearedFor, categories), normalized: t.normalized}
}

// withoutCategory returns existing minus category, as a new map for the
// same reason mergeClearedFor builds one: the caller's map is shared by
// reference with every taintInfo derived from the same source, and
// dropping a category in place would un-clear it for all of them
func withoutCategory(existing map[string]bool, category string) map[string]bool {
	if !existing[category] {
		return existing
	}
	remaining := make(map[string]bool, len(existing))
	for c := range existing {
		if c != category {
			remaining[c] = true
		}
	}
	return remaining
}

// mergeClearedFor returns existing plus every category in add, as a new
// map so the caller's own clearedFor (shared by reference with other
// taintInfo values derived from the same source) is never mutated
func mergeClearedFor(existing map[string]bool, add []string) map[string]bool {
	if len(add) == 0 {
		return existing
	}
	merged := make(map[string]bool, len(existing)+len(add))
	maps.Copy(merged, existing)
	for _, c := range add {
		merged[c] = true
	}
	return merged
}

// intersectClearedFor is mergeClearedFor's counterpart for combining two
// values rather than adding a sanitizer's covers to one. A string built
// from two tainted names is only cleared for a category when both operands
// were: quoting one of two interpolated arguments protects that argument,
// not the expression.
func intersectClearedFor(a, b map[string]bool) map[string]bool {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	var out map[string]bool
	for c := range a {
		if !b[c] {
			continue
		}
		if out == nil {
			out = make(map[string]bool, len(a))
		}
		out[c] = true
	}
	return out
}

// worstTaint merges confidence while intersecting both values' sanitizer guarantees
func worstTaint(a, b taintInfo) taintInfo {
	out := a
	if b.confidence < a.confidence {
		out = b
	}
	out.clearedFor = intersectClearedFor(a.clearedFor, b.clearedFor)
	out.normalized = a.normalized && b.normalized
	return out
}

// parsedFile stays cached for the run because recursive callers retain tree
// nodes. Source inventory byte limits bound the non-evicting cache.
type parsedFile struct {
	adapter *language.Adapter
	src     []byte
	root    *sitter.Node
	close   func()
	defs    []defSite
}

type defSite struct {
	node *sitter.Node
	name string
	line int
}

// seedKey identifies a symbol and parameter-name set. Values are excluded so
// changing confidence cannot bypass maxSeedsPerSymbol.
type seedKey struct {
	sym  graph.SymbolID
	seed string // sorted, comma-joined seeded parameter names; "" for no seed at all
}

func seedKeyFor(sym graph.SymbolID, seed map[string]taintInfo) seedKey {
	if len(seed) == 0 {
		return seedKey{sym: sym}
	}
	names := slices.Sorted(maps.Keys(seed))
	return seedKey{sym: sym, seed: strings.Join(names, ",")}
}

// ctx carries the state shared across one analyzer run: the graph, the file
// cache, which (symbol, seed) combinations have already been walked (so a
// cycle or a diamond in the call graph is only analyzed once per distinct
// seed), and the findings collected so far
type ctx struct {
	g   *graph.Graph
	idx map[string][]graph.SymbolID
	// root is g.Root opened once so every reopened source file goes through it.
	// readSource fails if opening it fails after source.Build already walked it.
	root  *os.Root
	files map[string]*parsedFile

	// runCtx carries cancellation into taint's own reparsing
	runCtx context.Context

	// These counters describe taint's own capped, timed-out, or unreadable
	// reparses. They become limits, not capability skips.
	sizeCapped, parseTimedOut, unreadable int
	sizeCap                               int64

	// visited guards interprocedural recursion: a given (symbol, seed)
	// combination is walked at most once. seedCounts bounds how many
	// distinct non-empty seeds one symbol accumulates in a run - see
	// maxSeedsPerSymbol - and seedCapHit records whether that bound was
	// ever reached, for taintCoverage to report as a limit
	visited    map[seedKey]bool
	seedCounts map[graph.SymbolID]int
	seedCapHit bool

	// depthCapHit records a tainted flow that stopped at maxDepth. Recursion requires a non-empty
	// seed, so every hit represents an untraced continuation.
	depthCapHit bool

	// ambiguousCalls counts calls that received tainted input and whose
	// callee matched more than one definition by name with nothing to
	// choose between them. The trace ends there, so it is a blind spot,
	// and taintCoverage reports it as one rather than letting it pass for
	// "nothing found".
	ambiguousCalls int

	// visitedSyms records every symbol walked at least once, regardless of
	// which seed - the driver loop (taint.go) uses it to avoid seeding a
	// symbol from the top level a second time once interprocedural
	// recursion already reached it, and taintCoverage uses it to tell
	// "this handler's body was never even found" from "it was found and
	// walked"
	visitedSyms map[graph.SymbolID]bool

	// aliases maps local names bound directly to known sinks or promisify wrappers. Module aliases
	// and sinks passed as values are the other two shapes that rewrite sink text before matching.
	aliases map[fileAlias]string

	// moduleAliases maps a local module name to the module path it stands
	// for - `import subprocess as sp` - so `sp.run` can be matched as
	// `subprocess.run`. Separate from aliases, which binds a whole callee
	// name, because this one rewrites a prefix.
	moduleAliases map[fileAlias]string

	// objects maps a local name to the object-literal text it was bound
	// to, so `const opts = { shell: true }` used three lines down can be
	// read at the call site that passes it
	objects map[fileAlias]string

	findings []model.Finding

	// seeded records which capability handlers actually received a
	// non-empty taint seed, as opposed to merely having been visited -
	// a handler walked with nothing seeded analyzed nothing an attacker
	// controls, and coverage must not call that "analyzed"
	seeded map[graph.SymbolID]bool
}

func newCtx(runCtx context.Context, g *graph.Graph) *ctx {
	idx := map[string][]graph.SymbolID{}
	for id, sym := range g.Symbols {
		idx[sym.Name] = append(idx[sym.Name], id)
	}
	c := &ctx{
		g: g, idx: idx, runCtx: runCtx,
		files:         map[string]*parsedFile{},
		visited:       map[seedKey]bool{},
		seedCounts:    map[graph.SymbolID]int{},
		visitedSyms:   map[graph.SymbolID]bool{},
		seeded:        map[graph.SymbolID]bool{},
		aliases:       map[fileAlias]string{},
		moduleAliases: map[fileAlias]string{},
		objects:       map[fileAlias]string{},
	}
	if g.Root != "" {
		if r, err := os.OpenRoot(g.Root); err == nil {
			c.root = r
		}
	}
	return c
}

func (c *ctx) closeAll() {
	for _, pf := range c.files {
		// fileFor caches a nil for every file it could not read or parse,
		// so the failure is remembered rather than retried; there is no
		// tree behind those to close
		if pf != nil {
			pf.close()
		}
	}
	if c.root != nil {
		c.root.Close()
	}
}

// readSource reopens path - relative to the graph's own root - through c.root when it was
// opened successfully, so a path this package did not choose itself is checked to stay
// under the scan root the same way the archive extractor already is. maxBytes preserves the
// inventory limit when this later pass reopens a file that was only partially parsed.
func (c *ctx) readSource(path string, maxBytes int64) ([]byte, error) {
	var f *os.File
	var err error
	switch {
	case c.root != nil:
		f, err = c.root.Open(path)
	case c.g.Root == "":
		f, err = os.Open(path)
	default:
		return nil, fmt.Errorf("taint: scan root %q could not be opened", c.g.Root)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if maxBytes <= 0 {
		return io.ReadAll(f)
	}
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

func (c *ctx) fileFor(path string) *parsedFile {
	if pf, ok := c.files[path]; ok {
		return pf
	}
	f := c.g.Files[path]
	if f == nil {
		c.unreadable++
		c.files[path] = nil
		return nil
	}
	adapter := language.ByID(language.ID(f.Language))
	if adapter == nil {
		c.unreadable++
		c.files[path] = nil
		return nil
	}
	src, err := c.readSource(path, f.MaxBytes)
	if err != nil {
		c.unreadable++
		c.files[path] = nil
		return nil
	}
	if f.MaxBytes > 0 {
		c.sizeCapped++
		c.sizeCap = max(c.sizeCap, f.MaxBytes)
	}
	tree, err := parser.ParseTree(c.runCtx, adapter, src)
	if err != nil {
		if errors.Is(err, parser.ErrParseTimeout) {
			c.parseTimedOut++
		} else {
			c.unreadable++
		}
		c.files[path] = nil
		return nil
	}
	root := tree.RootNode()
	pf := &parsedFile{
		adapter: adapter, src: src, root: root,
		close: func() { tree.Close() },
		defs:  findDefs(adapter, root, src),
	}
	c.files[path] = pf
	c.recordFileAliases(pf, path)
	return pf
}

// findDefs locates every function/method definition node in a parsed file,
// the same query the source parser itself uses, so a symbol's own body can
// be found again by file and line
func findDefs(adapter *language.Adapter, root *sitter.Node, src []byte) []defSite {
	q, err := adapter.Query("symbols")
	if err != nil {
		return nil
	}
	qc := sitter.NewQueryCursor()
	defer qc.Close()
	var out []defSite
	matches := qc.Matches(q, root, src)
	for m := matches.Next(); m != nil; m = matches.Next() {
		for _, cap := range m.Captures {
			node := cap.Node
			name := parser.DefName(adapter.ID, &node, src)
			if name == "" {
				// Match buildSymbol's fallback (internal/source/parser),
				// or an inline function literal - `server.tool("x", "y",
				// async (args) => {...})` - never matches back to its own
				// Symbol here, and every lookup for it falls through to
				// sym.Params instead of its actual parameter list
				name = "<anonymous>"
			}
			out = append(out, defSite{node: &node, name: name, line: int(node.StartPosition().Row) + 1})
		}
	}
	return out
}

func (c *ctx) defNodeFor(sym *graph.Symbol) (*parsedFile, *sitter.Node) {
	pf := c.fileFor(sym.File)
	if pf == nil {
		return nil, nil
	}
	for _, d := range pf.defs {
		if d.line == sym.Line && d.name == sym.Name {
			return pf, d.node
		}
	}
	return nil, nil
}

// seedFor taints registered handler parameters. It reads bindings from the AST
// so destructured parameters are not lost; sym.Params is only a fallback.
func (c *ctx) seedFor(sym *graph.Symbol) map[string]taintInfo {
	var kind graph.CapabilityKind
	found := false
	for _, cp := range c.g.Capabilities {
		if cp.Handler == sym.ID {
			kind, found = cp.Kind, true
			break
		}
	}
	if !found {
		return nil
	}
	if pf, node := c.defNodeFor(sym); pf == nil || node == nil {
		// The handler's own body could not be located at all - not the
		// same thing as a handler that genuinely takes no parameters.
		// Leaving c.seeded unset here means taintCoverage counts this as
		// skipped rather than analyzed: analyzeSymbol is about to fail
		// the identical lookup and trace nothing.
		return nil
	}
	detail := map[graph.CapabilityKind]string{
		graph.CapabilityTool:     "tool handler argument",
		graph.CapabilityPrompt:   "prompt argument",
		graph.CapabilityResource: "resource handler argument",
	}[kind]

	names := c.paramBindingNames(sym)
	if len(names) == 0 {
		if !c.handlerDeclaresParams(sym) {
			// A handler that genuinely takes no arguments has nothing an
			// attacker controls: there is nothing to seed, which is a real
			// answer - analyzed, not a gap - unlike a handler whose
			// declared parameters exist but could not be resolved to
			// names (still returns nil below, still a skip)
			c.seeded[sym.ID] = true
			return map[string]taintInfo{}
		}
		return nil
	}
	seed := map[string]taintInfo{}
	for _, name := range names {
		seed[name] = taintInfo{confidence: 1, chain: []model.FlowStep{{
			Kind: "source", Symbol: name, File: sym.File, Line: sym.Line, Detail: detail, Resolved: true,
		}}}
	}
	c.seeded[sym.ID] = true
	return seed
}

// handlerDeclaresParams reports whether sym's own definition declares at least one
// parameter, read directly from its parameter list's node count rather than from
// paramBindingNames's result. This distinguishes a real zero-argument handler from one whose
// parameter bindings could not be resolved; only the latter is a coverage gap.
func (c *ctx) handlerDeclaresParams(sym *graph.Symbol) bool {
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil {
		return len(sym.Params) > 0
	}
	list := parser.ParamList(node)
	if list == nil {
		return len(sym.Params) > 0
	}
	declared := int(list.NamedChildCount())
	if declared > 0 && parser.HasImplicitReceiver(pf.adapter.ID, node, pf.src) {
		// A method that declares nothing but self takes no argument, the
		// same real answer a bare `def ping()` gives - not a handler
		// whose parameters could not be resolved
		declared--
	}
	return declared > 0
}

// paramBindingNames returns every name sym's parameters bind: usually one per parameter,
// but a destructured JS/TS parameter binds one name per identifier the pattern introduces
// (nested, renamed and rest bindings included - see parser.ParamBindings). If the body cannot
// be reparsed, the graph's raw parameter names remain the conservative fallback.
func (c *ctx) paramBindingNames(sym *graph.Symbol) []string {
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil {
		return sym.Params
	}
	list := parser.ParamList(node)
	if list == nil {
		return sym.Params
	}
	var names []string
	cursor := list.Walk()
	defer cursor.Close()
	children := list.NamedChildren(cursor)
	if len(children) > 0 && parser.HasImplicitReceiver(pf.adapter.ID, node, pf.src) {
		// self is bound by the call, not by the caller: nothing an
		// attacker controls arrives through it
		children = children[1:]
	}
	for _, ch := range children {
		param := ch
		names = append(names, parser.ParamBindings(pf.adapter.ID, &param, pf.src)...)
		names = append(names, param.Utf8Text(pf.src))
	}
	if len(names) == 0 {
		return sym.Params
	}
	return names
}

// analyzeSymbol walks one function's body with the given seed taint. A seed is marked visited
// only after the definition and body are found, so lookup failure cannot count as analysis.
func (c *ctx) analyzeSymbol(sym *graph.Symbol, seed map[string]taintInfo, depth int) {
	if depth > maxDepth {
		c.depthCapHit = true
		return
	}
	key := seedKeyFor(sym.ID, seed)
	if c.visited[key] {
		return
	}
	if key.seed != "" && c.seedCounts[sym.ID] >= maxSeedsPerSymbol {
		c.seedCapHit = true
		return
	}
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil {
		return
	}
	body := node.ChildByFieldName("body")
	if body == nil {
		return
	}
	c.visited[key] = true
	c.visitedSyms[sym.ID] = true
	if key.seed != "" {
		c.seedCounts[sym.ID]++
	}
	tainted := make(map[string]taintInfo, len(seed))
	maps.Copy(tainted, seed)
	c.walk(pf, sym.File, tainted, body, depth, false)
}

// branchKinds are node kinds whose body may or may not run. Assignments inside them may add
// taint, but cannot clear or weaken taint that remains possible on another control-flow path.
var branchKinds = map[string]bool{
	"if_statement": true, "if_expression": true, "else_clause": true,
	"elif_clause": true, "conditional_expression": true, "ternary_expression": true,
	"try_statement": true, "except_clause": true, "catch_clause": true,
	"finally_clause": true, "try_expression": true,
	"match_statement": true, "match_expression": true, "case_clause": true,
	"switch_statement": true, "switch_expression": true,
	"expression_switch_statement": true, "type_switch_statement": true,
	"select_statement": true,
	"while_statement":  true, "while_expression": true, "do_statement": true,
	"loop_expression": true,
}

func (c *ctx) walk(pf *parsedFile, file string, tainted map[string]taintInfo, n *sitter.Node, depth int, conditional bool) {
	grammar := pf.adapter.Grammar
	switch {
	case slices.Contains(grammar.AssignKinds, n.Kind()):
		c.handleAssign(pf, file, tainted, n, depth, conditional)
	case slices.Contains(grammar.CallKinds, n.Kind()):
		c.handleCall(pf, file, tainted, n, depth, conditional)
	case slices.Contains(grammar.ForKinds, n.Kind()):
		c.handleLoop(pf, file, tainted, n, depth, conditional)
	}
	childConditional := conditional || branchKinds[n.Kind()] || slices.Contains(grammar.ForKinds, n.Kind())
	cursor := n.Walk()
	defer cursor.Close()
	for _, ch := range n.NamedChildren(cursor) {
		child := ch
		c.walk(pf, file, tainted, &child, depth, childConditional)
	}
	// Checked after the if-statement's own subtree (condition, consequence,
	// alternative) has been fully walked, not before: handleContainmentGuard
	// only clears taint for the statements that follow the if in the same
	// block, never for the guard's own escape branch, which must still see
	// the value as tainted
	if n.Kind() == ifStatementKinds[pf.adapter.ID] {
		c.handleContainmentGuard(pf, tainted, n)
	}
}

// handleLoop propagates collection taint into loop variables before walking
// the body. Go's range binding needs the extra unwrapping in loopBindingNode.
func (c *ctx) handleLoop(pf *parsedFile, file string, tainted map[string]taintInfo, n *sitter.Node, depth int, conditional bool) {
	bind := loopBindingNode(pf.adapter.ID, n)
	if bind == nil {
		return
	}
	targets := parser.AssignTargets(bind, pf.src)
	if len(targets) == 0 {
		return
	}
	rhs := parser.AssignValue(bind, pf.src)
	if rhs == nil {
		return
	}
	if info, ok := propagatedTaint(rhs.Utf8Text(pf.src), tainted); ok {
		setTaint(tainted, targets, info, conditional)
	}
}

// setTaint binds info to each target. Under a conditional it never lowers
// what is already known: the branch that produced the new value may not
// run, and the code after it is reached either way.
func setTaint(tainted map[string]taintInfo, targets []string, info taintInfo, conditional bool) {
	for _, t := range targets {
		if conditional {
			if old, ok := tainted[t]; ok && !atLeastAsTainted(old, info) {
				continue
			}
		}
		tainted[t] = info
	}
}

// clearTaint forgets each target, unless the untainted value came out of a
// branch that may not have run
func clearTaint(tainted map[string]taintInfo, targets []string, conditional bool) {
	if conditional {
		return
	}
	for _, t := range targets {
		delete(tainted, t)
	}
}

// atLeastAsTainted reports whether next keeps every warning old carried:
// no lower confidence, and nothing newly cleared
func atLeastAsTainted(old, next taintInfo) bool {
	if next.confidence < old.confidence {
		return false
	}
	for cat := range next.clearedFor {
		if !old.clearedFor[cat] {
			return false
		}
	}
	return true
}

// loopBindingNode returns the node whose fields AssignTargets/AssignValue
// should read for a loop node n - n itself for every grammar except Go,
// whose for_statement wraps a range loop's binding in a range_clause
// child; nil when n is a Go for_statement with no range_clause (a plain
// C-style loop, nothing to bind)
func loopBindingNode(id language.ID, n *sitter.Node) *sitter.Node {
	if id != language.Go {
		return n
	}
	cursor := n.Walk()
	defer cursor.Close()
	for _, ch := range n.NamedChildren(cursor) {
		if ch.Kind() == "range_clause" {
			child := ch
			return &child
		}
	}
	return nil
}

// fileAlias is one local name in one file. The file is part of the key
// because that is the scope a binding has: two files are free to use the
// same name for different things, and neither gets to speak for the other.
type fileAlias struct {
	file string
	name string
}

// isSinkText reports whether callee text contains a catalogued sink identifier or matches an argv
// sink. Receiver-blind method matching is excluded because it would bind aliases to unrelated
// methods.
func isSinkText(id language.ID, text string) bool {
	if _, ok := matchSink(text); ok {
		return true
	}
	_, _, ok := matchArgvSink(id, text, nil)
	return ok
}

// mutatingCollectionMethods are receiver methods that grow a local list in place rather
// than returning a new one - Python's append/extend/insert and JavaScript/TypeScript's
// push/unshift/splice. Each value is the number of leading non-content arguments to skip;
// non-mutating methods such as concat do not belong here.
var mutatingCollectionMethods = map[string]int{
	"append": 0, "extend": 0, "insert": 1, // Python
	"push": 0, "unshift": 0, "splice": 2, // JavaScript, TypeScript
}

// isIdentifierText reports whether text is a plain (possibly dotted) name
// with nothing else in it - no literal, no call, no arrow function. It is
// what keeps `const exec = "release"` and `const run = () => {...}` out of
// the alias table: only a name that could be another name's binding goes in.
func isIdentifierText(text string) bool {
	if text == "" {
		return false
	}
	for i := 0; i < len(text); i++ {
		if !isIdentByte(text[i]) && text[i] != '.' {
			return false
		}
	}
	return true
}

// sinkValueText reads an assignment's right-hand side as a reference to a
// sink: the sink's own name, or promisify(sink) - Node's canonical way to
// call exec from an async handler, and the spelling most published
// TypeScript servers use. util.promisify counts the same way
func sinkValueText(pf *parsedFile, rhs *sitter.Node) (string, bool) {
	text := strings.TrimSpace(rhs.Utf8Text(pf.src))
	if slices.Contains(pf.adapter.Grammar.CallKinds, rhs.Kind()) {
		calleeText, _, args := parser.CalleeAndArgs(pf.adapter.ID, rhs, pf.src)
		if parser.LastSegment(calleeText) != "promisify" || len(args) != 1 {
			return "", false
		}
		text = strings.TrimSpace(args[0].Text)
	}
	if !isIdentifierText(text) || !isSinkText(pf.adapter.ID, text) {
		return "", false
	}
	return text, true
}

// recordFileAliases finds renamed imports and assignments such as
// `execAsync = promisify(exec)`. It scans the whole file because aliases often live at module
// scope; conflicting bindings are ignored so traversal order cannot choose their meaning.
func (c *ctx) recordFileAliases(pf *parsedFile, file string) {
	sinks := map[string]string{}
	conflict := map[string]bool{}
	record := func(name, sink string) {
		if name == "" {
			return
		}
		if prev, seen := sinks[name]; seen && prev != sink {
			conflict[name] = true
			return
		}
		sinks[name] = sink
	}

	// The import list the source parser already built says what every local name in this file
	// stands for, which the syntax scan below cannot see: `from subprocess import Popen` binds
	// Popen with no alias node anywhere, and the sink tables spell that sink
	// "subprocess.Popen"
	modules := map[string]string{}
	moduleConflict := map[string]bool{}
	objects := map[string]string{}
	objectConflict := map[string]bool{}
	for _, imp := range c.g.Files[file].Imports {
		local := imp.Alias
		if local == "" {
			local = parser.LastSegment(imp.Path)
		}
		if isSinkText(pf.adapter.ID, imp.Path) {
			record(local, imp.Path)
			continue
		}
		if local == "" || local == imp.Path {
			continue
		}
		if prev, seen := modules[local]; seen && prev != imp.Path {
			moduleConflict[local] = true
			continue
		}
		modules[local] = imp.Path
	}

	var visit func(n *sitter.Node)
	visit = func(n *sitter.Node) {
		switch {
		case n.Kind() == "import_specifier" || n.Kind() == "aliased_import":
			nameN, aliasN := n.ChildByFieldName("name"), n.ChildByFieldName("alias")
			if nameN != nil && aliasN != nil {
				if original := nameN.Utf8Text(pf.src); isSinkText(pf.adapter.ID, original) {
					record(aliasN.Utf8Text(pf.src), original)
				}
			}
			return
		case slices.Contains(pf.adapter.Grammar.AssignKinds, n.Kind()):
			targets := parser.AssignTargets(n, pf.src)
			rhs := parser.AssignValue(n, pf.src)
			// `const { exec: run } = require("node:child_process")` is
			// the CommonJS spelling of a renaming import, and the only
			// place the original name appears is the destructuring key
			if rhs != nil && isRequireCall(pf, unwrapAwait(rhs)) {
				for local, original := range destructuredNames(pf, n) {
					if isSinkText(pf.adapter.ID, original) {
						record(local, original)
					}
				}
				return
			}
			sink := ""
			if rhs != nil && len(targets) == 1 {
				sink, _ = sinkValueText(pf, unwrapAwait(rhs))
				if text := strings.TrimSpace(rhs.Utf8Text(pf.src)); len(text) >= 2 && text[0] == '{' && text[len(text)-1] == '}' {
					if prev, seen := objects[targets[0]]; seen && prev != text {
						objectConflict[targets[0]] = true
					}
					objects[targets[0]] = text
				}
			}
			for _, t := range targets {
				record(t, sink)
			}
		}
		cursor := n.Walk()
		defer cursor.Close()
		for _, ch := range n.NamedChildren(cursor) {
			child := ch
			visit(&child)
		}
	}
	visit(pf.root)
	for name, sink := range sinks {
		if sink != "" && !conflict[name] {
			c.aliases[fileAlias{file: file, name: name}] = sink
		}
	}
	for name, text := range objects {
		// A name bound to two different objects is not one object
		if !objectConflict[name] && !conflict[name] {
			c.objects[fileAlias{file: file, name: name}] = text
		}
	}
	for name, path := range modules {
		// A name bound to a sink outright wins: it is the more specific
		// answer about the same identifier
		if moduleConflict[name] || sinks[name] != "" {
			continue
		}
		c.moduleAliases[fileAlias{file: file, name: name}] = path
	}
}

// isRequireCall reports whether n is `require(<literal>)`
func isRequireCall(pf *parsedFile, n *sitter.Node) bool {
	if !slices.Contains(pf.adapter.Grammar.CallKinds, n.Kind()) {
		return false
	}
	calleeText, _, args := parser.CalleeAndArgs(pf.adapter.ID, n, pf.src)
	return parser.LastSegment(calleeText) == "require" && len(args) == 1 && args[0].Literal
}

// destructuredNames reads an object-pattern assignment's renaming pairs as
// local name -> original property name. A shorthand binding needs no entry:
// the local name already is the original.
func destructuredNames(pf *parsedFile, n *sitter.Node) map[string]string {
	out := map[string]string{}
	var visit func(node *sitter.Node)
	visit = func(node *sitter.Node) {
		if node.Kind() == "pair_pattern" {
			key, value := node.ChildByFieldName("key"), node.ChildByFieldName("value")
			if key != nil && value != nil {
				out[strings.TrimSpace(value.Utf8Text(pf.src))] = strings.TrimSpace(key.Utf8Text(pf.src))
			}
			return
		}
		cursor := node.Walk()
		defer cursor.Close()
		for _, ch := range node.NamedChildren(cursor) {
			child := ch
			visit(&child)
		}
	}
	if left := n.ChildByFieldName("left"); left != nil {
		visit(left)
	} else if name := n.ChildByFieldName("name"); name != nil {
		visit(name)
	}
	return out
}

// rewriteModuleAlias expands a local module alias to the catalog path. For example, `sp.run`
// becomes `subprocess.run`, and Rust's `fs::read_to_string` becomes `std::fs::read_to_string`.
func (c *ctx) rewriteModuleAlias(file, calleeText string) (string, bool) {
	text := strings.TrimSpace(calleeText)
	i := strings.IndexByte(text, '.')
	if j := strings.Index(text, "::"); j >= 0 && (i < 0 || j < i) {
		i = j
	}
	if i <= 0 {
		return "", false
	}
	path, ok := c.moduleAliases[fileAlias{file: file, name: text[:i]}]
	if !ok {
		return "", false
	}
	return path + text[i:], true
}

// aliasedSinkText resolves a callee name through c.aliases. A callee that
// resolves to this project's own code is refused - the same reason
// handleCall falls back to matchMethodSink only once resolution has
// failed: a repository with its own run() outranks anything a name was
// bound to elsewhere in the file.
func (c *ctx) aliasedSinkText(file, calleeText string) (string, bool) {
	target, ok := c.aliases[fileAlias{file: file, name: strings.TrimSpace(calleeText)}]
	if !ok {
		return "", false
	}
	if _, inRepo := c.resolveCallee(file, calleeText); inRepo {
		return "", false
	}
	return target, true
}

// functionValueCallers take a function and the arguments to call it with, and run it
// somewhere else - another thread, an executor, later. The value is the position of the
// function argument; everything after it is that function's own argument list.
var functionValueCallers = map[string]int{
	"to_thread":       0, // asyncio.to_thread(fn, *args)
	"partial":         0, // functools.partial(fn, *args)
	"submit":          0, // Executor.submit(fn, *args)
	"run_in_executor": 1, // loop.run_in_executor(executor, fn, *args)
}

// sinkValueArg reads a call to one of functionValueCallers as a call to the sink it was
// handed, with the remaining arguments as that sink's own
func sinkValueArg(id language.ID, calleeText string, args []graph.Arg) (string, []graph.Arg, bool) {
	idx, ok := functionValueCallers[parser.LastSegment(calleeText)]
	if !ok || idx >= len(args) {
		return "", nil, false
	}
	fn := strings.TrimSpace(args[idx].Text)
	if !isIdentifierText(fn) || !isSinkText(id, fn) {
		return "", nil, false
	}
	return fn, args[idx+1:], true
}

// unwrapAwait returns the expression an await wraps, or n unchanged when it wraps nothing. Await
// nodes are not call nodes, so unwrapping is required for async sources, sinks, and sanitizers.
func unwrapAwait(n *sitter.Node) *sitter.Node {
	switch n.Kind() {
	case "await_expression", "await":
		if inner := n.NamedChild(0); inner != nil {
			return inner
		}
	}
	return n
}

// augmentedAssignKinds are Python and JavaScript/TypeScript grammar nodes for `x += y`. The walker
// models these as `x = x + y` so a literal right-hand side preserves existing taint. Go augmented
// assignments use the plain assignment path and can clear taint, a known fail-open limitation.
var augmentedAssignKinds = map[string]bool{
	"augmented_assignment":            true, // Python
	"augmented_assignment_expression": true, // JavaScript, TypeScript
}

func (c *ctx) handleAssign(pf *parsedFile, file string, tainted map[string]taintInfo, n *sitter.Node, depth int, conditional bool) {
	targets := parser.AssignTargets(n, pf.src)
	if len(targets) == 0 {
		return
	}
	rhs := parser.AssignValue(n, pf.src)
	if rhs == nil {
		clearTaint(tainted, targets, conditional)
		return
	}
	line := int(n.StartPosition().Row) + 1
	rhs = unwrapAwait(rhs)

	if augmentedAssignKinds[n.Kind()] {
		text := strings.Join(targets, " + ") + " + " + rhs.Utf8Text(pf.src)
		if info, ok := propagatedTaint(text, tainted); ok {
			setTaint(tainted, targets, info, conditional)
		}
		// No clear branch: appending to a value never removes what was
		// already in it
		return
	}

	if slices.Contains(pf.adapter.Grammar.CallKinds, rhs.Kind()) {
		calleeText, receiver, args := parser.CalleeAndArgs(pf.adapter.ID, rhs, pf.src)
		// A second spelling to ask the catalogue about, used only when the
		// written one matches nothing: `import subprocess as sp` makes
		// `sp.run` mean `subprocess.run`, while `import fs from
		// "node:fs/promises"` leaves `fs.readFile` already spelled the way
		// the catalogue has it. The flow steps keep the written form
		// either way.
		matchText, aliased := c.rewriteModuleAlias(file, calleeText)

		detail, isSource := matchSource(calleeText)
		if !isSource && aliased {
			detail, isSource = matchSource(matchText)
		}
		if isSource {
			info := taintInfo{confidence: 1, chain: []model.FlowStep{{
				Kind: "source", Symbol: calleeText, File: file, Line: line, Detail: detail, Resolved: true,
			}}}
			setTaint(tainted, targets, info, conditional)
			return
		}

		_, from, ok := c.taintedArgOrReceiver(file, receiver, args, tainted, "")
		if !ok {
			clearTaint(tainted, targets, conditional)
			return
		}

		sym, resolved := c.resolveCallee(file, calleeText)

		san, isSanitizer := sanitizerFor(calleeText, resolved)
		if !isSanitizer && aliased {
			san, isSanitizer = sanitizerFor(matchText, resolved)
		}
		if isSanitizer {
			// A strong sanitizer only clears the categories in san.covers (path_traversal for basename,
			// command_injection for shlex.quote, ...) - see sanitizerPattern
			info := from.extend(model.FlowStep{
				Kind: "sanitizer", Symbol: calleeText, File: file, Line: line, Detail: san.detail, Resolved: true,
			}, 0.6)
			if !san.weak {
				info.clearedFor = mergeClearedFor(from.clearedFor, san.covers)
			}
			if san.normalizes {
				info.normalized = true
			}
			setTaint(tainted, targets, info, conditional)
			return
		}

		kind, mult := "unknown", 0.6
		if resolved {
			kind, mult = "transform", 0.85
		}
		step := model.FlowStep{
			Kind: kind, Symbol: calleeText, File: file, Line: line, Resolved: resolved,
			Detail: "result of a call that received tainted input",
		}
		info := from.extend(step, mult)
		if reintroducesPathSyntax(calleeText) {
			// A guard proved something about the string it tested, and this call produces a different
			// string: "%2e%2e%2f" passes a join and a prefix test as ordinary characters and comes out
			// of a decoder as "../"
			info.clearedFor = withoutCategory(info.clearedFor, "path_traversal")
			info.normalized = false
		}
		setTaint(tainted, targets, info, conditional)

		if resolved {
			c.recurseInto(sym, seedFromArgs(sym, args, tainted, step, mult), depth)
		}
		return
	}

	text := rhs.Utf8Text(pf.src)
	// Attribute, index, or member access can carry a source value without being a call itself,
	// as in `requests.get(u).text`, `os.environ["JOB"]`, or `process.env.JOB`
	if detail, ok := matchSource(text); ok {
		setTaint(tainted, targets, taintInfo{confidence: 1, chain: []model.FlowStep{{
			Kind: "source", Symbol: strings.TrimSpace(text), File: file, Line: line, Detail: detail, Resolved: true,
		}}}, conditional)
		return
	}
	if info, ok := propagatedTaint(text, tainted); ok {
		setTaint(tainted, targets, info, conditional)
		return
	}
	clearTaint(tainted, targets, conditional)
}

func (c *ctx) handleCall(pf *parsedFile, file string, tainted map[string]taintInfo, n *sitter.Node, depth int, conditional bool) {
	calleeText, receiver, args := parser.CalleeAndArgs(pf.adapter.ID, n, pf.src)

	// An inline function/arrow literal passed alongside a tainted receiver
	// or sibling argument - `targets.forEach((t) => execSync("make " +
	// t))` - has its own parameter tainted here, independent of whatever
	// this call itself turns out to be (forEach is neither a sink nor a
	// resolved in-repo call, so nothing below this would ever reach it)
	c.walkCallbackArgs(pf, file, tainted, n, receiver, args, depth)

	// A method that grows a local list in place - `cmd.append(query)`,
	// `args.push(query)` - never assigns anything, so handleAssign's call
	// branch never sees it; this is that branch's call-statement twin, and
	// mirrors augmented_assignment's reasoning in handleAssign: appending
	// never removes what the receiver already carried, so there is no
	// clear branch here either, only a set
	if skip, ok := mutatingCollectionMethods[parser.LastSegment(calleeText)]; ok && isPlainIdent(receiver.Text) && skip < len(args) {
		if _, info, found := taintedArgIndex(args[skip:], tainted, ""); found {
			line := int(n.StartPosition().Row) + 1
			setTaint(tainted, []string{receiver.Text}, info.extend(model.FlowStep{
				Kind: "transform", Symbol: calleeText, File: file, Line: line, Resolved: true,
				Detail: "collection extended with tainted input",
			}, 0.9), conditional)
			return
		}
	}

	// sinkText is what the sink tables are asked about. It is the callee as written everywhere
	// except three rewritten shapes: local sink aliases, module aliases, and a sink handed to
	// something like asyncio.to_thread as a value.
	sinkText := calleeText
	if aliased, ok := c.aliasedSinkText(file, calleeText); ok {
		sinkText = aliased
	} else if rewritten, ok := c.rewriteModuleAlias(file, calleeText); ok && !isSinkText(pf.adapter.ID, calleeText) {
		sinkText = rewritten
	}
	if fnText, rest, ok := sinkValueArg(pf.adapter.ID, calleeText, args); ok {
		sinkText, args, receiver = fnText, rest, parser.Receiver{}
	}

	if argv, argvArgs, ok := matchArgvSink(pf.adapter.ID, sinkText, args); ok {
		// found only means some tainted value reached the argv call; a
		// strong sanitizer upstream may still have cleared it for this
		// exact category (info.clearedFor) without clearing it for every
		// category, the same gate the plain-sink branch below applies
		if category, severity, mult, note, info, found := c.classifyArgv(file, argv.kind, argvArgs, tainted); found && !info.clearedFor[category] {
			line := int(n.StartPosition().Row) + 1
			final := info.extend(model.FlowStep{
				Kind: "sink", Symbol: calleeText, File: file, Line: line, Detail: category, Resolved: true,
			}, mult)
			c.emit(category, severity, calleeText, final, file, line, note)
		}
		return
	}

	// Resolved once, up front: matchMethodSink below needs to know whether
	// the callee is this project's own code before it can safely match by
	// method name alone, and the "follow into a resolved call" fallback
	// at the bottom needs the same answer anyway
	sym, resolvedInRepo := c.resolveCallee(file, calleeText)
	if resolvedInRepo && callsItselfThroughReceiver(calleeText, sym, file, int(n.StartPosition().Row)+1) {
		sym, resolvedInRepo = nil, false
	}

	sink, sinkFound := matchSink(sinkText)
	if !sinkFound && !resolvedInRepo {
		// methodSinkPatterns matches by method name alone, which a plain in-repo function sharing
		// that name would also match - a helper named execute() is not cursor.execute just because
		// they share a name
		sink, sinkFound = matchMethodSink(sinkText)
	}
	if !sinkFound && !resolvedInRepo && fileImportsHTTPClient(c.g, file) {
		// Only tried once the file is already known to import a
		// recognized HTTP client module - see gatedMethodSinkPatterns for
		// why "get"/"post" cannot be matched the unconditional way
		// matchMethodSink's other entries are
		sink, sinkFound = matchGatedMethodSink(sinkText)
	}
	if sinkFound {
		var info taintInfo
		var found bool
		if sink.argIndex >= 0 {
			if sink.argIndex < len(args) {
				info, found = mentionsAny(args[sink.argIndex].Text, tainted, sink.category)
			}
		} else {
			_, info, found = c.taintedArgOrReceiver(file, receiver, args, tainted, sink.category)
		}
		// info.clearedFor[sink.category] means a strong sanitizer upstream
		// already covers exactly this sink's category (see handleAssign) -
		// not that the value is clean for every category, which is the
		// mistake that let basename() before a shell call and shlex.quote()
		// before a path read both scan clean
		if found && !info.clearedFor[sink.category] {
			line := int(n.StartPosition().Row) + 1
			final := info.extend(model.FlowStep{
				Kind: "sink", Symbol: calleeText, File: file, Line: line, Detail: sink.category, Resolved: true,
			}, 1)
			c.emit(sink.category, sink.severity, calleeText, final, file, line, "")
		}
		return
	}
	if _, ok := matchSource(calleeText); ok {
		return
	}
	if _, ok := sanitizerFor(calleeText, resolvedInRepo); ok {
		return
	}
	if !resolvedInRepo {
		// A callee that named more than one definition, handed tainted
		// input, is a trace that stopped rather than a trace that
		// finished. resolveByImport already tried the calling file's
		// imports; nothing else here can choose
		if len(c.idx[parser.LastSegment(calleeText)]) > 1 {
			if _, _, found := c.taintedArgOrReceiver(file, receiver, args, tainted, ""); found {
				c.ambiguousCalls++
			}
		}
		return
	}

	// Not a sink, source or sanitizer itself, but a resolved in-repo call:
	// `return helper(x, y)`, a bare `helper(x, y)` statement, or any other
	// call whose result is not captured by an assignment still deserves
	// following into the callee's own body, since the sink might be there
	// rather than in whatever this call returns - and every tainted
	// argument, not just the first one found, gets seeded (seedFromArgs)
	line := int(n.StartPosition().Row) + 1
	step := model.FlowStep{
		Kind: "transform", Symbol: calleeText, File: file, Line: line, Resolved: true,
		Detail: "passes tainted input into another function",
	}
	c.recurseInto(sym, seedFromArgs(sym, args, tainted, step, 0.9), depth)
}

// walkCallbackArgs follows an inline function/arrow literal passed as one of call's own
// arguments when the call's receiver or another argument is already tainted - the
// callback-taking shape `targets.forEach((t) => execSync("make " + t))`,
// `for_each`/`map`/`then` and their equivalents across languages all share
func (c *ctx) walkCallbackArgs(pf *parsedFile, file string, tainted map[string]taintInfo, call *sitter.Node, receiver parser.Receiver, args []graph.Arg, depth int) {
	argsList := call.ChildByFieldName("arguments")
	if argsList == nil {
		return
	}
	_, info, ok := c.taintedArgOrReceiver(file, receiver, args, tainted, "")
	if !ok {
		return
	}
	cursor := argsList.Walk()
	defer cursor.Close()
	for _, ch := range argsList.NamedChildren(cursor) {
		lit := ch
		if !slices.Contains(pf.adapter.Grammar.FunctionKinds, lit.Kind()) {
			continue
		}
		sym := c.literalSymbol(pf, file, &lit)
		if sym == nil || len(sym.Params) == 0 {
			continue
		}
		c.recurseInto(sym, map[string]taintInfo{sym.Params[0]: info}, depth)
	}
}

// literalSymbol finds the graph.Symbol for an inline function/arrow
// literal argument node, using the same name-and-line identity buildSymbol
// (internal/source/parser) assigned it when the graph was first built:
// every function-like node becomes its own Symbol, anonymous or not,
// addressable the same way findDefs already looks up a definition's own
// node in the other direction
func (c *ctx) literalSymbol(pf *parsedFile, file string, lit *sitter.Node) *graph.Symbol {
	name := parser.DefName(pf.adapter.ID, lit, pf.src)
	if name == "" {
		name = "<anonymous>"
	}
	line := int(lit.StartPosition().Row) + 1
	return c.g.Symbols[graph.MakeSymbolID(file, name, line)]
}

// seedFromArgs builds a parameter seed for sym from every tainted argument in args - not
// just the first one found, so a callee sharing a helper with more than one
// attacker-controlled argument has every one of them followed into the callee, not only
// whichever happened to be scanned first
func seedFromArgs(sym *graph.Symbol, args []graph.Arg, tainted map[string]taintInfo, step model.FlowStep, mult float64) map[string]taintInfo {
	if sym == nil {
		return nil
	}
	seed := map[string]taintInfo{}
	for i, a := range args {
		if i >= len(sym.Params) {
			continue
		}
		if info, ok := mentionsAny(a.Text, tainted, ""); ok {
			seed[sym.Params[i]] = info.extend(step, mult)
		}
	}
	return seed
}

// recurseInto walks sym's body with seed applied as its parameters' taint,
// through analyzeSymbol's (symbol, seed) visited guard: a cycle or a
// diamond in the call graph is walked at most once per distinct seed, so a
// helper seeded differently by two different callers is analyzed for each
// (bounded by maxSeedsPerSymbol), and analyzed only once for the same
// caller shape encountered again
func (c *ctx) recurseInto(sym *graph.Symbol, seed map[string]taintInfo, depth int) {
	if sym == nil || len(seed) == 0 {
		return
	}
	c.analyzeSymbol(sym, seed, depth+1)
}

// callsItselfThroughReceiver rejects a free function falsely resolving its own receiver call,
// as in a query wrapper calling pool.query. Real methods may recurse. Other same-name calls use
// resolveCallee's normal rule: one candidate resolves directly, while imports may narrow several
// candidates to one.
func callsItselfThroughReceiver(calleeText string, sym *graph.Symbol, file string, line int) bool {
	if sym == nil || sym.Kind != graph.KindFunction {
		return false
	}
	if parser.LastSegment(calleeText) == strings.TrimSpace(calleeText) {
		return false
	}
	return sym.File == file && line >= sym.Line && line <= sym.EndLine
}

// resolveCallee uses flat, name-based resolution. A unique name resolves directly; resolveByImport
// may narrow several candidates using the caller's imports. parser.Resolve instead breaks such a
// tie when one candidate is defined in the calling file.
func (c *ctx) resolveCallee(file, calleeText string) (*graph.Symbol, bool) {
	name := parser.LastSegment(calleeText)
	cands := c.idx[name]
	if len(cands) != 1 {
		return c.resolveByImport(file, cands)
	}
	sym := c.g.Symbols[cands[0]]
	if sym == nil || (sym.Kind != graph.KindFunction && sym.Kind != graph.KindMethod) {
		return nil, false
	}
	return sym, true
}

// resolveByImport picks between same-named definitions using what the calling file
// imported. `from ops.shell import run_cmd` says which run_cmd this file meant, and two
// helpers of the same name in different modules is ordinary layout, not an evasion - before
// this, any second definition ended the trace in silence. If imports do not leave exactly one
// candidate, resolution fails. handleCall records that ambiguity only for a tainted call;
// handleAssign does not record it.
func (c *ctx) resolveByImport(file string, cands []graph.SymbolID) (*graph.Symbol, bool) {
	var match *graph.Symbol
	for _, id := range cands {
		sym := c.g.Symbols[id]
		if sym == nil || (sym.Kind != graph.KindFunction && sym.Kind != graph.KindMethod) {
			continue
		}
		if !c.importNames(file, sym.File) {
			continue
		}
		if match != nil {
			return nil, false
		}
		match = sym
	}
	return match, match != nil
}

// importNames reports whether from's import list names the module def
// lives in
func (c *ctx) importNames(from, def string) bool {
	want := moduleSegments(def)
	if len(want) == 0 {
		return false
	}
	for _, imp := range c.g.Files[from].Imports {
		// A from-import spells the symbol as a final segment
		// ("ops.shell.run_cmd"), so a suffix of the import is allowed to
		// be what matches the file
		if segmentsHaveSuffix(moduleSegments(imp.Path), want) {
			return true
		}
	}
	return false
}

// moduleSegments reduces a module reference - a dotted import, a relative
// specifier, a file path - to its bare name segments, so "ops.shell",
// "./ops/shell.js" and "ops/shell.py" all reduce to [ops shell]
func moduleSegments(p string) []string {
	p = strings.ReplaceAll(p, "\\", "/")
	if ext := path.Ext(p); ext != "" && language.ForExt(ext) != nil {
		p = strings.TrimSuffix(p, ext)
	}
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '.' })
}

// segmentsHaveSuffix reports whether want appears at the end of have, or
// with one extra trailing segment - the symbol name a from-import adds
func segmentsHaveSuffix(have, want []string) bool {
	if len(want) == 0 {
		return false
	}
	for _, drop := range []int{0, 1} {
		h := have
		if drop > 0 {
			if len(h) < drop {
				continue
			}
			h = h[:len(h)-drop]
		}
		if len(h) < len(want) {
			continue
		}
		h = h[len(h)-len(want):]
		same := true
		for i := range want {
			if h[i] != want[i] {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

// taintedArgIndex returns the first argument (in order) that mentions a
// tainted identifier, and which one it was. category is the sink category
// this check is being made for - see mentionsAny - or "" when no sink is
// known yet (propagating taint through an ordinary expression, not
// evaluating a sink match)
func taintedArgIndex(args []graph.Arg, tainted map[string]taintInfo, category string) (int, taintInfo, bool) {
	idx, info, ok := worstCandidate(taintCandidates(args, nil, tainted, category), category)
	return idx, info, ok
}

// taintCandidate is one place an expression's taint was found: an argument
// position, or -1 for a receiver
type taintCandidate struct {
	idx  int
	info taintInfo
}

// taintCandidates collects every argument (and then every extra) that
// mentions something tainted, in the order the caller wants them
// considered
func taintCandidates(args []graph.Arg, extra []taintCandidate, tainted map[string]taintInfo, category string) []taintCandidate {
	var out []taintCandidate
	for i, a := range args {
		if info, ok := mentionsAny(a.Text, tainted, category); ok {
			out = append(out, taintCandidate{i, info})
		}
	}
	return append(out, extra...)
}

// worstCandidate picks which of the places tainted input was found speaks for the call.
// With a sink category in hand, the first place nothing cleared wins, because one sanitized
// argument says nothing about the argument next to it; a cleared one is returned only when
// every place was cleared.
func worstCandidate(cands []taintCandidate, category string) (int, taintInfo, bool) {
	if len(cands) == 0 {
		return -1, taintInfo{}, false
	}
	if category == "" {
		merged := cands[0].info
		for _, c := range cands[1:] {
			merged = worstTaint(merged, c.info)
		}
		return cands[0].idx, merged, true
	}
	for _, c := range cands {
		if !c.info.clearedFor[category] {
			return c.idx, c.info, true
		}
	}
	return cands[0].idx, cands[0].info, true
}

// taintedArgOrReceiver checks arguments, receiver text, and receiver CallText. It inspects the
// receiver call's arguments only for known constructors or resolved in-repository helpers, which
// avoids treating every chained opaque call as propagating its arguments.
func (c *ctx) taintedArgOrReceiver(file string, receiver parser.Receiver, args []graph.Arg, tainted map[string]taintInfo, category string) (int, taintInfo, bool) {
	var extra []taintCandidate
	if receiver.Text != "" {
		if info, ok := mentionsAny(receiver.Text, tainted, category); ok {
			extra = append(extra, taintCandidate{-1, info})
		}
	}
	if receiver.CallText != "" {
		if matchReceiverConstructor(receiver.CallText) {
			if _, info, ok := taintedArgIndex(receiver.CallArgs, tainted, category); ok {
				extra = append(extra, taintCandidate{-1, info})
			}
		}
		// The inner call's own callee text, with its arguments left out of view: for a chain, that
		// is the subject the chain started from - `name.trim().toLowerCase()` gives "name.trim",
		// which still mentions name
		if info, ok := mentionsAny(receiver.CallText, tainted, category); ok {
			extra = append(extra, taintCandidate{-1, info})
		}
		// A receiver call that resolves to this project's own code is not the opaque case the
		// exclusion above guards against: the helper is right there to be read, and
		// `locate(name).read_text()` is the same flow as `t = locate(name); t.read_text()`, which
		// was already reported
		if _, inRepo := c.resolveCallee(file, receiver.CallText); inRepo {
			if _, info, ok := taintedArgIndex(receiver.CallArgs, tainted, category); ok {
				extra = append(extra, taintCandidate{-1, info})
			}
		}
	}
	return worstCandidate(taintCandidates(args, extra, tainted, category), category)
}

// mentionsAny returns the weakest whole-word taint match after category-aware
// sanitizer masking. propagatedTaint handles assignments that need per-name
// sanitizer state.
func mentionsAny(text string, tainted map[string]taintInfo, category string) (taintInfo, bool) {
	text = maskStrongSanitizerCalls(text, category)
	text = maskAttributeSanitizers(text)
	text = maskSubscriptKeys(maskLiteralText(text))
	var best, cleared taintInfo
	found, foundCleared := false, false
	for name, info := range tainted {
		if !mentionsIdent(text, name) {
			continue
		}
		// A name some sanitizer already cleared for this category does not
		// get to answer for the name beside it that nothing cleared. It is
		// kept only as the fallback for when every mentioned name was
		// cleared, so the caller still sees why.
		if category != "" && info.clearedFor[category] {
			if !foundCleared || info.confidence < cleared.confidence {
				cleared, foundCleared = info, true
			}
			continue
		}
		if !found {
			best, found = info, true
			continue
		}
		best = worstTaint(best, info)
	}
	if found {
		return best, true
	}
	return cleared, foundCleared
}

// propagatedTaint computes assignment taint per name. Visible occurrences stay tainted; fully
// sanitized occurrences add the intersection of cleared categories and receive reduced confidence.
func propagatedTaint(text string, tainted map[string]taintInfo) (taintInfo, bool) {
	text = maskSubscriptKeys(maskLiteralText(maskAttributeSanitizers(text)))
	fullyMasked := maskStrongSanitizerCalls(text, "")
	var best taintInfo
	found := false
	for name, info := range tainted {
		if !mentionsIdent(text, name) {
			continue
		}
		candidate := info
		// normalized is a claim about the string a guard is about to test, not the value it was
		// derived from, and this branch is reached exactly when a tainted name was embedded in
		// something larger - a concatenation, an index, a member access
		if strings.TrimSpace(text) != name {
			candidate.normalized = false
		}
		if !mentionsIdent(fullyMasked, name) {
			candidate.confidence *= 0.6
			if covers := enclosingCoversIntersection(text, name); len(covers) > 0 {
				candidate.clearedFor = mergeClearedFor(info.clearedFor, covers)
			}
		}
		if !found {
			best, found = candidate, true
			continue
		}
		best = worstTaint(best, candidate)
	}
	return best, found
}

// enclosingCoversIntersection intersects the categories of every sanitizer
// directly enclosing a name. Independent span checks handle overlapping
// specific and receiver-blind catalog entries.
func enclosingCoversIntersection(text, name string) []string {
	positions := identOccurrences(text, name)
	if len(positions) == 0 {
		return nil
	}
	var intersection []string
	first := true
	for _, s := range strongSanitizers {
		spans := callArgSpans(text, s.text)
		necessary := false
		for _, pos := range positions {
			if withinAnySpan(pos, spans) {
				necessary = true
				break
			}
		}
		if !necessary {
			continue
		}
		if first {
			intersection = append([]string(nil), s.covers...)
			first = false
			continue
		}
		intersection = intersectCovers(intersection, s.covers)
	}
	return intersection
}

// identOccurrences returns the byte offset of every whole-word occurrence
// of name in text, in order
func identOccurrences(text, name string) []int {
	var out []int
	for i := 0; i < len(text); {
		idx := indexIdentFrom(text, name, i)
		if idx < 0 {
			break
		}
		out = append(out, idx)
		i = idx + len(name)
	}
	return out
}

// callArgSpans returns the [start, end) byte range of the argument text - the space between
// a call's own matching parens, exclusive of the parens themselves - for every whole-word
// call to name found in text
func callArgSpans(text, name string) [][2]int {
	var spans [][2]int
	i := 0
	for i < len(text) {
		idx := indexIdentFrom(text, name, i)
		if idx < 0 {
			break
		}
		open := idx + len(name)
		if open >= len(text) || text[open] != '(' {
			i = idx + len(name)
			continue
		}
		end := matchingParen(text, open)
		if end < 0 {
			break
		}
		spans = append(spans, [2]int{open + 1, end})
		i = end
	}
	return spans
}

func withinAnySpan(pos int, spans [][2]int) bool {
	for _, sp := range spans {
		if pos >= sp[0] && pos < sp[1] {
			return true
		}
	}
	return false
}

// intersectCovers returns the categories present in both a and b
func intersectCovers(a, b []string) []string {
	var out []string
	for _, c := range a {
		if slices.Contains(b, c) {
			out = append(out, c)
		}
	}
	return out
}

// maskStrongSanitizerCalls hides arguments only for strong sanitizers that
// cover category, which keeps a path sanitizer from clearing taint headed for a
// command sink and vice versa. Empty category masks all strong sanitizers. Weak
// sanitizers remain visible.
func maskStrongSanitizerCalls(text, category string) string {
	for _, san := range strongSanitizers {
		if category != "" && !slices.Contains(san.covers, category) {
			continue
		}
		text = maskCallsTo(text, san.text)
	}
	return text
}

// attributeSanitizer recognizes a constructor call followed by a property access, complementing
// the call-based sanitizer tables in catalog.go
type attributeSanitizer struct {
	call string // the constructor call name, e.g. "Path"
	prop string // the property that clears taint, e.g. ".name"
}

// attributeSanitizers are pathlib's own genuinely sufficient traversal sanitizers: .name
// (the final path component) and .stem (.name minus its last suffix) discard every
// directory component the same way os.path.basename/filepath.Base do - not a heuristic
// judgement, a fact about what the property returns - on either of pathlib's two path
// constructors
var attributeSanitizers = []attributeSanitizer{
	{"Path", ".name"},
	{"Path", ".stem"},
	{"PurePath", ".name"},
	{"PurePath", ".stem"},
}

// maskAttributeSanitizers blanks the whole `call(...)prop` span for every
// attributeSanitizers entry found in text - the attribute-access
// counterpart to maskStrongSanitizerCalls: `Path(name).name` clears
// "name" from view the same way `basename(name)` already does. A
// constructor call used any other way - passed around, read_text()'d
// directly, assigned without the sanitizing property - is left alone.
func maskAttributeSanitizers(text string) string {
	for _, s := range attributeSanitizers {
		text = maskCallThenProperty(text, s.call, s.prop)
	}
	return text
}

// maskCallThenProperty is maskCallsTo's counterpart for a call immediately followed by a
// specific property access: it blanks the *entire* `callName(...)prop` span everywhere
// `callName(...)` is directly followed by prop, and leaves every other occurrence of
// callName(...) untouched
func maskCallThenProperty(text, callName, prop string) string {
	var b strings.Builder
	i := 0
	for i < len(text) {
		idx := indexIdentFrom(text, callName, i)
		if idx < 0 {
			b.WriteString(text[i:])
			break
		}
		open := idx + len(callName)
		if open >= len(text) || text[open] != '(' {
			b.WriteString(text[i : idx+len(callName)])
			i = idx + len(callName)
			continue
		}
		end := matchingParen(text, open)
		if end < 0 {
			b.WriteString(text[i:])
			break
		}
		if !strings.HasPrefix(text[end+1:], prop) {
			b.WriteString(text[i : end+1])
			i = end + 1
			continue
		}
		full := end + 1 + len(prop)
		b.WriteString(text[i:idx])
		b.WriteString(strings.Repeat(" ", full-idx))
		i = full
	}
	return b.String()
}

// maskCallsTo blanks the space between name's own matching parentheses
// everywhere name appears as a whole-word call in text - "name(" -
// leaving name, the parentheses themselves, and everything else in text
// untouched
func maskCallsTo(text, name string) string {
	var b strings.Builder
	i := 0
	for i < len(text) {
		idx := indexIdentFrom(text, name, i)
		if idx < 0 {
			b.WriteString(text[i:])
			break
		}
		open := idx + len(name)
		if open >= len(text) || text[open] != '(' {
			b.WriteString(text[i : idx+len(name)])
			i = idx + len(name)
			continue
		}
		end := matchingParen(text, open)
		if end < 0 {
			b.WriteString(text[i:])
			break
		}
		b.WriteString(text[i : open+1])
		b.WriteString(strings.Repeat(" ", end-open-1))
		i = end
	}
	return b.String()
}

// indexIdentFrom is mentionsIdent's search, starting at from and returning the match's own
// index instead of just whether one exists
func indexIdentFrom(text, name string, from int) int {
	for from <= len(text) {
		rel := strings.Index(text[from:], name)
		if rel == -1 {
			return -1
		}
		idx := from + rel
		before := idx == 0 || !isIdentByte(text[idx-1])
		end := idx + len(name)
		after := end >= len(text) || !isIdentByte(text[end])
		if before && after {
			return idx
		}
		from = idx + 1
	}
	return -1
}

// matchingParen returns the index of the ")" matching the "(" at open,
// tracking nested parens and quoted strings so a paren or quote inside a
// nested literal never ends the match early
func matchingParen(text string, open int) int {
	depth := 0
	var quote byte
	for i := open; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote && text[i-1] != '\\' {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// maskSubscriptKeys hides lookup keys because selected values come from the
// collection. Collection names remain visible, and array literals are not
// masked. Blanking preserves offsets.
func maskSubscriptKeys(text string) string {
	out := []byte(text)
	for i := 0; i < len(out); i++ {
		if out[i] != '[' || !subscriptAt(out, i) {
			continue
		}
		depth := 1
		j := i + 1
		for ; j < len(out) && depth > 0; j++ {
			switch out[j] {
			case '[':
				depth++
			case ']':
				depth--
			}
			if depth > 0 {
				out[j] = ' '
			}
		}
		i = j - 1
	}
	return string(out)
}

// subscriptAt reports whether the "[" at idx opens a subscript rather than
// an array literal, by what precedes it
func subscriptAt(out []byte, idx int) bool {
	j := idx - 1
	for j >= 0 && (out[j] == ' ' || out[j] == '\t') {
		j--
	}
	if j < 0 {
		return false
	}
	c := out[j]
	return isIdentByte(c) || c == ')' || c == ']' || c == '"' || c == '\'' || c == '`'
}

// maskLiteralText prevents literal words from looking like variable references while leaving
// interpolated expressions visible. Blanking preserves positions for the identifier matcher;
// these offsets are not emitted as evidence.
func maskLiteralText(text string) string {
	out := []byte(text)
	var quote byte
	for i := 0; i < len(out); i++ {
		c := out[i]
		if quote == 0 {
			if c == '"' || c == '\'' || c == '`' {
				quote = c
			}
			continue
		}
		// Consume the escaped byte rather than looking behind at c: this blanks as it goes, so by
		// the time a closing quote is reached the backslash before it has already become a space
		// and a lookbehind reads the wrong thing
		if c == '\\' && i+1 < len(out) {
			out[i], out[i+1] = ' ', ' '
			i++
			continue
		}
		if c == quote {
			quote = 0
			continue
		}
		if c == '{' {
			depth := 1
			j := i + 1
			for ; j < len(out) && depth > 0; j++ {
				switch out[j] {
				case '{':
					depth++
				case '}':
					depth--
				}
			}
			i = j - 1
			continue
		}
		out[i] = ' '
	}
	// An unclosed literal means the language-neutral scan may have misread syntax. Return the
	// original text so uncertainty creates possible extra flow instead of hiding an identifier.
	if quote != 0 {
		return text
	}
	return string(out)
}

func mentionsIdent(text, name string) bool {
	if name == "" {
		return false
	}
	for idx := strings.Index(text, name); idx != -1; {
		before := idx == 0 || !isIdentByte(text[idx-1])
		end := idx + len(name)
		after := end >= len(text) || !isIdentByte(text[end])
		if before && after {
			return true
		}
		next := strings.Index(text[idx+1:], name)
		if next == -1 {
			return false
		}
		idx += 1 + next
	}
	return false
}

func isIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
