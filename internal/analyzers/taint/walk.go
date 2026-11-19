package taint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/model"
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

	// review, when set, is why a name-based judgement could not settle the finding; it sends the
	// finding to needs_review instead of dropping it
	review string

	// normalized is set by sanitizer patterns marked normalizes. It survives ordinary propagation,
	// but concatenation, recognized decoders, and worstTaint clear it because the resulting path is
	// no longer known to be normalized.
	normalized bool
}

func (t taintInfo) extend(step model.FlowStep, confidenceMult float64) taintInfo {
	chain := make([]model.FlowStep, len(t.chain), len(t.chain)+1)
	copy(chain, t.chain)
	chain = append(chain, step)
	return taintInfo{confidence: t.confidence * confidenceMult, chain: chain, clearedFor: t.clearedFor, normalized: t.normalized, review: t.review}
}

// clearFor returns t with categories added to clearedFor, the way a strong
// sanitizer call's covers already does in handleAssign - used by
// handleContainmentGuard (containment.go) to clear path_traversal from a
// variable a guard clause has just proven stays under its root, without
// the new flow step a real sanitizer call gets: nothing about how the
// value was computed changed here, only what later control flow proves
// about it
func (t taintInfo) clearFor(categories ...string) taintInfo {
	return taintInfo{confidence: t.confidence, chain: t.chain, clearedFor: mergeClearedFor(t.clearedFor, categories), normalized: t.normalized, review: t.review}
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
	// The source class is part of the shape: a helper reached first with an environment value and
	// then with file contents or MCP input is walked for each, or whichever path the code happened
	// to reach first would hide the one that matters
	names := slices.Sorted(maps.Keys(seed))
	parts := make([]string, len(names))
	for i, n := range names {
		class := ""
		if ch := seed[n].chain; len(ch) > 0 {
			class = sourceClass(ch[0].Detail)
		}
		// So is what the value was already cleared for: a caller that passes a relative path,
		// cleared for SSRF, must not stand for one that passes the caller's whole URL
		cleared := ""
		if cf := seed[n].clearedFor; len(cf) > 0 {
			cats := make([]string, 0, len(cf))
			for k, v := range cf {
				if v {
					cats = append(cats, k)
				}
			}
			sort.Strings(cats)
			cleared = "/" + strings.Join(cats, "+")
		}
		parts[i] = n + ":" + class + cleared
	}
	return seedKey{sym: sym, seed: strings.Join(parts, ",")}
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

	// clientBindings caches httpClientBindings per file
	clientBindings map[string]map[string]bool

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

	// Return-value summaries (returns.go): summaryDepth > 0 while a summary walk runs silently,
	// retCapture collects the returned values' taint, retFunc is the function being summarized
	summaryDepth int
	retCapture   *[]taintInfo
	retFunc      *sitter.Node
	retSummaries map[retKey]*retSummary

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

	// regexps holds JavaScript/TypeScript names this file binds only to a regular expression -
	// a literal, new RegExp(...) or RegExp(...) - so the bare "exec" sink can tell
	// RegExp.prototype.exec from child_process.exec
	regexps map[fileAlias]bool

	findings []model.Finding

	// seeded records which capability handlers actually received a
	// non-empty taint seed, as opposed to merely having been visited -
	// a handler walked with nothing seeded analyzed nothing an attacker
	// controls, and coverage must not call that "analyzed"
	seeded map[graph.SymbolID]bool

	// summaries and replays carry a walked shape's findings to later callers the visited guard
	// turns away (see replay)
	summaries map[seedKey][]summaryEntry
	replays   map[seedKey]int
	// escapers caches bodyEscaper per symbol
	escapers map[graph.SymbolID]string
}

func newCtx(runCtx context.Context, g *graph.Graph) *ctx {
	idx := map[string][]graph.SymbolID{}
	for _, sym := range orderedSymbols(g) {
		idx[sym.Name] = append(idx[sym.Name], sym.ID)
	}
	c := &ctx{
		g: g, idx: idx, runCtx: runCtx,
		files:         map[string]*parsedFile{},
		visited:       map[seedKey]bool{},
		summaries:     map[seedKey][]summaryEntry{},
		escapers:      map[graph.SymbolID]string{},
		replays:       map[seedKey]int{},
		seedCounts:    map[graph.SymbolID]int{},
		visitedSyms:   map[graph.SymbolID]bool{},
		retSummaries:  map[retKey]*retSummary{},
		seeded:        map[graph.SymbolID]bool{},
		aliases:       map[fileAlias]string{},
		moduleAliases: map[fileAlias]string{},
		objects:       map[fileAlias]string{},
		regexps:       map[fileAlias]bool{},
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
	var capRec graph.Capability
	found := false
	for _, cp := range c.g.Capabilities {
		if cp.Handler == sym.ID {
			kind, capRec, found = cp.Kind, cp, true
			break
		}
	}
	if !found {
		return nil
	}
	if kind == graph.CapabilityResource && capRec.URIFixed {
		// A fixed resource (registerResource("llms-txt", `${BASE}/llms.txt`, ..., async (uri) => ...)):
		// the SDK calls its handler only for that exact URI, so its uri argument is the server's
		// own constant, not something the client chose
		c.seeded[sym.ID] = true
		return map[string]taintInfo{}
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

	names, position := c.paramBindingNames(sym)
	if names != nil && len(names) == 0 && c.handlerDeclaresParams(sym) {
		// Every declared parameter is a context the SDK injects: nothing the client controls
		// arrives, which is an analyzed handler with an empty seed, not a gap
		c.seeded[sym.ID] = true
		return map[string]taintInfo{}
	}
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
	validators := c.annotationValidators(sym)
	var scalar map[string]bool
	if kind == graph.CapabilityTool && capRec.Form == "decorator" {
		scalar = c.scalarAnnotatedParams(sym)
	}
	for _, name := range names {
		if scalar[name] {
			// port: int = 8000 on a FastMCP tool: the SDK validates the arguments against the
			// annotations before the handler runs, so the value is a number, a bool or one of the
			// author's Literal choices - nothing that can carry a path or a command
			continue
		}
		info := taintInfo{confidence: 1, chain: []model.FlowStep{{
			Kind: "source", Symbol: name, File: sym.File, Line: sym.Line, Detail: detail, Resolved: true,
		}}}
		if v := validators[name]; v != "" {
			// path: Annotated[str, BeforeValidator(validate_path)]: the SDK runs the project's own
			// check on the argument before the handler sees it
			info = info.extend(model.FlowStep{
				Kind: "sanitizer", Symbol: v, File: sym.File, Line: sym.Line, Detail: validatorDetail, Resolved: true,
			}, 1)
		}
		if review := c.goCustomParamsType(sym, name); review != "" && info.review == "" {
			info.review = review
		}
		if p, ok := position[name]; ok && p > 0 {
			skip, review := c.laterParamRole(sym, capRec)
			if skip {
				continue
			}
			info.review = review
		}
		seed[name] = info
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
func (c *ctx) paramBindingNames(sym *graph.Symbol) ([]string, map[string]int) {
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil {
		return sym.Params, nil
	}
	list := parser.ParamList(node)
	if list == nil {
		return sym.Params, nil
	}
	names := []string{}
	position := map[string]int{}
	skipped := 0
	cursor := list.Walk()
	defer cursor.Close()
	children := list.NamedChildren(cursor)
	if len(children) > 0 && parser.HasImplicitReceiver(pf.adapter.ID, node, pf.src) {
		// self is bound by the call, not by the caller: nothing an
		// attacker controls arrives through it
		children = children[1:]
	}
	for i, ch := range children {
		param := ch
		if pf.adapter.ID == language.Rust && param.Kind() == "self_parameter" {
			// &self, &mut self, self: the tool struct, not anything the client sends
			skipped++
			continue
		}
		if sdkContextParam(param.Utf8Text(pf.src), i) {
			// The SDK fills it in - a request context, a cancellation context, a progress
			// reporter - so the client controls none of it
			skipped++
			continue
		}
		bound := append(parser.ParamBindings(pf.adapter.ID, &param, pf.src), param.Utf8Text(pf.src))
		for _, b := range bound {
			position[b] = i
		}
		names = append(names, bound...)
	}
	if len(names) == 0 && skipped == 0 {
		return sym.Params, nil
	}
	return names, position
}

// laterParamRole says what a TypeScript or JavaScript handler parameter after the first is. The
// TypeScript SDK calls a tool, prompt or resource callback as (args, extra): only the first
// parameter carries what the client sent. A project's own wrapper may call its handler with
// anything, so there the parameter stays a source but its findings go to review.
func (c *ctx) laterParamRole(sym *graph.Symbol, cp graph.Capability) (skip bool, review string) {
	f := c.g.Files[sym.File]
	if f == nil || (f.Language != string(language.TypeScript) && f.Language != string(language.JavaScript)) {
		return false, ""
	}
	// Only when the first parameter is plainly the arguments object, ({ url, page }, extra): other
	// frameworks order their callbacks differently, (ctx, args)
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil {
		return false, ""
	}
	list := parser.ParamList(node)
	if list == nil {
		return false, ""
	}
	cursor := list.Walk()
	defer cursor.Close()
	params := list.NamedChildren(cursor)
	if len(params) == 0 || !strings.HasPrefix(strings.TrimSpace(params[0].Utf8Text(pf.src)), "{") {
		return false, ""
	}
	switch cp.Form {
	case "direct", "factory", "loop":
		return true, ""
	}
	return false, fmt.Sprintf("the value is a later parameter of a handler registered through a %s; the SDK passes only (args, extra), so what the project's wrapper puts in this parameter - client input or its own data - decides between a real issue and noise", cp.Form)
}

// goSDKRequestType matches the request types Go MCP SDKs hand a tool handler: mcp-go's
// mcp.CallToolRequest and the official SDK's *mcp.CallToolRequest / CallToolParamsFor[T]
var goSDKRequestType = regexp.MustCompile(`\bCallTool(Request|Params|ParamsFor|Result)\b|^\*?mcp\.`)

// goCustomParamsType returns a review reason when a Go tool handler's parameter is a type of the
// project's own rather than an SDK request: api.ToolHandlerParams bundling the call's arguments
// with the server's config and clients. Which of its fields carry client input is the project's
// choice, so a flow from it is not decided by the type.
func (c *ctx) goCustomParamsType(sym *graph.Symbol, name string) string {
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil || pf.adapter.ID != language.Go {
		return ""
	}
	list := parser.ParamList(node)
	if list == nil {
		return ""
	}
	for i := range list.NamedChildCount() {
		p := list.NamedChild(i)
		if p == nil || p.Kind() != "parameter_declaration" {
			continue
		}
		typ := p.ChildByFieldName("type")
		if typ == nil {
			continue
		}
		for _, b := range parser.ParamBindings(pf.adapter.ID, p, pf.src) {
			if b != name {
				continue
			}
			t := strings.TrimSpace(typ.Utf8Text(pf.src))
			if goSDKRequestType.MatchString(t) || sdkContextType.MatchString(" "+t) || !strings.Contains(t, ".") {
				return ""
			}
			return fmt.Sprintf("the handler takes %s, the project's own parameter type rather than an SDK request; which of its fields carry the client's arguments and which hold the server's own config or clients decides between a real issue and noise", t)
		}
	}
	return ""
}

// sdkContextType matches the parameter types MCP SDKs inject into a handler: FastMCP's Context,
// Go's context.Context, the TypeScript SDK's RequestHandlerExtra
var sdkContextType = regexp.MustCompile(`(^|[\s:*&(])(context\.Context|Context(\[[^\]]*\])?|RequestHandlerExtra(<[^>]*>)?|ServerContext)(\s*(\||=|,|$))`)

// sdkContextParam reports whether a handler parameter is a context the SDK injects. The type
// annotation decides, not the name, since a tool may well take a "context: str" argument. The one
// name-only case is an untyped "extra" after the first parameter, the TypeScript SDK's convention
// for its RequestHandlerExtra argument.
func sdkContextParam(text string, position int) bool {
	t := strings.TrimSpace(text)
	if position > 0 && t == "extra" {
		return true
	}
	if i := strings.IndexAny(t, ": "); i > 0 {
		return sdkContextType.MatchString(t[i:])
	}
	return false
}

// analyzeSymbol walks one function's body with the given seed taint. A seed is marked visited
// only after the definition and body are found, so lookup failure cannot count as analysis.
func (c *ctx) analyzeSymbol(sym *graph.Symbol, seed map[string]taintInfo, depth int) {
	if depth > maxDepth {
		c.depthCapHit = true
		return
	}
	if scalar := c.goScalarParams(sym); len(scalar) > 0 && len(seed) > 0 {
		// func list(id string, withLast bool): Go's compiler guarantees a bool or a number in
		// withLast, which carries no text into a query, a path or a command
		kept := make(map[string]taintInfo, len(seed))
		for k, v := range seed {
			if !scalar[k] {
				kept[k] = v
			}
		}
		if len(kept) == 0 {
			return
		}
		seed = kept
	}
	key := seedKeyFor(sym.ID, seed)
	if c.visited[key] {
		// The same shape was walked from another caller; its findings still hold for this one,
		// whose path - and so reachability and source - can differ
		c.replay(key, seed)
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
	start := len(c.findings)
	c.walk(pf, sym.File, tainted, body, depth, false)
	c.summarize(key, seed, start)
}

// maxReplaysPerKey bounds how many times one walk's findings are re-emitted for later callers
const maxReplaysPerKey = 64

// summaryEntry is a finding a walk produced from one of its seeded parameters: the path after
// that parameter's own chain is the part every caller with the same shape shares
type summaryEntry struct {
	finding   model.Finding
	review    string
	param     string
	prefixLen int
	seedConf  float64
}

// summarize records, for the walk just finished, each finding whose path starts with one seeded
// parameter's chain. A finding that does not start with one (its source is inside the walk) is the
// same whoever calls, so it needs no replay.
func (c *ctx) summarize(key seedKey, seed map[string]taintInfo, start int) {
	if len(seed) == 0 {
		return
	}
	names := taintedNames(seed)
	for i := start; i < len(c.findings); i++ {
		f := c.findings[i]
		if len(f.Evidence) == 0 {
			continue
		}
		path := f.Evidence[0].Path
		best, bestLen := "", -1
		for _, n := range names {
			pc := seed[n].chain
			if len(pc) > bestLen && len(pc) <= len(path) && slices.Equal(path[:len(pc)], pc) {
				best, bestLen = n, len(pc)
			}
		}
		if best == "" {
			continue
		}
		review := ""
		if f.Triage == model.TriageNeedsReview && f.TriageReason != seed[best].review {
			// a reason the walk itself produced, not one the seed carried in
			review = f.TriageReason
		}
		c.summaries[key] = append(c.summaries[key], summaryEntry{finding: f, review: review, param: best, prefixLen: bestLen, seedConf: seed[best].confidence})
	}
}

// replay re-emits a walked shape's findings with this caller's chain in front of the shared part
func (c *ctx) replay(key seedKey, seed map[string]taintInfo) {
	if len(seed) == 0 || c.replays[key] >= maxReplaysPerKey {
		return
	}
	entries := c.summaries[key]
	if len(entries) == 0 {
		return
	}
	c.replays[key]++
	for _, e := range entries {
		ns, ok := seed[e.param]
		if !ok || ns.clearedFor[e.finding.Category] {
			continue
		}
		old := e.finding.Evidence[0].Path
		chain := make([]model.FlowStep, 0, len(ns.chain)+len(old)-e.prefixLen)
		chain = append(chain, ns.chain...)
		chain = append(chain, old[e.prefixLen:]...)
		if slices.Equal(chain, old) {
			continue
		}
		f := e.finding
		f.Evidence = []model.Evidence{f.Evidence[0]}
		f.Evidence[0].Path = chain
		desc := "traced path: " + describePath(chain)
		f.Description, f.Evidence[0].Description = desc, desc
		if e.seedConf > 0 {
			f.Confidence = max(0, min(f.Confidence*ns.confidence/e.seedConf, 1))
		}
		f.Triage, f.TriageReason = "", ""
		switch {
		case ns.review != "":
			f.Triage, f.TriageReason = model.TriageNeedsReview, ns.review
		case e.review != "":
			f.Triage, f.TriageReason = model.TriageNeedsReview, e.review
		}
		c.findings = append(c.findings, f)
	}
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
	if restore := blockScope(pf, tainted, n); restore != nil {
		defer restore()
	}
	if c.retCapture != nil {
		defer c.captureReturn(pf, n, tainted)
	}
	switch {
	case slices.Contains(grammar.AssignKinds, n.Kind()):
		// const url = ... directly in a { } block is a new binding whose only value is its
		// initializer, even inside a branch: the old value cannot reach a use after it
		c.handleAssign(pf, file, tainted, n, depth, conditional && !blockLexicalDeclarator(pf, n))
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

// ownMethodInFile reports whether calleeText is this.<name> or self.<name> and the file defines
// exactly one method of that name - the one such a call reaches, unless it is inherited from
// elsewhere, in which case the file defines none and the call is left alone
func (c *ctx) ownMethodInFile(file, calleeText string) bool {
	t := strings.TrimSpace(calleeText)
	name, ok := strings.CutPrefix(t, "this.")
	if !ok {
		if name, ok = strings.CutPrefix(t, "self."); !ok {
			return false
		}
	}
	if !isPlainIdent(name) {
		return false
	}
	n := 0
	for _, id := range c.idx[name] {
		if s := c.g.Symbols[id]; s != nil && s.File == file && s.Kind == graph.KindMethod {
			n++
		}
	}
	return n == 1
}

// enclosingFunctionText returns the source text of the function around n, or "" at module level
func enclosingFunctionText(pf *parsedFile, n *sitter.Node) string {
	for a := n.Parent(); a != nil; a = a.Parent() {
		switch a.Kind() {
		case "function_definition", "function_declaration", "method_definition", "arrow_function", "function_expression", "method_declaration", "function_item":
			return a.Utf8Text(pf.src)
		}
	}
	return ""
}

// blockScope handles JavaScript/TypeScript block scoping: a const or let declared directly in a
// { } block is a different variable from any outer one of the same name, and it ends with the
// block. blockScope saves the outer state of every such name and returns the function that puts
// it back once the block has been walked, or nil when the block declares none.
func blockScope(pf *parsedFile, tainted map[string]taintInfo, n *sitter.Node) func() {
	if n.Kind() != "statement_block" || (pf.adapter.ID != language.JavaScript && pf.adapter.ID != language.TypeScript) {
		return nil
	}
	saved := map[string]*taintInfo{}
	for i := range n.NamedChildCount() {
		decl := n.NamedChild(i)
		if decl == nil || decl.Kind() != "lexical_declaration" {
			continue
		}
		for j := range decl.NamedChildCount() {
			d := decl.NamedChild(j)
			if d == nil || d.Kind() != "variable_declarator" {
				continue
			}
			for _, name := range boundNames(d.ChildByFieldName("name"), pf.src) {
				if _, seen := saved[name]; seen {
					continue
				}
				if v, ok := tainted[name]; ok {
					saved[name] = &v
				} else {
					saved[name] = nil
				}
			}
		}
	}
	if len(saved) == 0 {
		return nil
	}
	return func() {
		for name, v := range saved {
			if v == nil {
				delete(tainted, name)
			} else {
				tainted[name] = *v
			}
		}
	}
}

// blockLexicalDeclarator reports whether n is a declarator of a const or let directly in a
// JavaScript/TypeScript { } block, the declarations blockScope scopes
func blockLexicalDeclarator(pf *parsedFile, n *sitter.Node) bool {
	if n.Kind() != "variable_declarator" || (pf.adapter.ID != language.JavaScript && pf.adapter.ID != language.TypeScript) {
		return false
	}
	decl := n.Parent()
	if decl == nil || decl.Kind() != "lexical_declaration" {
		return false
	}
	block := decl.Parent()
	return block != nil && block.Kind() == "statement_block"
}

// boundNames lists the identifiers a declaration binds: x, or each name in {a, b: c} and [d, e]
func boundNames(n *sitter.Node, src []byte) []string {
	if n == nil {
		return nil
	}
	switch n.Kind() {
	case "identifier", "shorthand_property_identifier_pattern":
		return []string{n.Utf8Text(src)}
	case "assignment_pattern", "object_assignment_pattern":
		return boundNames(n.ChildByFieldName("left"), src)
	case "pair_pattern":
		return boundNames(n.ChildByFieldName("value"), src)
	}
	var out []string
	for i := range n.NamedChildCount() {
		out = append(out, boundNames(n.NamedChild(i), src)...)
	}
	return out
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
	// regexBind is whether each assignment to a name was a regular expression; a name also
	// assigned anything else is not one
	regexBind := map[string]bool{}
	regexConflict := map[string]bool{}
	tracksRegExps := pf.adapter.ID == language.JavaScript || pf.adapter.ID == language.TypeScript
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
			if tracksRegExps {
				isRegExp := rhs != nil && len(targets) == 1 && isRegExpValue(pf, rhs)
				for _, t := range targets {
					if prev, seen := regexBind[t]; seen && prev != isRegExp {
						regexConflict[t] = true
					}
					regexBind[t] = isRegExp
				}
			}
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
	for name, isRegExp := range regexBind {
		if isRegExp && !regexConflict[name] && !conflict[name] {
			c.regexps[fileAlias{file: file, name: name}] = true
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

// isRegExpValue reports whether a JavaScript/TypeScript expression evaluates to a regular
// expression: a literal, new RegExp(...), or RegExp(...)
func isRegExpValue(pf *parsedFile, n *sitter.Node) bool {
	n = unwrapParens(n)
	switch n.Kind() {
	case "regex":
		return true
	case "new_expression":
		ctor := n.ChildByFieldName("constructor")
		return ctor != nil && isRegExpConstructor(ctor.Utf8Text(pf.src))
	case "call_expression":
		fn := n.ChildByFieldName("function")
		return fn != nil && isRegExpConstructor(fn.Utf8Text(pf.src))
	}
	return false
}

func isRegExpConstructor(text string) bool {
	text = strings.TrimSpace(text)
	return text == "RegExp" || text == "globalThis.RegExp"
}

func unwrapParens(n *sitter.Node) *sitter.Node {
	for n.Kind() == "parenthesized_expression" && n.NamedChildCount() == 1 {
		n = n.NamedChild(0)
	}
	return n
}

// regExpReceiver reports whether call is `<receiver>.exec(...)` on a value known to be a regular
// expression: an inline literal or constructor, or a name this file binds only to one. Any
// receiver it cannot place - a parameter, a property, an import - is left to the sink tables.
func (c *ctx) regExpReceiver(pf *parsedFile, file string, call *sitter.Node) bool {
	if pf.adapter.ID != language.JavaScript && pf.adapter.ID != language.TypeScript {
		return false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" {
		return false
	}
	prop := fn.ChildByFieldName("property")
	if prop == nil || prop.Utf8Text(pf.src) != "exec" {
		return false
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil {
		return false
	}
	obj = unwrapParens(obj)
	if isRegExpValue(pf, obj) {
		return true
	}
	if obj.Kind() != "identifier" {
		return false
	}
	name := obj.Utf8Text(pf.src)
	return c.regexps[fileAlias{file: file, name: name}] && !shadowedAt(call, name, pf.src)
}

// shadowedAt reports whether a function parameter, loop variable or catch binding around n
// declares name. Assignments are already folded into the file-wide binding; these bindings are
// not assignments, and one of them can hold anything, child_process included.
func shadowedAt(n *sitter.Node, name string, src []byte) bool {
	for a := n.Parent(); a != nil; a = a.Parent() {
		var bindings []*sitter.Node
		switch a.Kind() {
		case "function_declaration", "function_expression", "function", "arrow_function",
			"method_definition", "generator_function_declaration", "generator_function":
			bindings = append(bindings, a.ChildByFieldName("parameters"), a.ChildByFieldName("parameter"))
		case "for_in_statement":
			bindings = append(bindings, a.ChildByFieldName("left"))
		case "catch_clause":
			bindings = append(bindings, a.ChildByFieldName("parameter"))
		}
		for _, b := range bindings {
			if b != nil && declaresIdent(b, name, src) {
				return true
			}
		}
	}
	return false
}

// declaresIdent reports whether any identifier in a binding subtree is name. It also visits
// default values and type annotations, which can only make it report a shadow that is not
// there - the safe direction, since a shadow keeps the sink.
func declaresIdent(n *sitter.Node, name string, src []byte) bool {
	switch n.Kind() {
	case "identifier", "shorthand_property_identifier_pattern":
		return n.Utf8Text(src) == name
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if ch := n.NamedChild(i); ch != nil && declaresIdent(ch, name, src) {
			return true
		}
	}
	return false
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
	if branches, ok := conditionalBranches(rhs); ok {
		// x = "a.jsonl" if kind == FLOW else "b.jsonl": the value is one of the branches; the
		// condition only picks which, so it carries no taint into x
		var text []string
		for _, b := range branches {
			text = append(text, b.Utf8Text(pf.src))
		}
		if _, found := propagatedTaint(strings.Join(text, " ; "), tainted); !found {
			clearTaint(tainted, targets, conditional)
			return
		}
	}
	if info, ok := hexOnly(rhs.Utf8Text(pf.src), tainted); ok {
		// key = name.encode().hex(), digest = sha256(x).hexdigest(): only hex digits remain
		setTaint(tainted, targets, info.extend(model.FlowStep{
			Kind: "sanitizer", Symbol: "hex encoding", File: file, Line: line, Resolved: true,
			Detail: "the value is hex-encoded: only 0-9 and a-f remain",
		}, 1), conditional)
		return
	}
	if rebuilt := allowlistRebuild(rhs.Utf8Text(pf.src)); rebuilt != "" {
		if info, ok := mentionsAny(rebuilt, tainted, ""); ok {
			// "".join(c if c.isalnum() else "-" for c in name), re.sub(r"[^A-Za-z0-9_-]", "", name):
			// only letters, digits, "_" and "-" survive
			info = info.extend(model.FlowStep{
				Kind: "sanitizer", Symbol: "allowlist rebuild", File: file, Line: line, Resolved: true,
				Detail: "the value is rebuilt from letters, digits, \"_\" and \"-\" only",
			}, 1)
			info.clearedFor = mergeClearedFor(info.clearedFor, []string{"path_traversal", "command_injection", "sql_injection"})
			setTaint(tainted, targets, info, conditional)
			return
		}
	}
	// Clear SSRF taint when a fixed prefix closes the URL's host before computed text begins
	fixedHost := c.urlHostFixed(pf, file, rhs, tainted)

	if augmentedAssignKinds[n.Kind()] {
		text := strings.Join(targets, " + ") + " + " + rhs.Utf8Text(pf.src)
		if info, ok := propagatedTaint(text, tainted); ok {
			if len(targets) == 1 && !fromMCPInputName(tainted, targets[0]) && c.holdsFixedHostURL(pf, n, targets[0]) {
				// url = "https://docs.example/latest/"; url += topic: text appended to a URL whose
				// host is already closed lands in its path
				info = info.clearFor("ssrf")
			}
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

		detail, isSource := matchSource(maskLiteralText(calleeText))
		if !isSource && aliased {
			detail, isSource = matchSource(maskLiteralText(matchText))
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
			if isComposition(pf, rhs) {
				info = info.extend(model.FlowStep{
					Kind: "transform", Symbol: titleCallee(calleeText), File: file, Line: line, Detail: compositionDetail, Resolved: true,
				}, 1)
			}
			setTaint(tainted, targets, ssrfCleared(info, fixedHost), conditional)
			return
		}

		kind, mult, detail := "unknown", 0.6, "result of a call that received tainted input"
		if resolved {
			kind, mult = "transform", 0.85
		} else if c.mcpGoArgumentGetter(file, calleeText) {
			// req.RequireString("path"): the mcp-go SDK's request getters return the client's
			// argument as sent, so the call is known and passes the value on unchanged
			kind, mult, resolved, detail = "transform", 1, true, "the client's argument, read through the mcp-go request"
		}
		step := model.FlowStep{
			Kind: kind, Symbol: calleeText, File: file, Line: line, Resolved: resolved,
			Detail: detail,
		}
		info := from.extend(step, mult)
		if why, ok := c.escapedBy(rhs.Utf8Text(pf.src)); ok && info.review == "" {
			info.review = escapedReview(why)
		}
		if resolved && c.isProjectValidator(sym) {
			info = info.extend(model.FlowStep{
				Kind: "sanitizer", Symbol: calleeText, File: file, Line: line, Detail: validatorDetail, Resolved: true,
			}, 1)
		}
		if isComposition(pf, rhs) {
			info = info.extend(model.FlowStep{
				Kind: "transform", Symbol: titleCallee(calleeText), File: file, Line: line, Detail: compositionDetail, Resolved: true,
			}, 1)
		}
		if reintroducesPathSyntax(calleeText) {
			// A guard proved something about the string it tested, and this call produces a different
			// string: "%2e%2e%2f" passes a join and a prefix test as ordinary characters and comes out
			// of a decoder as "../"
			info.clearedFor = withoutCategory(info.clearedFor, "path_traversal")
			info.normalized = false
		}
		if resolved && kind == "transform" && c.goScalarResult(sym) {
			// flag := boolArgument(req, "force"): a Go function declared to return a bool or a number
			// hands back no text, whatever it was given
			clearTaint(tainted, targets, conditional)
			c.recurseInto(sym, c.fixedHostArgs(pf, file, rhs, sym, args, tainted, c.seedArgs(sym, args, tainted, step, mult)), depth)
			return
		}
		if resolved && kind == "transform" {
			if cats := c.callResultCleared(sym, args, tainted); len(cats) > 0 {
				// resolve(name) returns name only after its own check: the result is cleared for
				// what every return of the function clears
				info = info.extend(model.FlowStep{
					Kind: "sanitizer", Symbol: calleeText, File: file, Line: line, Resolved: true,
					Detail: "the function returns the value only after checking or rebuilding it (" + strings.Join(cats, ", ") + ")",
				}, 1)
				info.clearedFor = mergeClearedFor(info.clearedFor, cats)
			}
		}
		setTaint(tainted, targets, ssrfCleared(info, fixedHost), conditional)

		if resolved {
			c.recurseInto(sym, c.fixedHostArgs(pf, file, rhs, sym, args, tainted, c.seedArgs(sym, args, tainted, step, mult)), depth)
		}
		return
	}

	text := rhs.Utf8Text(pf.src)
	// Attribute, index, or member access can carry a source value without being a call itself,
	// as in `requests.get(u).text`, `os.environ["JOB"]`, or `process.env.JOB`. String contents
	// are blanked first: a description that says "fetch the next page" reads nothing
	if detail, ok := matchSource(maskLiteralText(text)); ok {
		setTaint(tainted, targets, taintInfo{confidence: 1, chain: []model.FlowStep{{
			Kind: "source", Symbol: strings.TrimSpace(text), File: file, Line: line, Detail: detail, Resolved: true,
		}}}, conditional)
		return
	}
	if info, ok := propagatedTaint(text, tainted); ok {
		if cats, rv, sum := c.exprSummary(pf, file, rhs, tainted); sum {
			// backup_id = f"{prefix(url_path)}{stamp}.json": the tainted value is used only through
			// project functions whose returns are cleared (or escaped)
			info.clearedFor = mergeClearedFor(info.clearedFor, cats)
			if rv != "" && info.review == "" {
				info.review = rv
			}
		}
		if isComposition(pf, rhs) {
			info = info.extend(model.FlowStep{
				Kind: "transform", Symbol: titleCallee(text), File: file, Line: line, Detail: compositionDetail, Resolved: true,
			}, 1)
		}
		setTaint(tainted, targets, ssrfCleared(info, fixedHost), conditional)
		return
	}
	clearTaint(tainted, targets, conditional)
}

// validatorDetail marks a pass through a project's own validation function
const validatorDetail = "checked by a project validator the scanner does not verify"

// projectValidatorName matches the names projects give their own input checks
var projectValidatorName = regexp.MustCompile(`(?i)^_*(validate|sanitize|sanitise|check|ensure|verify|assert|safe|clean|normalize)[a-z0-9_]*$`)

// isProjectValidator reports whether an in-repo function looks like an input check: a validator's
// name and a body that can reject its input by raising or throwing
func (c *ctx) isProjectValidator(sym *graph.Symbol) bool {
	if sym == nil || !projectValidatorName.MatchString(sym.Name) {
		return false
	}
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil {
		return false
	}
	body := node.Utf8Text(pf.src)
	return strings.Contains(body, "raise ") || strings.Contains(body, "throw ") || strings.Contains(body, "return fmt.Errorf") || strings.Contains(body, "errors.New(")
}

func hasValidatorStep(info taintInfo) bool {
	for _, st := range info.chain {
		if st.Detail == validatorDetail {
			return true
		}
	}
	return false
}

// compositionDetail marks a step where the tainted value was combined with other text. It is
// evidence for a reader - this is where an argument was spliced into a query or a command - and it
// is what separates an injection from a tool that passes the caller's whole value on by design.
const compositionDetail = "combined with other text into a larger string"

// compositionCalls build a string or a path out of parts. The value is the fewest arguments that
// make a call a composition: Path(name) or resolve(name) alone converts one value, while
// Path(base, name) and path.resolve(ROOT, name) put the caller's part under a base the tool
// meant to stay inside.
var compositionCalls = map[string]int{
	"format": 1, "Sprintf": 2, "sprintf": 2, "join": 1, "Join": 1, "concat": 1, "Concat": 1,
	"joinpath": 1, "resolve": 2, "Path": 2, "PurePath": 2, "PosixPath": 2,
}

// isComposition reports whether an expression builds a larger string from parts: concatenation,
// %-formatting, an f-string or template with an interpolation, or a format/join call
func isComposition(pf *parsedFile, n *sitter.Node) bool {
	if n == nil {
		return false
	}
	n = unwrapAwait(n)
	switch n.Kind() {
	case "parenthesized_expression":
		if n.NamedChildCount() == 1 {
			return isComposition(pf, n.NamedChild(0))
		}
	case "binary_operator", "binary_expression":
		if op := n.ChildByFieldName("operator"); op != nil {
			switch op.Utf8Text(pf.src) {
			case "+", "%":
				return true
			case "/":
				// pathlib's base / name; in other languages "/" is division
				return pf.adapter.ID == language.Python
			}
		}
	case "template_string":
		for i := range n.NamedChildCount() {
			if n.NamedChild(i).Kind() == "template_substitution" {
				return true
			}
		}
	case "string":
		for i := range n.NamedChildCount() {
			if n.NamedChild(i).Kind() == "interpolation" {
				return true
			}
		}
	}
	if slices.Contains(pf.adapter.Grammar.CallKinds, n.Kind()) {
		callee, _, args := parser.CalleeAndArgs(pf.adapter.ID, n, pf.src)
		if min, ok := compositionCalls[parser.LastSegment(callee)]; ok && len(args) >= min {
			return true
		}
		// A method called on a composed value keeps it composed: (NOTES / name).resolve()
		if fn := n.ChildByFieldName("function"); fn != nil {
			if obj := fn.ChildByFieldName("object"); obj != nil {
				return isComposition(pf, obj)
			}
		}
	}
	return false
}

// receiverComposed reports whether a sink's receiver is a composed value: (DOCS / name),
// Path("/srv/docs", name), DOCS.joinpath(name)
func receiverComposed(r parser.Receiver) bool {
	if compositionText.MatchString(strings.TrimSpace(r.Text)) {
		return true
	}
	if r.CallText != "" {
		min, ok := compositionCalls[parser.LastSegment(r.CallText)]
		return ok && len(r.CallArgs) >= min
	}
	return false
}

// compositionText is the text-only fallback for a receiver, which has no node at hand here:
// (DOCS / name).read_text(), (root + name).open()
var compositionText = regexp.MustCompile(`\s[/+%]\s|\$\{|\bjoinpath\(|\bjoin\(|^f["']`)

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
		if idx, info, found := taintedArgIndex(args[skip:], tainted, ""); found {
			line := int(n.StartPosition().Row) + 1
			if why, ok := c.escapedBy(args[skip+idx].Text); ok && info.review == "" {
				info.review = escapedReview(why)
			}
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
	sinkText := sinkCallee(calleeText)
	asWritten := true
	if aliased, ok := c.aliasedSinkText(file, calleeText); ok {
		sinkText, asWritten = aliased, false
	} else if rewritten, ok := c.rewriteModuleAlias(file, calleeText); ok && !isSinkText(pf.adapter.ID, sinkCallee(calleeText)) {
		sinkText, asWritten = sinkCallee(rewritten), false
	}
	if fnText, rest, ok := sinkValueArg(pf.adapter.ID, calleeText, args); ok {
		sinkText, args, receiver, asWritten = fnText, rest, parser.Receiver{}, false
	}

	if argv, argvArgs, ok := matchArgvSink(pf.adapter.ID, sinkText, args); ok {
		// found only means some tainted value reached the argv call; a
		// strong sanitizer upstream may still have cleared it for this
		// exact category (info.clearedFor) without clearing it for every
		// category, the same gate the plain-sink branch below applies
		if category, severity, mult, note, info, found := c.classifyArgv(file, argv.kind, calleeText, c.expandArgvVar(pf, n, argv.kind, argvArgs), tainted); found && !info.clearedFor[category] {
			if info.review == "" && (category == "command_injection" || category == "argument_injection") {
				// an element the project built through its own quoting function
				for _, a := range c.expandArgvVar(pf, n, argv.kind, argvArgs) {
					for _, e := range append([]graph.Arg{a}, bracketedListElements(a.Text)...) {
						if _, hit := mentionsAny(e.Text, tainted, ""); !hit {
							continue
						}
						if why, ok := c.escapedBy(e.Text); ok {
							info.review = escapedReview(why)
						}
					}
				}
			}
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
	if resolvedInRepo && c.isProjectValidator(sym) {
		// validate_table_name(table_name) as a statement: later uses of the argument went through
		// a check. The scanner cannot tell whether the check is sound, so taint stays and the step
		// sends the finding to review instead of clearing it.
		line := int(n.StartPosition().Row) + 1
		for _, a := range args {
			name := strings.TrimSpace(a.Text)
			if info, ok := tainted[name]; ok && isPlainIdent(name) && !hasValidatorStep(info) {
				tainted[name] = info.extend(model.FlowStep{
					Kind: "sanitizer", Symbol: calleeText, File: file, Line: line, Detail: validatorDetail, Resolved: true,
				}, 1)
			}
		}
	}

	sink, sinkFound := matchSink(sinkText)
	if sinkFound && sink.text == "exec" && pf.adapter.ID == language.Go && strings.TrimSpace(sinkText) != "exec" {
		// exec.LookPath, exec.ExitError: Go's os/exec package name, not a shell exec. Go starts a
		// process only through exec.Command(Context), which the argv rules handle
		sinkFound = false
	}
	if sinkFound && sink.category == "command_injection" && parser.LastSegment(sinkText) == "exec" && sqlExecReceiver(sinkText) {
		// this.sql.exec(query, ...bindings) and db.exec(sql) run SQL, not a process
		sink = sinkPattern{text: "exec", category: "sql_injection", severity: model.SeverityHigh, argIndex: 0}
	}
	if sinkFound && sink.category == "ssrf" && asyncpgQuery[parser.LastSegment(sinkText)] && receiverLooksLikeDB(sinkText) {
		// conn.fetch(sql) in asyncpg is a query, not an HTTP request
		sink = sinkPattern{text: parser.LastSegment(sinkText), category: "sql_injection", severity: model.SeverityHigh, argIndex: 0}
	}
	if sinkFound && resolvedInRepo && asWritten && !strings.ContainsAny(sink.text, ".:") && !strings.ContainsAny(calleeText, ".:") && sym != nil && sym.Name == calleeText && c.bindsName(file, sym, calleeText) {
		// fetch(path) where this file defines or imports its own fetch: the call goes to that
		// function, which is followed below, not to the global API sharing its name. A function
		// of that name elsewhere in the tree - a fetch(req) method in a server object - does not
		// shadow the global here.
		sinkFound = false
	}
	if sinkFound && sink.text == "exec" && sink.category == "command_injection" && pf.adapter.ID == language.Python && strings.TrimSpace(sinkText) == "exec" {
		// Python's builtin exec(code) runs Python source, not a process: code execution
		sink = sinkPattern{text: "exec", category: "eval", severity: model.SeverityHigh, argIndex: 0}
	}
	if sinkFound && sink.text == "exec" && asWritten && c.regExpReceiver(pf, file, n) {
		// RegExp.prototype.exec matches a string against a pattern; it runs nothing
		sinkFound = false
	}
	byMethodName := false
	if !sinkFound && !resolvedInRepo {
		// methodSinkPatterns matches by method name alone, which a plain in-repo function sharing
		// that name would also match - a helper named execute() is not cursor.execute just because
		// they share a name
		sink, sinkFound = matchMethodSink(sinkText)
		byMethodName = sinkFound
	}
	needsSQLEvidence := false
	if !sinkFound && resolvedInRepo && receiverMaybeDB(sinkText) {
		// Resolution is by method name, so one in-repo class with an execute() or query() method
		// made every cursor.execute(...) and client.query(...) in the tree resolve to it, and real
		// SQL injection went unreported. A database-like receiver keeps the SQL check; the in-repo
		// method is still followed below. A generic receiver (client) also needs SQL text on the
		// path, so a search client's query(IndexId=...) or an HTTP client's execute(request)
		// is not read as SQL.
		if m, ok := matchMethodSink(sinkText); ok && m.category == "sql_injection" {
			sink, sinkFound, byMethodName = m, true, true
			needsSQLEvidence = !receiverLooksLikeDB(sinkText)
		}
	}
	if !sinkFound && !resolvedInRepo {
		recv := receiver
		if recv.Text == "" && recv.CallText == "" {
			// Recover the receiver from the callee after unwrapping asyncio.to_thread(client.get, url)
			if i := strings.LastIndexByte(sinkText, '.'); i > 0 {
				recv.Text = sinkText[:i]
			}
		}
		if c.httpClientReceiver(pf, file, recv) {
			sink, sinkFound = matchGatedMethodSink(sinkText)
		}
	}
	if sinkFound && (byMethodName || !strings.ContainsAny(sink.text, ".:")) && c.ownMethodInFile(file, calleeText) {
		// this.open('manual', id) / self.open(path) where this file defines that one method: a
		// call on this or self goes to the object's own member, not to the builtin or library
		// function the sink name means; the method is followed below
		sinkFound = false
	}
	if sinkFound {
		var info taintInfo
		var found bool
		if sink.argIndex >= 0 {
			if a, ok := sinkArg(args, sink.argIndex, sink.category); ok && !(byMethodName && isFunctionLiteralText(a.Text)) {
				// A sink matched by method name alone whose checked argument is a function
				// literal is some other API: a URL or a query string is never a closure, while
				// sync.Once.Do(func() {...}) and errgroup-style Do(fn) take exactly that
				info, found = mentionsAny(a.Text, tainted, sink.category)
				if found {
					// open(locate(name)): the argument is a project function's result, and every
					// return of that function is cleared for this sink's category - or escapes the
					// value through the project's own function, which goes to review
					if cl, rv := c.argCallVerdict(pf, file, argNode(n, a, pf.src), tainted, sink.category); cl {
						found = false
					} else if rv != "" && info.review == "" {
						info.review = rv
					}
				}
				if found && sink.category == "sql_injection" && pf.adapter.ID == language.Python && c.sqlalchemyStatement(file, a.Text, enclosingFunctionText(pf, n)) {
					// session.execute(update(T).where(T.id == x)): a SQLAlchemy statement binds x as a
					// parameter; only text(), literal_column() or a built string would make it SQL
					found = false
				}
				if found && sink.category == "ssrf" {
					if an := argNode(n, a, pf.src); c.urlHostFixed(pf, file, an, tainted) {
						found = false
					}
				}
				// The two checks below judge by names, not by what the code does: an execute() or
				// query() on an object not named like a database handle, or a generic client with no
				// SQL text on the path, is probably not SQL - a tool class, a job runner, a search API
				// - but a name cannot prove it. The finding stays, for a person to decide.
				if found && needsSQLEvidence && !sqlKeywords.MatchString(a.Text) && !chainHasSQLText(info) {
					info.review = fmt.Sprintf("%s was matched as SQL by its method name only: the receiver may be a database client, but no SQL text was seen on the path", sinkText)
				}
				if found && sink.category == "sql_injection" && byMethodName && pf.adapter.ID == language.Python && keywordOnlyNonSQL(args) && info.review == "" {
					// service.searchanalytics().query(siteUrl=..., body=...): DB-API drivers take the
					// statement positionally or as sql=/query=; named fields of another kind read as
					// an API client's query, but the names cannot prove it
					info.review = fmt.Sprintf("%s was matched as SQL by its method name only, and every argument is a named field none of which carries a statement (sql, query, statement), so it is probably an API client's query", sinkText)
				}
				if found && sink.category == "sql_injection" && byMethodName && commandObjectArg(a.Text) {
					// store.execute({ type: "save_app", name, ui }): an object literal with no field a
					// driver reads SQL from (sql, text, query, statement) is a command, not a query
					found = false
				}
				if found && byMethodName && sink.category == "sql_injection" && !sqlReceiver(sinkText, a.Text) {
					info.review = fmt.Sprintf("%s was matched as SQL by its method name only: the receiver is not named like a database handle and the argument shows no SQL text, so it is probably another API's %s", sinkText, parser.LastSegment(sinkText))
				}
				if found && byMethodName && !strings.ContainsAny(strings.TrimSpace(sinkText), ".:") && !sqlKeywords.MatchString(a.Text) && !chainHasSQLText(info) {
					// Query(**filters): the name patterns are for methods on a handle, and this call
					// has no receiver - a constructor or a plain function - unless the method was
					// pulled off its object first (const { query } = pool)
					info.review = fmt.Sprintf("%s was matched by a method name, but the call has no receiver and no SQL text was seen on the path, so it is probably a constructor or a plain function of the same name", sinkText)
				}
			}
		} else {
			var idx int
			idx, info, found = c.taintedArgOrReceiver(file, receiver, args, tainted, sink.category)
			if found && idx >= 0 && idx < len(args) {
				if _, rv := c.argCallVerdict(pf, file, argNode(n, args[idx], pf.src), tainted, sink.category); rv != "" && info.review == "" {
					info.review = rv
				}
			}
			if found && idx >= 0 && idx < len(args) && c.argCallClears(pf, file, argNode(n, args[idx], pf.src), tainted, sink.category) {
				// open(locate(name)): the tainted argument is a project function's result, and every
				// return of that function is cleared for this sink's category
				found = false
				for j, a := range args {
					if j == idx {
						continue
					}
					if i2, ok := mentionsAny(a.Text, tainted, sink.category); ok && !c.argCallClears(pf, file, argNode(n, a, pf.src), tainted, sink.category) {
						info, found = i2, true
						break
					}
				}
			}
			if found && idx < 0 && c.argCallClears(pf, file, receiverNode(n), tainted, sink.category) {
				// locate(name).read_text(): the receiver is a project function's result, and every
				// return of that function is cleared for this sink's category
				found = false
			}
			composedReceiver := found && idx < 0 && receiverComposed(receiver)
			if composedReceiver || (found && idx >= 0 && idx < len(args) && isComposition(pf, argNode(n, args[idx], pf.src))) {
				what := receiver.Text
				if what == "" {
					what = receiver.CallText
				}
				if idx >= 0 {
					what = args[idx].Text
				}
				line := int(n.StartPosition().Row) + 1
				info = info.extend(model.FlowStep{
					Kind: "transform", Symbol: titleCallee(what), File: file, Line: line, Detail: compositionDetail, Resolved: true,
				}, 1)
			}
		}
		// info.clearedFor[sink.category] means a strong sanitizer upstream
		// already covers exactly this sink's category (see handleAssign) -
		// not that the value is clean for every category, which is the
		// mistake that let basename() before a shell call and shlex.quote()
		// before a path read both scan clean
		if found && !info.clearedFor[sink.category] {
			line := int(n.StartPosition().Row) + 1
			if sink.argIndex >= 0 {
				if a, ok := sinkArg(args, sink.argIndex, sink.category); ok && isComposition(pf, argNode(n, a, pf.src)) {
					info = info.extend(model.FlowStep{
						Kind: "transform", Symbol: titleCallee(a.Text), File: file, Line: line, Detail: compositionDetail, Resolved: true,
					}, 1)
				}
			}
			if sink.category == "deserialization" && strings.HasSuffix(strings.TrimSpace(sinkText), "yaml.load") &&
				(pf.adapter.ID == language.TypeScript || pf.adapter.ID == language.JavaScript) && info.review == "" {
				// js-yaml's load has used the safe default schema since version 4; in 3 it builds
				// JavaScript functions from !!js/function tags. The version installed decides.
				info.review = fmt.Sprintf("%s is js-yaml's load, which is safe from version 4 on and builds JavaScript functions from !!js/function tags in version 3; the installed version decides between a real issue and noise", sinkText)
			}
			if sink.category == "ssrf" && byMethodName && parser.LastSegment(sinkText) == "Get" && info.review == "" && !httpLikeReceiver(sinkText) {
				// taskrunInformer.Lister().TaskRuns(ns).Get(name), cache.Get(key): a Get method on a
				// lister, a cache or a map is a lookup, not an HTTP request; matched by name alone
				info.review = fmt.Sprintf("%s was matched as an HTTP request by its method name only: its receiver does not look like an HTTP client, so it is probably a lookup in a cache, a lister or a map", sinkText)
			}
			if sink.text == "fetch" && sink.category == "ssrf" && info.review == "" && fetchOnOtherObject(pf.adapter.ID, sinkText) {
				// imap.fetch([uid]), cursor.fetch(n): a method named fetch on an object that is not the
				// global fetch API - matched by name alone
				info.review = fmt.Sprintf("%s was matched as an HTTP request by its method name only: its receiver is not the global fetch, so it may be another API's fetch (a mail client, a database cursor, a git remote)", sinkText)
			}
			if sink.text == "exec" && sink.category == "command_injection" && pf.adapter.ID == language.Java && javaExecOnOtherObject(calleeText) {
				info.review = fmt.Sprintf("%s was matched as a command by its method name only: its receiver is not a Runtime, so it is probably another API's exec", strings.TrimSpace(calleeText))
			} else if sink.text == "exec" && sink.category == "command_injection" && c.execOnOtherObject(file, sinkText) {
				// client.browsers.process.exec(id, {...}): a method named exec on an object no
				// child_process import binds - an API client's own exec - matched by name alone
				info.review = fmt.Sprintf("%s was matched as a command by its method name only: its receiver is not bound to child_process in this file, so it may be another API's exec (a remote sandbox, a database driver)", sinkText)
			}
			if name := strings.TrimSpace(calleeText); info.review == "" && isPlainIdent(name) &&
				(pf.adapter.ID == language.JavaScript || pf.adapter.ID == language.TypeScript) && shadowedAt(n, name, pf.src) {
				// function runGit(exec: ExecFileFn, ...) { exec("git", args, ...) }: the name is a
				// parameter (or a loop or catch binding) of the code around the call, not the library
				// function the sink table means; what it holds - child_process.exec, execFile or a
				// test double - is decided by the caller
				info.review = fmt.Sprintf("%s is a parameter of the enclosing function, not the library function of that name; which function it holds is decided by its caller", name)
			}
			final := info.extend(model.FlowStep{
				Kind: "sink", Symbol: calleeText, File: file, Line: line, Detail: sink.category, Resolved: true,
			}, 1)
			c.emit(sink.category, sink.severity, calleeText, final, file, line, "")
		}
		return
	}
	if _, ok := matchSource(maskLiteralText(calleeText)); ok {
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
				if c.summaryDepth == 0 {
					c.ambiguousCalls++
				}
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
	c.recurseInto(sym, c.fixedHostArgs(pf, file, n, sym, args, tainted, c.seedArgs(sym, args, tainted, step, 0.9)), depth)
}

// fixedHostArgs clears SSRF from a parameter whose argument fixes the host before any computed
// text - getStream(`/api/v1/applications/${name}/logs`) or get("https://api.x.example/" + id) -
// the same judgement handleAssign and the sink check make, applied where a URL is built as an
// argument and the request is made in the callee. What the caller can still change is the path
// on that host, which the path is no longer evidence of SSRF for.
func (c *ctx) fixedHostArgs(pf *parsedFile, file string, call *sitter.Node, sym *graph.Symbol, args []graph.Arg, tainted map[string]taintInfo, seed map[string]taintInfo) map[string]taintInfo {
	if call == nil || sym == nil {
		return seed
	}
	call = unwrapAwait(call)
	for i, a := range args {
		if i >= len(sym.Params) {
			break
		}
		info, ok := seed[sym.Params[i]]
		if !ok {
			continue
		}
		if an := argNode(call, a, pf.src); an != nil && c.urlHostFixed(pf, file, an, tainted) {
			seed[sym.Params[i]] = info.clearFor("ssrf")
		}
	}
	return seed
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
			info = info.extend(step, mult)
			if compositionText.MatchString(strings.TrimSpace(a.Text)) {
				// _ci_read(GITHUB_DIR / filename): the composition happens in the call itself
				info = info.extend(model.FlowStep{
					Kind: "transform", Symbol: titleCallee(a.Text), File: step.File, Line: step.Line, Detail: compositionDetail, Resolved: true,
				}, 1)
			}
			seed[sym.Params[i]] = info
		}
	}
	return seed
}

// seedArgs is seedFromArgs plus variadic parameters: CallProcedure(proc, "--soft", rev) with
// func CallProcedure(proc string, args ...string), def run(cmd, *argv) or function f(a, ...rest)
// sends every argument from the variadic position on to that one parameter
func (c *ctx) seedArgs(sym *graph.Symbol, args []graph.Arg, tainted map[string]taintInfo, step model.FlowStep, mult float64) map[string]taintInfo {
	seed := seedFromArgs(sym, args, tainted, step, mult)
	if sym == nil || len(args) <= len(sym.Params) {
		return seed
	}
	v := c.variadicParam(sym)
	if v == "" {
		return seed
	}
	for _, a := range args[len(sym.Params):] {
		if info, ok := mentionsAny(a.Text, tainted, ""); ok {
			if _, have := seed[v]; !have {
				if seed == nil {
					seed = map[string]taintInfo{}
				}
				seed[v] = info.extend(step, mult)
			}
		}
	}
	return seed
}

// variadicParam is the name of a function's trailing variadic parameter, or ""
func (c *ctx) variadicParam(sym *graph.Symbol) string {
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil {
		return ""
	}
	list := parser.ParamList(node)
	if list == nil || list.NamedChildCount() == 0 {
		return ""
	}
	last := list.NamedChild(list.NamedChildCount() - 1)
	if last == nil {
		return ""
	}
	switch last.Kind() {
	case "variadic_parameter_declaration", "list_splat_pattern", "rest_pattern", "required_parameter", "rest_parameter":
	default:
		return ""
	}
	text := strings.TrimSpace(last.Utf8Text(pf.src))
	if !strings.Contains(text, "...") && !strings.HasPrefix(text, "*") {
		return ""
	}
	if strings.HasPrefix(text, "**") {
		return ""
	}
	bs := parser.ParamBindings(pf.adapter.ID, last, pf.src)
	if len(bs) != 1 {
		return ""
	}
	return bs[0]
}

// goScalarResult reports whether a Go function's single result is a number or a bool
func (c *ctx) goScalarResult(sym *graph.Symbol) bool {
	if sym == nil || c.g.Files[sym.File] == nil || c.g.Files[sym.File].Language != string(language.Go) {
		return false
	}
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil {
		return false
	}
	res := node.ChildByFieldName("result")
	if res == nil {
		return false
	}
	t := strings.TrimSpace(res.Utf8Text(pf.src))
	if strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
		// (int64, error): the value a caller assigns first is the number; an unnamed list only
		parts := parser.SplitTopLevel(t[1 : len(t)-1])
		if len(parts) == 0 || strings.Contains(strings.TrimSpace(parts[0]), " ") {
			return false
		}
		t = strings.TrimSpace(parts[0])
	}
	return goScalarTypes[t]
}

// recurseInto walks sym's body with seed applied as its parameters' taint,
// through analyzeSymbol's (symbol, seed) visited guard: a cycle or a
// diamond in the call graph is walked at most once per distinct seed, so a
// helper seeded differently by two different callers is analyzed for each
// (bounded by maxSeedsPerSymbol), and analyzed only once for the same
// caller shape encountered again
func (c *ctx) recurseInto(sym *graph.Symbol, seed map[string]taintInfo, depth int) {
	if sym == nil || len(seed) == 0 || c.summaryDepth > 0 {
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
	if category == "path_traversal" {
		args = withoutNonPathOptions(args)
	}
	return worstCandidate(taintCandidates(args, extra, tainted, category), category)
}

// nonPathOptions are keyword arguments of file APIs that never name a file:
// path.read_text(encoding=enc) reads the receiver, whatever the encoding is
var nonPathOptions = map[string]bool{
	"encoding": true, "errors": true, "newline": true, "mode": true, "buffering": true,
	"closefd": true, "exist_ok": true, "parents": true, "missing_ok": true,
}

func withoutNonPathOptions(args []graph.Arg) []graph.Arg {
	out := args[:0:0]
	for _, a := range args {
		if !nonPathOptions[a.Keyword] {
			out = append(out, a)
		}
	}
	return out
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
	for _, name := range taintedNames(tainted) {
		info := tainted[name]
		if !mentionsTaintedVar(text, name) {
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
	for _, name := range taintedNames(tainted) {
		info := tainted[name]
		if !mentionsTaintedVar(text, name) {
			continue
		}
		candidate := info
		// normalized is a claim about the string a guard is about to test, not the value it was
		// derived from, and this branch is reached exactly when a tainted name was embedded in
		// something larger - a concatenation, an index, a member access
		if strings.TrimSpace(text) != name {
			candidate.normalized = false
		}
		if !mentionsTaintedVar(fullyMasked, name) {
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
// constantPerElement matches expressions that turn each element of a collection into the same
// literal - placeholders for a parameterized query: xs.map(() => "?"), xs.map((_) => '$1'),
// ["?"] * len(xs), "?" * len(xs), "?" for _ in xs. Their text names the collection, but what they
// produce does not depend on its contents.
var constantPerElement = regexp.MustCompile(`[A-Za-z_$][\w.$]*\s*\.map\(\s*\(?\s*\w*\s*(?:,\s*\w+\s*)?\)?\s*=>\s*(?:"[^"]*"|'[^']*'|` + "`[^`$]*`" + `)\s*\)|\[\s*(?:"[^"]*"|'[^']*')\s*\]\s*\*\s*len\(\s*[\w.]+\s*\)|(?:"[^"]*"|'[^']*')\s*\*\s*len\(\s*[\w.]+\s*\)|(?:"[^"]*"|'[^']*')\s+for\s+\w+\s+in\s+[\w.]+`)

func maskLiteralText(text string) string {
	text = constantPerElement.ReplaceAllString(text, `""`)
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

// sqlReceiverHint matches receiver names that hold a database handle
var sqlReceiverHint = regexp.MustCompile(`(?i)(^|[._])(cur|cursor|conn|connection|con|db|database|session|engine|tx|txn|transaction|stmt|statement|pool|client|sql|sqlite|pg|mysql|duck|duckdb|snowflake|bigquery|bq|kusto|spark|query|repo|dao|store)([0-9]*|_[a-z0-9_]*)$`)

// sqlKeywords matches SQL text in the checked argument
var sqlKeywords = regexp.MustCompile(`(?i)\b(select|insert|update|delete|create|drop|alter|merge|with|where|from)\b`)

// sqlReceiver reports whether a call matched only by method name - execute, query, Exec - is
// plausibly a SQL call: its receiver is named like a database handle, or its checked argument
// carries SQL text. A receiver this cannot judge (a bare call) keeps the match.
func sqlReceiver(sinkText, argText string) bool {
	i := strings.LastIndexByte(sinkText, '.')
	if i <= 0 {
		return true
	}
	recv := strings.TrimSpace(strings.TrimRight(sinkText[:i], "!?"))
	return sqlReceiverHint.MatchString(recv) || sqlKeywords.MatchString(argText)
}

// receiverLooksLikeDB reports whether a method call's receiver is named like a database handle,
// excluding the object's own methods (self, this, cls), which resolve to the right class
func receiverLooksLikeDB(sinkText string) bool {
	i := strings.LastIndexByte(sinkText, '.')
	if i <= 0 {
		return false
	}
	recv := strings.TrimSpace(strings.TrimRight(sinkText[:i], "!?"))
	switch recv {
	case "self", "this", "cls":
		return false
	}
	return strictDBReceiver.MatchString(recv)
}

// bindsName reports whether a bare call name refers to sym: a free function (not a method, which
// a bare name cannot call) that this file defines or imports from the project's own code. A
// FetchStandardFontDataFactory.fetch method beside a fetch(url) call, or `fetch` imported from
// node-fetch, leaves the global API in place.
func (c *ctx) bindsName(file string, sym *graph.Symbol, name string) bool {
	if sym.Kind != graph.KindFunction || sym.Receiver != "" {
		return false
	}
	if sym.File == file {
		return true
	}
	f := c.g.Files[file]
	if f == nil {
		return false
	}
	for _, im := range f.Imports {
		if im.Alias != name && !(im.Alias == "" && parser.LastSegment(im.Path) == name) {
			continue
		}
		if importNamesFile(im.Path, sym.File) {
			return true
		}
	}
	return false
}

// importNamesFile reports whether an import path written in the project points at file: a
// relative import (./http, .http.fetch) or a dotted module path the file's path contains
// (digikala_mcp.http.fetch for src/digikala_mcp/http.py)
func importNamesFile(path, file string) bool {
	if strings.HasPrefix(path, ".") {
		return true
	}
	module := path
	if i := strings.LastIndexAny(module, "./"); i > 0 {
		module = module[:i]
	}
	module = strings.ReplaceAll(module, ".", "/")
	return module != "" && strings.Contains(file, module)
}

// receiverMaybeDB is the broad receiver test: any name a database handle may have, including
// generic ones like client
func receiverMaybeDB(sinkText string) bool {
	i := strings.LastIndexByte(sinkText, '.')
	if i <= 0 {
		return false
	}
	recv := strings.TrimSpace(strings.TrimRight(sinkText[:i], "!?"))
	switch recv {
	case "self", "this", "cls":
		return false
	}
	return sqlReceiverHint.MatchString(recv)
}

// chainHasSQLText reports whether a path built a string with SQL text in it on the way
func chainHasSQLText(info taintInfo) bool {
	for _, st := range info.chain {
		if st.Detail == compositionDetail && sqlKeywords.MatchString(st.Symbol) {
			return true
		}
	}
	return false
}

// sqlExecReceiverName names the objects whose exec() runs SQL: a SQL storage handle, a database,
// a connection or cursor. Not session or container: a sandbox session or a container exec() runs
// a process.
var sqlExecReceiverName = regexp.MustCompile(`(?i)(^|[._])(sql|sqlite3?|db|database|conn|connection|cursor|pg|mysql|duckdb|tx|txn|transaction)([0-9]*|_[a-z0-9_]*)$|(?i)[a-z0-9](Db|DB|Sql|SQL)$`)

func sqlExecReceiver(sinkText string) bool {
	i := strings.LastIndexByte(sinkText, '.')
	if i <= 0 {
		return false
	}
	return sqlExecReceiverName.MatchString(strings.TrimSpace(strings.TrimRight(sinkText[:i], "!?")))
}

// asyncpgQuery are the query methods of asyncpg connections and pools, which share fetch's name
var asyncpgQuery = map[string]bool{"fetch": true, "fetchrow": true, "fetchval": true}

// strictDBReceiver names only unambiguous database handles. It gates the check that overrides an
// in-repo resolution, so generic names - client, query, store - that also name HTTP clients and
// search APIs stay out: kendra_client.query and an HttpClient's execute are not SQL.
var strictDBReceiver = regexp.MustCompile(`(?i)(^|[._])(cur|cursor|conn|connection|db|database|session|engine|tx|txn|transaction|pool|sqlite|pg|mysql|duckdb)([0-9]*|_[a-z0-9_]*)$`)

// isFunctionLiteralText reports whether an argument is written as a function literal in one of
// the supported languages: a Go func literal, a JavaScript function or arrow function, a Python
// lambda, or a Rust closure
func isFunctionLiteralText(text string) bool {
	t := strings.TrimSpace(text)
	t = strings.TrimPrefix(t, "async ")
	t = strings.TrimPrefix(t, "move ")
	switch {
	case strings.HasPrefix(t, "func(") || strings.HasPrefix(t, "func ("):
		return true
	case strings.HasPrefix(t, "function"), strings.HasPrefix(t, "lambda ") || strings.HasPrefix(t, "lambda:"):
		return true
	case strings.HasPrefix(t, "|"):
		return true
	}
	// An arrow function: a parameter list or a single identifier, then =>
	if i := strings.Index(t, "=>"); i > 0 {
		head := strings.TrimSpace(t[:i])
		if strings.HasPrefix(head, "(") && strings.HasSuffix(head, ")") || isPlainIdent(head) {
			return true
		}
	}
	return false
}

// sinkCallee is the part of callee text that names the function actually being called. String
// contents are blanked, and everything up to the last closing bracket is an earlier call or
// expression whose result is only the receiver: in `execSync(cmd).toString().trim` the call is
// trim, and in `expect(fs.rmSync).not.toHaveBeenCalled` it is toHaveBeenCalled. The inner call
// is its own call node and is matched there. A compiled `(0, child_process.exec)` indirection
// names the function inside its parentheses, after the last comma.
func sinkCallee(text string) string {
	masked := maskLiteralText(text)
	i := strings.LastIndexAny(masked, ")]")
	if i < 0 {
		return masked
	}
	if tail := masked[i+1:]; strings.TrimSpace(tail) != "" || masked[i] != ')' {
		return tail
	}
	trimmed := strings.TrimSpace(masked)
	if strings.HasPrefix(trimmed, "(") && strings.HasSuffix(trimmed, ")") {
		inner := trimmed[1 : len(trimmed)-1]
		if j := strings.LastIndexByte(inner, ','); j >= 0 && !strings.ContainsAny(inner[j+1:], "()[]") {
			return strings.TrimSpace(inner[j+1:])
		}
	}
	return ""
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

// mentionsTaintedVar reports whether text uses the variable name: like mentionsIdent, except that a
// plain name right after a "." is an attribute of something else - path in os.path.join, url in
// request.url - and not the variable. A dotted name (args.path) is matched as written.
func mentionsTaintedVar(text, name string) bool {
	if strings.Contains(name, ".") {
		return mentionsIdent(text, name)
	}
	for idx := strings.Index(text, name); idx != -1; {
		before := idx == 0 || !isIdentByte(text[idx-1]) && text[idx-1] != '.'
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

// taintedNames returns the keys of a taint map in sorted order. When two names tie, the first one
// seen supplies the path, so map order would otherwise pick the path at random.
func taintedNames(tainted map[string]taintInfo) []string {
	out := make([]string, 0, len(tainted))
	for k := range tainted {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// execOnOtherObject reports whether a JavaScript or TypeScript exec call has a receiver that no
// import of child_process (or a module re-exporting it) binds in this file: a.b.exec(...) where a
// is a local client. A bare exec(...) or child_process.exec(...) is not this case.
// javaExecOnOtherObject reports whether a Java exec call is on something other than a Runtime:
// a process starts through Runtime.getRuntime().exec(...) or a Runtime held in a variable, while
// jolokiaService.exec(mbean, op) is another API's exec. A bare exec(...) is left alone.
func javaExecOnOtherObject(calleeText string) bool {
	t := strings.Join(strings.Fields(calleeText), "")
	recv, ok := strings.CutSuffix(t, ".exec")
	if !ok || recv == "" {
		return false
	}
	r := strings.ToLower(recv)
	return !strings.Contains(r, "runtime") && r != "rt"
}

func (c *ctx) execOnOtherObject(file, sinkText string) bool {
	f := c.g.Files[file]
	if f == nil || (f.Language != string(language.TypeScript) && f.Language != string(language.JavaScript)) {
		return false
	}
	root, _, dotted := strings.Cut(strings.TrimSpace(sinkText), ".")
	if !dotted || root == "" {
		return false
	}
	for _, imp := range f.Imports {
		path := strings.TrimPrefix(imp.Path, "node:")
		if path != "child_process" && !strings.HasPrefix(path, "child_process/") && path != "execa" && path != "shelljs" {
			continue
		}
		local := imp.Alias
		if local == "" {
			local = parser.LastSegment(imp.Path)
		}
		if local == root || imp.Alias == "" {
			// a namespace or default import of child_process may bind the root; an import whose
			// binding is not recorded could too
			return false
		}
	}
	return root != "child_process" && root != "cp" && root != "childProcess"
}

// escaperName matches the names projects give their own quoting and escaping functions
var escaperName = regexp.MustCompile(`(?i)^_*\w*(quote|escape)\w*$`)

// callNames finds the callees an expression calls
var callNames = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*)\s*\(`)

// escapedBy reports whether an expression's value is escaped by a function the project names as a
// quoting or escaping one: called directly (shell_quote(x)), or called inside an in-repo function
// the expression calls, including as an iterator step - args.iter().map(quote_remote_arg). The
// escaping is not verified, so a finding through it goes to review rather than away.
func (c *ctx) escapedBy(text string) (string, bool) {
	for _, m := range callNames.FindAllStringSubmatch(text, 8) {
		name := parser.LastSegment(m[1])
		if isEscaper(name) {
			return name, true
		}
		ids := c.idx[name]
		if len(ids) != 1 {
			continue
		}
		if esc := c.bodyEscaper(c.g.Symbols[ids[0]]); esc != "" {
			return name + " (which applies " + esc + ")", true
		}
	}
	return "", false
}

// bodyEscaper returns the escaping function a symbol's body applies, or "", once per symbol
func (c *ctx) bodyEscaper(sym *graph.Symbol) string {
	if sym == nil {
		return ""
	}
	if v, ok := c.escapers[sym.ID]; ok {
		return v
	}
	out := ""
	if pf, node := c.defNodeFor(sym); pf != nil && node != nil {
		if body := node.Utf8Text(pf.src); len(body) <= 20000 {
			for _, e := range escaperUse.FindAllStringSubmatch(body, -1) {
				if esc := e[1] + e[2]; isEscaper(esc) && esc != sym.Name {
					out = esc
					break
				}
			}
		}
	}
	c.escapers[sym.ID] = out
	return out
}

// escaperUse finds an escaping function applied inside a body: .map(quote_arg), map(shlex_quote,
// ...), or a direct call
var escaperUse = regexp.MustCompile(`(?i)(?:\.map\(\s*|\bmap\(\s*)(_*\w*(?:quote|escape)\w*)\s*[,)]|\b(_*\w*(?:quote|escape)\w*)\s*\(`)

// isEscaper reports whether a name reads as escaping, not as its inverse (unescape, unquote) or as
// an unrelated word that contains it
func isEscaper(name string) bool {
	low := strings.ToLower(name)
	return escaperName.MatchString(name) && !strings.Contains(low, "unescape") && !strings.Contains(low, "unquote") && !strings.Contains(low, "dequote")
}

func escapedReview(why string) string {
	return "the value passes through " + why + ", a quoting or escaping function of the project; whether it escapes correctly for the program or query that receives the value decides between a real issue and noise, and the scanner does not verify it"
}

// conditionalBranches returns the two value branches of a conditional expression - Python's
// `a if cond else b`, the C-family `cond ? a : b` - and false for anything else
func conditionalBranches(n *sitter.Node) ([]*sitter.Node, bool) {
	if n == nil {
		return nil, false
	}
	for n.Kind() == "parenthesized_expression" && n.NamedChildCount() == 1 {
		n = n.NamedChild(0)
	}
	switch n.Kind() {
	case "conditional_expression":
		// Python: a if cond else b - named children in order a, cond, b
		if n.NamedChildCount() == 3 {
			return []*sitter.Node{n.NamedChild(0), n.NamedChild(2)}, true
		}
	case "ternary_expression":
		c, a := n.ChildByFieldName("consequence"), n.ChildByFieldName("alternative")
		if c != nil && a != nil {
			return []*sitter.Node{c, a}, true
		}
	}
	return nil, false
}

func fromMCPInputName(tainted map[string]taintInfo, name string) bool {
	info, ok := tainted[name]
	return ok && fromMCPInput(info)
}

// holdsFixedHostURL reports whether name's latest plain assignment before n, in the enclosing
// function, is a literal URL whose host is closed ("https://host/..."), directly or through one
// variable assigned such a literal in the same file
func (c *ctx) holdsFixedHostURL(pf *parsedFile, n *sitter.Node, name string) bool {
	if !isPlainIdent(name) {
		return false
	}
	fn := n.Parent()
	for fn != nil && !strings.Contains(fn.Kind(), "function") && !strings.Contains(fn.Kind(), "method") && fn.Kind() != "arrow_function" {
		fn = fn.Parent()
	}
	start := uint(0)
	if fn != nil {
		start = fn.StartByte()
	}
	before := string(pf.src[start:n.StartByte()])
	rhs := lastPlainAssignment(before, name)
	if rhs == "" {
		return false
	}
	if v, ok := parser.UnquoteString(rhs); ok {
		return fixesURLHost(v)
	}
	if isPlainIdent(rhs) {
		if v, ok := parser.UnquoteString(lastPlainAssignment(string(pf.src[:n.StartByte()]), rhs)); ok {
			return fixesURLHost(v)
		}
	}
	return false
}

// mcpGoGetter names the argument getters of mcp-go's CallToolRequest: RequireString, GetInt,
// GetStringSlice, GetArguments and the like
var mcpGoGetter = regexp.MustCompile(`^(Require|Get)(String|Int|Float|Bool|StringSlice|IntSlice|FloatSlice|BoolSlice|Arguments|RawArguments)$`)

// mcpGoArgumentGetter reports whether a method call is one of mcp-go's request argument getters,
// in a file that imports mcp-go. They return what the client sent for the named argument.
func (c *ctx) mcpGoArgumentGetter(file, calleeText string) bool {
	if !strings.Contains(calleeText, ".") || !mcpGoGetter.MatchString(parser.LastSegment(calleeText)) {
		return false
	}
	f := c.g.Files[file]
	if f == nil {
		return false
	}
	for _, imp := range f.Imports {
		if strings.HasPrefix(imp.Path, "github.com/mark3labs/mcp-go/") {
			return true
		}
	}
	return false
}

// lastPlainAssignment returns the right-hand side of the last `name = value` (not +=) in text
func lastPlainAssignment(text, name string) string {
	re := regexp.MustCompile(`(?m)^[ \t]*(?:let|const|var|final)?\s*` + regexp.QuoteMeta(name) + `\s*(?::[^=\n]+)?=\s*([^=\n].*?)\s*;?\s*$`)
	ms := re.FindAllStringSubmatch(text, -1)
	if len(ms) == 0 {
		return ""
	}
	return strings.TrimSpace(ms[len(ms)-1][1])
}

// fetchOnOtherObject reports whether a JavaScript or TypeScript call is a fetch method on some object
// other than the global one: imap.fetch(...), not fetch(...) or globalThis.fetch(...)
func fetchOnOtherObject(lang language.ID, sinkText string) bool {
	if lang != language.TypeScript && lang != language.JavaScript {
		return false
	}
	t := strings.TrimSpace(sinkText)
	root, rest, dotted := strings.Cut(t, ".")
	if !dotted || parser.LastSegment(t) != "fetch" {
		return false
	}
	switch root {
	case "window", "globalThis", "self", "global":
		return rest != "fetch"
	}
	return true
}

// helperRelativePath reports whether a URL expression starts with a call to an in-repo function
// whose returned value is itself a relative path: `${repoPath(project, repo)}/pull-requests` with
// repoPath = (p, r) => `/projects/${encodeURIComponent(p)}/repos/...`. The helper's literal "/word"
// opens the path, so the caller's values that follow cannot name another host.
func (c *ctx) helperRelativePath(pf *parsedFile, n *sitter.Node) bool {
	if n == nil {
		return false
	}
	n = unwrapAwait(n)
	var call *sitter.Node
	switch n.Kind() {
	case "template_string":
		for i := range n.ChildCount() {
			ch := n.Child(i)
			if ch.Kind() == "`" {
				continue
			}
			if ch.Kind() == "template_substitution" && ch.NamedChildCount() == 1 {
				call = ch.NamedChild(0)
			}
			break
		}
	case "binary_expression", "binary_operator":
		inner := n
		for {
			l := inner.ChildByFieldName("left")
			if l == nil || (l.Kind() != "binary_expression" && l.Kind() != "binary_operator") {
				break
			}
			inner = l
		}
		call = inner.ChildByFieldName("left")
	case "call_expression", "call":
		call = n
	}
	if call == nil || (call.Kind() != "call_expression" && call.Kind() != "call") {
		return false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	ids := c.idx[parser.LastSegment(fn.Utf8Text(pf.src))]
	if len(ids) != 1 {
		return false
	}
	hpf, def := c.defNodeFor(c.g.Symbols[ids[0]])
	if hpf == nil || def == nil {
		return false
	}
	ret := returnedExpression(def)
	return ret != nil && relativePathURL(hpf, ret)
}

// returnedExpression is what a function returns when that is one expression: an arrow function's
// expression body, or the value of the only return statement in a block body
func returnedExpression(def *sitter.Node) *sitter.Node {
	body := def.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	if body.Kind() != "statement_block" && body.Kind() != "block" {
		return body
	}
	var ret *sitter.Node
	count := 0
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		for i := range n.NamedChildCount() {
			ch := n.NamedChild(i)
			switch ch.Kind() {
			case "return_statement":
				count++
				if ch.NamedChildCount() > 0 {
					ret = ch.NamedChild(0)
				}
			case "function_declaration", "arrow_function", "function_expression", "function_definition", "method_definition":
				// returns of a nested function are not this one's
			default:
				walk(ch)
			}
		}
	}
	walk(body)
	if count != 1 {
		return nil
	}
	return ret
}

// httpLikeReceiver reports whether a .Get call's receiver reads as an HTTP client: http.Get,
// client.Get, httpClient.Get, resty's R().Get. A call chain or another name does not.
func httpLikeReceiver(sinkText string) bool {
	t := strings.TrimSpace(sinkText)
	recv := strings.TrimSuffix(t, ".Get")
	if recv == t {
		return true
	}
	low := strings.ToLower(recv)
	return httpReceiverName.MatchString(low) || strings.HasSuffix(low, ".r()")
}

var httpReceiverName = regexp.MustCompile(`(^|[._])(http|https|client|httpclient|resty|req|request|requests|session|api|rest|web)\w*$`)

// annotationValidator matches a Pydantic validator attached to a parameter's type annotation:
// Annotated[str, BeforeValidator(validate_path)], AfterValidator(check_url), PlainValidator(fn)
var annotationValidator = regexp.MustCompile(`\b(?:Before|After|Plain|Wrap)Validator\(\s*([A-Za-z_][\w.]*)`)

// annotationValidators maps each Python handler parameter to the validator its annotation attaches
func (c *ctx) annotationValidators(sym *graph.Symbol) map[string]string {
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil || pf.adapter.ID != language.Python {
		return nil
	}
	list := parser.ParamList(node)
	if list == nil {
		return nil
	}
	out := map[string]string{}
	cursor := list.Walk()
	defer cursor.Close()
	for _, param := range list.NamedChildren(cursor) {
		text := param.Utf8Text(pf.src)
		m := annotationValidator.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		for _, b := range parser.ParamBindings(pf.adapter.ID, &param, pf.src) {
			out[b] = parser.LastSegment(m[1])
		}
	}
	return out
}

// goScalarTypes are the Go types that hold a number or a bool and nothing else
var goScalarTypes = map[string]bool{
	"bool": true, "int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
	"float32": true, "float64": true, "byte": true, "rune": true, "time.Duration": true,
}

// goScalarParams lists a Go function's parameters declared with a number or bool type. The
// compiler enforces Go's types, so a value reaching such a parameter cannot be text. Other
// languages' annotations are not enforced at run time and are not read here.
func (c *ctx) goScalarParams(sym *graph.Symbol) map[string]bool {
	if sym == nil || c.g.Files[sym.File] == nil || c.g.Files[sym.File].Language != string(language.Go) {
		return nil
	}
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil {
		return nil
	}
	list := node.ChildByFieldName("parameters")
	if list == nil {
		return nil
	}
	var out map[string]bool
	for i := range list.NamedChildCount() {
		p := list.NamedChild(i)
		if p == nil || p.Kind() != "parameter_declaration" {
			continue
		}
		typ := p.ChildByFieldName("type")
		if typ == nil || !goScalarTypes[typ.Utf8Text(pf.src)] {
			continue
		}
		for j := range p.NamedChildCount() {
			if n := p.NamedChild(j); n != nil && n.Kind() == "identifier" {
				if out == nil {
					out = map[string]bool{}
				}
				out[n.Utf8Text(pf.src)] = true
			}
		}
	}
	return out
}

// scalarType reports whether a Python annotation is a number, a bool or a Literal, alone or wrapped
// in Optional[...], Annotated[..., ...] or a union with None: int, Optional[int], int | None,
// Annotated[int, Field(ge=1)], Literal["fast", "slow"]
func scalarType(t string) bool {
	t = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "typing."))
	if parts := parser.SplitTopLevelSep(t, '|'); len(parts) > 1 {
		seen := false
		for _, p := range parts {
			if strings.TrimSpace(p) == "None" {
				continue
			}
			if !scalarType(p) {
				return false
			}
			seen = true
		}
		return seen
	}
	switch t {
	case "int", "float", "bool":
		return true
	}
	if strings.HasPrefix(t, "Literal[") && strings.HasSuffix(t, "]") {
		return true
	}
	for _, w := range []string{"Optional[", "Annotated["} {
		if strings.HasPrefix(t, w) && strings.HasSuffix(t, "]") {
			args := parser.SplitTopLevel(t[len(w) : len(t)-1])
			return len(args) > 0 && scalarType(args[0])
		}
	}
	return false
}

// scalarAnnotatedParams lists a Python handler's parameters whose annotation is a scalar type the
// SDK validates the argument against before the handler runs
func (c *ctx) scalarAnnotatedParams(sym *graph.Symbol) map[string]bool {
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil || pf.adapter.ID != language.Python {
		return nil
	}
	list := parser.ParamList(node)
	if list == nil {
		return nil
	}
	out := map[string]bool{}
	cursor := list.Walk()
	defer cursor.Close()
	for _, param := range list.NamedChildren(cursor) {
		typ := param.ChildByFieldName("type")
		if typ == nil || !scalarType(strings.Join(strings.Fields(typ.Utf8Text(pf.src)), " ")) {
			continue
		}
		for _, b := range parser.ParamBindings(pf.adapter.ID, &param, pf.src) {
			out[b] = true
		}
	}
	return out
}

// sqlFieldKey matches an object-literal key a database driver reads the statement from:
// mysql2 query({ sql, values }), pg query({ text, values }), { query: ... }, { statement: ... }
var sqlFieldKey = regexp.MustCompile(`(?i)(^|[{,\s])["']?(sql|text|query|statement|stmt)["']?\s*[:,}]`)

// commandObjectArg reports whether a sink argument is an object or dict literal with no key a
// driver reads SQL from
func commandObjectArg(text string) bool {
	t := strings.TrimSpace(text)
	if len(t) < 2 || t[0] != '{' || t[len(t)-1] != '}' {
		return false
	}
	return !sqlFieldKey.MatchString(t)
}

// keywordOnlyNonSQL reports whether every argument of a Python call is a keyword one and none of
// them names a statement (sql, query, statement, operation, stmt, text)
func keywordOnlyNonSQL(args []graph.Arg) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		if a.Keyword == "" {
			return false
		}
		switch strings.ToLower(a.Keyword) {
		case "sql", "query", "statement", "operation", "stmt", "text", "command":
			return false
		}
	}
	return true
}
