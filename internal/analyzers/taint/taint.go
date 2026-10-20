// Package taint traces MCP-reachable values to dangerous sinks across files.
// It tracks names within functions and seeds resolved callees. Unresolved calls
// remain in the path at reduced confidence.
package taint

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func init() { analyzer.Register(&Analyzer{}) }

// Analyzer traces tool/prompt/resource handler arguments, environment
// variables, file contents and HTTP response bodies to the sinks listed in
// catalog.go
type Analyzer struct{}

func (*Analyzer) Name() string { return "taint" }

func (*Analyzer) AppliesTo(kind model.TargetKind) bool {
	return kind == model.TargetSource || kind == model.TargetPackage
}

func (*Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	started := time.Now().UTC()
	var acRoot string
	if ac != nil {
		acRoot = ac.Root
	}
	root, err := source.ResolveRoot(target.Path, acRoot)
	if err != nil {
		return model.Errorf("taint", "config", "%v", err)
	}
	if root == "" {
		return model.Errorf("taint", "config", "no source path to scan")
	}

	g, baseCov, walkCoverageMissing, err := source.LoadGraph(ctx, ac, root)
	if err != nil {
		return model.Errorf("taint", "internal", "building source graph: %v", err)
	}
	// baseCov's capability counts are source.Build's own ("every discovered
	// one was inspected for name/handler") - taintCoverage below computes
	// taint's own, stricter count (whether a handler was actually seeded),
	// so baseCov contributes file-level fields only, not these
	baseCov.CapabilitiesDiscovered, baseCov.CapabilitiesAnalyzed, baseCov.CapabilitiesSkipped = 0, 0, 0

	tc := newCtx(ctx, g)
	defer tc.closeAll()

	// Seed every handler from its own capability, even if another trace already reached it. That
	// trace carried different arguments; the (symbol, seed) guard still prevents duplicate work.
	for _, sym := range g.Symbols {
		if ctx.Err() != nil {
			break
		}
		if seed := tc.seedFor(sym); seed != nil {
			tc.analyzeSymbol(sym, seed, 0)
		}
	}
	// Everything else: a plain function can still introduce taint on its
	// own (an environment variable, a file, an HTTP response) and reach a
	// sink entirely within itself, with no handler involved
	for _, sym := range g.Symbols {
		if ctx.Err() != nil {
			break
		}
		if tc.visitedSyms[sym.ID] {
			continue
		}
		tc.analyzeSymbol(sym, nil, 0)
	}

	model.SortFindings(tc.findings)

	var warnings []string
	status := model.AnalyzerCompleted
	if ctx.Err() != nil {
		status = model.AnalyzerPartial
	}
	if walkCoverageMissing {
		// The graph came from ac.Artifacts but nobody published the walk's
		// own Coverage next to it (source.WalkCoverageKey) - taint has no
		// file-level coverage to report and would otherwise claim complete
		// coverage over a tree it never walked itself. See loadGraph.
		status = model.AnalyzerPartial
		warnings = append(warnings, "the published source graph carried no walk coverage; file-level coverage cannot be reported for this scan")
	}

	cov := baseCov
	cov.Add(taintCoverage(g, tc))
	var arts *analyzer.Artifacts
	if ac != nil {
		arts = ac.Artifacts
	}
	cov = source.FoldWalkCoverage(arts, cov)

	res := model.AnalyzerResult{
		Analyzer:  "taint",
		Status:    status,
		Required:  true,
		Coverage:  cov,
		Findings:  tc.findings,
		Warnings:  warnings,
		StartedAt: started,
	}
	res.FinishedAt = time.Now().UTC()
	res.Duration = res.FinishedAt.Sub(started)
	return res
}

// emit records one finding. note, when set, is a specific explanation for
// this particular verdict (why an argv-style call was or was not treated
// as a shell command) and is prepended to the traced-path description
// rather than replacing it
func (c *ctx) emit(category string, severity model.Severity, calleeText string, info taintInfo, file string, line int, note string) {
	desc := describePath(info.chain)
	if note != "" {
		desc = note + ". Path: " + desc
	} else {
		desc = "traced path: " + desc
	}
	c.findings = append(c.findings, model.Finding{
		RuleID:        "taint." + category,
		Category:      category,
		Title:         fmt.Sprintf("tainted data reaches %s (%s)", calleeText, category),
		Severity:      severity,
		Confidence:    max(0, min(info.confidence, 1)),
		EvidenceLevel: model.EvidenceDataflow,
		File:          file,
		Line:          line,
		Description:   desc,
		Evidence: []model.Evidence{{
			Level:       model.EvidenceDataflow,
			Kind:        "taint_path",
			Description: desc,
			File:        file,
			Line:        line,
			Path:        info.chain,
		}},
	})
}

func describePath(chain []model.FlowStep) string {
	parts := make([]string, len(chain))
	for i, s := range chain {
		d := s.Detail
		if d == "" {
			d = s.Symbol
		}
		parts[i] = d
	}
	return strings.Join(parts, " -> ")
}

// taintCoverage reports how many of the discovered capabilities taint
// actually managed to trace from their handler. One whose handler name
// never resolved, or whose body could not be located, stays unaccounted -
// neither analyzed nor skipped - with a reason recorded, because taint did
// not analyze it and a skip would claim otherwise.
func taintCoverage(g *graph.Graph, tc *ctx) model.Coverage {
	cov := model.Coverage{CapabilitiesDiscovered: len(g.Capabilities)}
	if tc.seedCapHit {
		cov.LimitsHit = append(cov.LimitsHit, fmt.Sprintf(
			"a helper shared by many callers exceeded the taint analyzer's per-symbol seed limit (%d distinct tainted-argument combinations); later combinations were not traced",
			maxSeedsPerSymbol))
	}
	if tc.depthCapHit {
		cov.LimitsHit = append(cov.LimitsHit, fmt.Sprintf(
			"a tainted flow exceeded %d nested helper calls and was not traced further",
			maxDepth))
	}
	// tc.sizeCapped/parseTimedOut are taint's own count of files it reopened and re-parsed for
	// its own walk - not a copy of the source walk's count of every oversized or slow file in
	// the tree, most of which taint may never touch
	if tc.ambiguousCalls > 0 {
		cov.LimitsHit = append(cov.LimitsHit, fmt.Sprintf(
			"%d call(s) carrying tainted input named more than one definition in this tree and could not be followed into any of them",
			tc.ambiguousCalls))
	}
	if tc.sizeCapped > 0 {
		cov.LimitsHit = append(cov.LimitsHit, fmt.Sprintf(
			"%d file(s) reached by the taint walk exceeded the %d byte size limit and were read and parsed only up to it",
			tc.sizeCapped, tc.sizeCap))
	}
	if tc.parseTimedOut > 0 {
		cov.LimitsHit = append(cov.LimitsHit, fmt.Sprintf(
			"%d file(s) reached by the taint walk exceeded its own %s per-file parse deadline and were not traced",
			tc.parseTimedOut, parser.ParseTimeout))
	}
	// A file the walk reached and could not reopen, could not get a parser for, or could not
	// parse
	if tc.unreadable > 0 {
		cov.LimitsHit = append(cov.LimitsHit, fmt.Sprintf(
			"%d file(s) reached by the taint walk could not be re-read or re-parsed and were not traced",
			tc.unreadable))
	}
	// None of these three branches touches CapabilitiesSkipped: each one is taint saying it
	// could not trace the capability at all, which leaves it unaccounted so Coverage.Gaps()
	// reports it and the scan downgrades. A skip would balance the arithmetic and let one
	// untraceable handler alongside one ordinary one report full coverage.
	for _, c := range g.Capabilities {
		switch {
		case c.Handler == "":
			cov.AddSkipReason("capability handler is not statically known")
		case !tc.visitedSyms[c.Handler]:
			cov.AddSkipReason("handler body could not be located or parsed")
		case !tc.seeded[c.Handler]:
			cov.AddSkipReason("handler parameters could not be resolved to taint sources")
		default:
			cov.CapabilitiesAnalyzed++
		}
	}
	return cov
}

func (*Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name:    "taint",
		Purpose: "Traces MCP-reachable input (tool/prompt/resource arguments, environment variables, files, HTTP responses) to dangerous sinks across the call graph, including across files.",
		Threats: []string{
			"command injection", "path traversal", "SSRF", "SQL injection",
			"eval / dynamic code loading", "insecure deserialization", "server-side template injection",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceDataflow},
		Active:   false,
		Limitations: []string{
			"a capability whose handler cannot be resolved to a symbol - a bound method, a handler chosen at runtime, a value assembled from a table - is not traced at all; it is reported as an unanalyzed capability, which downgrades the scan rather than passing",
			"propagation matches a tainted identifier by name in an expression's source text, not by walking its AST; a same-named variable shadowed in a nested scope is not distinguished",
			"no path-sensitivity: a variable tainted in one branch is treated as tainted after the branch, whichever way it went, and an assignment inside an if, a try, a switch arm or a loop body may add taint but never remove or weaken what is already known - so a default-value guard or a sanitizer that runs on only one branch leaves the flow reported",
			"a sanitizer is recognized by name against a fixed catalogue; a project's own hand-rolled validation function is invisible unless its own body is itself traced",
			fmt.Sprintf("interprocedural tracing uses the call graph's name-based resolution; ambiguous names and flows beyond %d nested helper calls stop the trace and appear in limits_hit, while cycles stop without a gap", maxDepth),
			fmt.Sprintf("a helper shared by more than %d distinct tainted-argument combinations across its callers has the rest left untraced, recorded in the result's limits_hit rather than silently dropped", maxSeedsPerSymbol),
			"a guard clause that tests containment of a normalized path and then returns, raises or throws clears path_traversal for that variable; a guard with an else branch, one whose exit is a continue or break, and one performed inside a helper function are all unrecognized and leave the flow reported",
			"a character-wise prefix check (JavaScript/TypeScript's startsWith, Go's strings.HasPrefix) only counts as containment when the value it compares against ends at a path separator; is_relative_to, Java's Path#startsWith and Rust's Path::starts_with are instead trusted to be anchored by predicate name and language alone, so a path already converted to a plain string before the comparison defeats that trust",
			"a containment guard is only honoured when its predicate decides the exit on its own: a condition joining it to anything other than a disequality on the same path - a feature flag, a trust level, a call - is treated as no guard at all and the flow stays reported",
			"a category cleared by a sanitizer or a containment guard stays cleared through every later transformation, except the decoders that can turn escaped text back into path syntax (decodeURIComponent, unquote, QueryUnescape and their kin), which drop it; a decoder matched only by a generic name, such as Java's URLDecoder.decode, is not among them",
			"a sink matched by method name is missed when an unrelated function of the same name is defined elsewhere in the repository, because the call resolves to that function instead; only the case where the shadowing function is the one containing the call is recognized",
			"a sink reached through a name is recognized only for the forms the alias table covers: a bare rebinding, a from-import, a renaming import, a CommonJS destructuring rename, a module alias, promisify, and a sink handed to asyncio.to_thread, run_in_executor or functools.partial",
			"a sink stored in a structure, chosen at runtime, or reached through an alias bound in another file is not a sink here",
			"a value read out of a collection by a tainted key is treated as untainted, on the reasoning that the values are the author's and only the choice among them is the caller's; a collection whose contents are themselves attacker-controlled is caught only when the collection's own name carries taint",
			"the callback-style sqlite3 API (db.all/get/run/each) is not matched as a SQL sink, because those method names are indistinguishable from ordinary collection, cache and router methods; the pg, mysql2 and better-sqlite3 entry points (query, execute, prepare) are matched",
			"a guard comparing against a bare separator literal (\"/\") constrains nothing and is not read as containment, but only a literal is examined: a root that reaches \"/\" through a constant or a computed value is taken at face value",
			"a value appended to a collection taints the collection only when the receiver is a plain local name: cmd.append(v) and args.push(v) are followed, self.items.append(v) and registry[key].push(v) are not, so a command assembled through a field or a nested element is not traced",
			"an argv array handed to a child process as a variable rather than written out at the call site cannot be read element by element; it is checked as one argument, so the position of the tainted value is unknown - which means a terminator or an option boundary inside such an array does not clear the flow, and a shell given an unreadable argv is reported as command injection rather than the weaker category",
		},
	}
}
