// Package source builds a repository graph and discovers MCP registrations.
// Build walks, parses, resolves symbols, and finds MCP registrations. It is the independent
// entry point for every graph-consuming analyzer, so none depends on analyzer execution order.
package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/internal/source/inventory"
	"github.com/revinand/mcp-scanner/internal/source/language"
	"github.com/revinand/mcp-scanner/internal/source/parser"
	"github.com/revinand/mcp-scanner/internal/source/registration"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// ArtifactKey is where the built graph is published on ac.Artifacts
const ArtifactKey = "source.graph"

// WalkCoverageKey stores coverage from the walk that produced ArtifactKey. Consumers that reuse
// the graph must also reuse its blind spots instead of claiming a fresh, complete walk.
const WalkCoverageKey = "source.walk_coverage"

// Publish shares a built graph and the coverage of the walk that produced it.
//
// The two go together: a consumer that reuses the graph has to reuse its blind
// spots too, or it reports a complete walk it never performed. Coverage is
// stored first on purpose. Artifacts is mutex-guarded, so a consumer that sees
// the graph is guaranteed to see the coverage stored before it - publishing
// them the other way round leaves a window where the graph looks like the
// product of a walk that found nothing.
func Publish(a *analyzer.Artifacts, g *graph.Graph, cov model.Coverage) {
	if a == nil || g == nil {
		return
	}
	a.Set(WalkCoverageKey, cov)
	a.Set(ArtifactKey, g)
}

// FoldWalkCoverage merges file counters, skips, and limits into a graph
// consumer's coverage without overwriting analyzer-specific symbol or
// capability counts. Missing shared coverage leaves cov unchanged, which lets callers report
// that absence according to the target type rather than fabricating counters.
func FoldWalkCoverage(a *analyzer.Artifacts, cov model.Coverage) model.Coverage {
	wcov, ok := analyzer.Get[model.Coverage](a, WalkCoverageKey)
	if !ok {
		return cov
	}
	cov.FilesDiscovered = max(cov.FilesDiscovered, wcov.FilesDiscovered)
	cov.FilesParsed = max(cov.FilesParsed, wcov.FilesParsed)
	cov.FilesFailed = max(cov.FilesFailed, wcov.FilesFailed)
	cov.FilesSkipped = max(cov.FilesSkipped, wcov.FilesSkipped)
	for _, r := range wcov.SkipReasons {
		if !slices.Contains(cov.SkipReasons, r) {
			cov.SkipReasons = append(cov.SkipReasons, r)
		}
	}
	for _, l := range wcov.LimitsHit {
		if !slices.Contains(cov.LimitsHit, l) {
			cov.LimitsHit = append(cov.LimitsHit, l)
		}
	}
	return cov
}

// Build walks root, parses every file discovered, resolves the call graph
// and discovers MCP registrations. It always returns a graph, even an empty
// one, because the caller still needs the coverage counters to report a
// gap honestly rather than silently.
func Build(ctx context.Context, root string) (*graph.Graph, model.Coverage, error) {
	g := graph.New(root)

	inv, err := inventory.Walk(ctx, root, inventory.DefaultLimits())
	if err != nil {
		return g, model.Coverage{}, err
	}
	cov := inv.Coverage

	var timedOut, syntaxErrs int
	for i, f := range inv.Files {
		if ctx.Err() != nil {
			// The scanner deadline leaves files unread, so record a limit rather than explaining
			// them away as skipped
			cov.LimitsHit = append(cov.LimitsHit, fmt.Sprintf(
				"scan deadline reached during parsing; %d discovered file(s) were not read", len(inv.Files)-i))
			break
		}

		adapter := language.ByID(f.Lang)
		src, err := readFile(f.Abs, f.MaxBytes)
		if err != nil {
			cov.FilesFailed++
			continue
		}
		res, err := parser.ParseFile(ctx, adapter, f.Path, src)
		if err != nil {
			// A cancelled or timed-out parse is counted here exactly like any
			// other parse failure - never as a silent skip - so a file whose
			// shape drives the grammar quadratic still shows up as a gap
			// instead of a clean scan over code nobody actually read
			cov.FilesFailed++
			if errors.Is(err, parser.ErrParseTimeout) {
				timedOut++
			}
			continue
		}

		cov.FilesParsed++
		if res.HasSyntaxErrors {
			syntaxErrs++
		}
		cov.SymbolsDiscovered += len(res.Symbols)
		for _, s := range res.Symbols {
			if s.Kind == graph.KindFunction || s.Kind == graph.KindMethod {
				cov.FunctionsDiscovered++
			}
			g.Symbols[s.ID] = s
		}
		g.Files[f.Path] = &graph.File{Path: f.Path, Language: string(f.Lang), Imports: res.Imports, MaxBytes: f.MaxBytes}
		g.Calls = append(g.Calls, res.Calls...)
	}
	if timedOut > 0 {
		cov.LimitsHit = append(cov.LimitsHit, fmt.Sprintf(
			"%d file(s) exceeded the %s per-file parse deadline and were aborted", timedOut, parser.ParseTimeout))
	}
	if syntaxErrs > 0 {
		// FilesParsed already counts these - the grammar produced a tree, and everything outside
		// the broken region was extracted normally - but a region tree-sitter could not parse
		// yields no symbols and no calls, so a capability, a sink or a sanitizer sitting in that
		// region is invisible to source, taint and behavioral alike
		cov.LimitsHit = append(cov.LimitsHit, fmt.Sprintf(
			"%d file(s) only partly parsed; the grammar could not read part of each, and that part was not analyzed", syntaxErrs))
	}

	parser.Resolve(g)
	registration.Discover(g)
	cov.CapabilitiesDiscovered = len(g.Capabilities)
	cov.CapabilitiesAnalyzed = len(g.Capabilities) // every discovered one was inspected for name/handler
	if len(g.Capabilities) == 0 {
		// Coverage.Gaps() only flags a capability count when CapabilitiesDiscovered is positive, so
		// zero alone would look like a clean scan of a tree that isn't an MCP server at all
		cov.LimitsHit = append(cov.LimitsHit, noRegistrationReason(g))
	}

	return g, cov, nil
}

// importsKnownMCPSDK reports whether any parsed file imports a module this build recognizes
// as an MCP SDK
func importsKnownMCPSDK(g *graph.Graph) bool {
	for _, f := range g.Files {
		if registration.FileImportsMCPSDK(f) {
			return true
		}
	}
	return false
}

// noRegistrationReason explains a tree with zero resolved capabilities.
// graph.File.Imports already tells the difference between "nothing here
// looks like an MCP server" and "this looks like one this build cannot
// read" without changing whether the gap fires - see the LimitsHit entry
// in Build
func noRegistrationReason(g *graph.Graph) string {
	if importsKnownMCPSDK(g) {
		return "an MCP SDK import was found but no tool, prompt or resource registration was resolved: " +
			"this build does not recognize the registration form used here"
	}
	return "no MCP tool, prompt or resource registration was resolved in this tree: " +
		"either the server registers them in a form this build does not recognize, or there is no MCP server here"
}

// readFile reads a whole file, or - when maxBytes is set, meaning inventory found it over
// the size limit - only its first maxBytes. Parsing the prefix retains useful findings while
// inventory records the unread suffix as a coverage gap.
func readFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return os.ReadFile(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}
