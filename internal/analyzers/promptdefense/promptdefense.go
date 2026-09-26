// Package promptdefense detects prompt injection, hidden content and tool
// poisoning in the text an MCP server hands to an LLM: tool and prompt
// descriptions, resource content and server instructions. It works entirely
// off the discovered snapshot, so it applies the same way to remote, stdio
// and static targets.
package promptdefense

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/mcp/snapshot"
	"github.com/revinand/mcp-scanner/internal/source"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

const analyzerName = "promptdefense"

// Interface satisfaction is otherwise only checked by a runtime type
// assertion (Applicable, Describer are both optional), so a signature typo
// here would silently drop the method instead of failing to build
var (
	_ analyzer.Analyzer   = (*Analyzer)(nil)
	_ analyzer.Applicable = (*Analyzer)(nil)
	_ analyzer.Describer  = (*Analyzer)(nil)
)

func init() {
	analyzer.Register(New())
}

// Analyzer flags prompt injection, hidden content and tool poisoning
// declared in an MCP server's own text
type Analyzer struct{}

// New builds the analyzer. Rules are loaded lazily on first use and cached
// per resolved directory, since the registry keeps one instance for the
// life of the process.
func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return analyzerName }

// AppliesTo is every target kind: the analyzer only reads the snapshot,
// never the network or filesystem of the target itself
func (a *Analyzer) AppliesTo(model.TargetKind) bool { return true }

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	rules, rulesDir, err := resolveRules(ac)
	if err != nil {
		return model.Errorf(analyzerName, "config", "load rules: %v", err)
	}

	if ac == nil || ac.Snapshot == nil {
		return model.Skipped(analyzerName, "no MCP snapshot available for this target")
	}

	units, discovered, analyzed, skipped, skipReasons, limitsHit := extract(ac.Snapshot, target.Kind)
	analyzed, skipped, skipReasons = foldSynthesisCoverage(ac.Artifacts, analyzed, skipped, skipReasons)

	status := model.AnalyzerCompleted
	var findings []model.Finding
	var warnings []string
	// Which rules ran is a fact about the scan's coverage. A reader
	// comparing two reports needs to know that one of them was judged by a
	// rule set that is not the shipped one.
	if rulesDir != "" {
		warnings = append(warnings, fmt.Sprintf(
			"prompt-defense rules merged from %s over the embedded set (%d rules in total)",
			rulesDir, len(rules)))
	}

	for _, r := range rules {
		if ctx.Err() != nil {
			status = model.AnalyzerPartial
			warnings = append(warnings, "context cancelled before every rule ran; results are partial")
			break
		}
		findings = append(findings, r.evaluate(units)...)
	}
	findings = dropSyntheticDuplicates(findings)

	cov := model.Coverage{
		CapabilitiesDiscovered: discovered,
		CapabilitiesAnalyzed:   analyzed,
		CapabilitiesSkipped:    skipped,
		SkipReasons:            skipReasons,
		LimitsHit:              limitsHit,
	}
	// extract only ever counts capabilities that reached the snapshot;
	// discovery's own pagination can stop short of the server's full list
	// without extract ever seeing the gap. Folding in what the snapshot
	// itself knows about its truncation is what surfaces that here too,
	// the way protocol's capabilityCoverage always has.
	cov = snapshot.FoldCapabilityCoverage(ac.Snapshot, cov)
	// A source or package target is built by walking a file tree; a tool registered in a
	// directory the walk excluded, or a file it could not read, never becomes a capability in
	// the snapshot and so does not exist as far as extract above is concerned
	if target.Kind == model.TargetSource || target.Kind == model.TargetPackage {
		cov = source.FoldWalkCoverage(ac.Artifacts, cov)
	}

	return model.AnalyzerResult{
		Analyzer: analyzerName,
		Status:   status,
		Findings: findings,
		Warnings: warnings,
		Coverage: cov,
	}
}

// dropSyntheticDuplicates keeps the first rule/location finding. expandUnits orders declared
// text before decoded or normalized synthetic units, so an original-text finding wins over its
// derived duplicate.
func dropSyntheticDuplicates(findings []model.Finding) []model.Finding {
	type key struct{ rule, where string }
	seen := make(map[key]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		where := f.File
		for _, suffix := range syntheticFieldSuffixes {
			where = strings.TrimSuffix(where, suffix)
		}
		k := key{f.RuleID, where}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// foldSynthesisCoverage merges internal/source's per-capability resolution accounting into
// what extract derived from field emptiness alone. On a source target, a description that
// exists but couldn't be resolved statically looks identical to extract as one that
// genuinely declares none, since the name synthesis falls back to is never empty.
func foldSynthesisCoverage(artifacts *analyzer.Artifacts, analyzed, skipped int, reasons []string) (int, int, []string) {
	cov, ok := analyzer.Get[model.Coverage](artifacts, source.SynthesizeCoverageKey)
	if !ok || cov.CapabilitiesSkipped == 0 {
		return analyzed, skipped, reasons
	}
	move := min(cov.CapabilitiesSkipped, analyzed)
	// Leave unresolved declarations unaccounted rather than calling them skipped. The resulting
	// discovered-versus-analyzed gap prevents full coverage over text static analysis never read.
	analyzed -= move
	for _, reason := range cov.SkipReasons {
		if !slices.Contains(reasons, reason) {
			reasons = append(reasons, reason)
		}
	}
	return analyzed, skipped, reasons
}

func (a *Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name: analyzerName,
		Purpose: "Finds prompt injection, hidden content and tool poisoning in the text " +
			"an MCP server hands to an LLM: tool and prompt descriptions, a tool's input " +
			"and output schema (including parameter and return-value descriptions), " +
			"all string leaves in annotations and _meta, resource content and server instructions.",
		Threats: []string{
			"instruction override",
			"hidden or invisible content (zero-width characters, bidi overrides, mixed scripts, HTML comments, base64 blobs)",
			"tool poisoning (calling another tool silently, hiding actions from the user, reading unrelated files)",
			"credential harvesting",
			"exfiltration instructions",
			"oversized or fake-turn descriptions",
			"annotations that contradict what the description says the tool does",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceHeuristic, model.EvidenceStatic},
		Active:   false,
		Limitations: []string{
			"only sees text the server declared or returned in the snapshot; a payload assembled at tool-call time is invisible",
			"pattern matching can miss a paraphrased, translated or split-across-fields injection attempt",
			"the rules also run over a normalized fold of every unit - whitespace collapsed, emphasis and HTML tags stripped, curly punctuation, full-width and mathematical alphanumerics and Cyrillic/Greek look-alikes mapped to ASCII, combining marks dropped - so a spelling variant is matched; a substitution the fold does not know is still a miss",
			"the hidden-character and confusable checks deliberately keep reading the raw text rather than the fold",
			"a qualifier in the same sentence as a match - a defensive verb, a missing context word, an introducing preface - reduces confidence and drops severity by exactly one step: a CRITICAL match is reported at HIGH, still at the default gate, and a HIGH at MEDIUM, below it",
			"a match that is both quoted and qualified - the shape a linter describing a payload takes - is the one case that drops all the way to LOW: two independent author-written signals, and the benign corpus pins the case it exists for",
			"resource content or a prompt's rendered text that was never fetched is analyzed by name and description only (run with --read-resources/--get-prompts on a live target to fetch it; a static or source target has no session to fetch from at all)",
			"a prompt requiring an argument the scanner does not have fails to render even with --get-prompts set; that is reported as a coverage gap, not evasion",
			"input schema, output schema, annotations and _meta share one described-value budget per tool; a tool deep or wide enough to hit it stops there and the scan reports a coverage gap rather than scanning past it",
			"on a source target it sees text only for capabilities whose registration form the build recognizes, and nothing at all when none were resolved",
			"the rules applied may not be the shipped ones: a rules_dir option, or a rules/prompt-defense directory beside the binary, merges over or replaces them - check the scan's own warnings for where its rules came from",
		},
	}
}

var (
	rulesCacheMu sync.Mutex
	rulesCache   = map[string]cachedRules{}

	embeddedOnce  sync.Once
	embeddedCache cachedRules
)

// rulesCacheTTL bounds how long a compiled on-disk rules_dir is trusted without re-reading
// it. Unbounded caching is correct for the CLI - one scan per process - but wrong for a
// long-running server: an operator editing a rule file would need a restart to see it, and
// a directory that was briefly unreadable would stay an ERROR for the rest of the process's
// life.
const rulesCacheTTL = 30 * time.Second

type cachedRules struct {
	rules    []*compiledRule
	err      error
	loadedAt time.Time
}

// resolveRules checks configured, executable-adjacent, then embedded rules.
// Disk rules merge over embedded rules by ID. Configured missing or empty
// directories fail instead of falling back.
func resolveRules(ac *analyzer.AnalysisContext) ([]*compiledRule, string, error) {
	dir := ""
	if ac != nil {
		if v, ok := ac.Option(analyzerName, "rules_dir"); ok {
			if s, ok := v.(string); ok && s != "" {
				dir = s
			}
		}
	}
	if dir == "" {
		if found, ok := config.RulesDirBesideExecutable("prompt-defense"); ok {
			dir = found
		}
	}
	if dir == "" {
		rules, err := loadCachedEmbedded()
		return rules, "", err
	}

	extra, err := loadCached(dir)
	if err != nil {
		return nil, dir, err
	}
	base, err := loadCachedEmbedded()
	if err != nil {
		return nil, dir, err
	}
	return mergeRules(base, extra), dir, nil
}

// mergeRules layers extra over base, replacing a shipped rule when the IDs
// match and appending otherwise. Order is base-then-new so a report reads the
// same way whichever directory an operator points at.
func mergeRules(base, extra []*compiledRule) []*compiledRule {
	byID := make(map[string]int, len(base))
	out := make([]*compiledRule, 0, len(base)+len(extra))
	for _, r := range base {
		byID[r.ID] = len(out)
		out = append(out, r)
	}
	for _, r := range extra {
		if i, ok := byID[r.ID]; ok {
			out[i] = r
			continue
		}
		byID[r.ID] = len(out)
		out = append(out, r)
	}
	return out
}

// loadCached compiles the rules under dir and reuses them for every scan
// that resolves to the same directory within rulesCacheTTL (the common
// case: the same analyzer instance scanning many targets in one process)
func loadCached(dir string) ([]*compiledRule, error) {
	rulesCacheMu.Lock()
	defer rulesCacheMu.Unlock()
	if v, ok := rulesCache[dir]; ok && time.Since(v.loadedAt) < rulesCacheTTL {
		return v.rules, v.err
	}
	rules, err := LoadRules(dir)
	rulesCache[dir] = cachedRules{rules, err, time.Now()}
	return rules, err
}

// loadCachedEmbedded compiles the embedded rule set once per process
func loadCachedEmbedded() ([]*compiledRule, error) {
	embeddedOnce.Do(func() {
		embeddedCache.rules, embeddedCache.err = loadEmbeddedRules()
	})
	return embeddedCache.rules, embeddedCache.err
}
