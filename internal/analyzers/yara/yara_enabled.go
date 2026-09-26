//go:build yara

// github.com/hillu/go-yara/v4 is declared in go.mod, but this file needs the system yara
// library to cgo-link, and that library isn't installed everywhere - without it `make
// build-yara` stops at "Package yara was not found in the pkg-config search path" instead
// of compiling this file

package yara

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"sync"
	"time"

	goyara "github.com/hillu/go-yara/v4"

	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/mcp/snapshot"
	"github.com/revinand/mcp-scanner/internal/mcp/surface"
	"github.com/revinand/mcp-scanner/internal/source"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

const scanTimeout = 30 * time.Second

var _ analyzer.Analyzer = (*Analyzer)(nil)

// embeddedRules mirrors rules/yara/*.yar at the repository root; see
// embed.go in the promptdefense package for why a copy is needed and what
// keeps it from drifting. rules/yara/ at the repository root is the source
// of truth - edit the .yar files there, copy the changed files into
// rulesdata/, and run TestEmbeddedRulesMatchSource
//
//go:embed rulesdata/*.yar
var embeddedRules embed.FS

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	rules, rulesDir, err := resolveRules(ac)
	if err != nil {
		return model.Errorf(analyzerName, "config", "load yara rules: %v", err)
	}

	if ac == nil || ac.Snapshot == nil {
		return model.Skipped(analyzerName, "no MCP snapshot available for this target")
	}

	// analyzed is deliberately not taken from extractUnits: it counts what
	// there was to scan, and the loop below can stop before it gets through
	// it. What was actually scanned is counted there instead.
	units, discovered, _, skipped, skipReasons, limitsHit := extractUnits(ac.Snapshot, target.Kind)

	status := model.AnalyzerCompleted
	var findings []model.Finding
	var warnings []string
	// Which signatures ran is a fact about the scan's coverage
	if rulesDir != "" {
		warnings = append(warnings, fmt.Sprintf(
			"yara signatures loaded from %s, replacing the embedded set", rulesDir))
	}
	// A capability can contribute more than one unit (a prompt has both a
	// description and a text), so it counts as analyzed once, and only once
	// the loop has actually reached it
	scanned := map[string]bool{}
	for _, u := range units {
		if ctx.Err() != nil {
			status = model.AnalyzerPartial
			break
		}

		var matches goyara.MatchRules
		if err := rules.ScanMem([]byte(u.text), 0, scanTimeout, &matches); err != nil {
			return model.Errorf(analyzerName, "internal", "yara scan failed on %s: %v", u.locator(), err)
		}
		for _, m := range matches {
			findings = append(findings, findingFromMatch(u, m))
		}
		scanned[u.capKind+"/"+u.capability] = true
	}

	cov := model.Coverage{
		CapabilitiesDiscovered: discovered,
		CapabilitiesAnalyzed:   len(scanned),
		CapabilitiesSkipped:    skipped,
		SkipReasons:            skipReasons,
		LimitsHit:              limitsHit,
	}
	// The loop counters describe what the snapshot held, not what discovery managed to put in
	// it: a tool list cut short by pagination, and a source tree whose walk hit an unreadable
	// directory or a size cap, are both invisible from here
	cov = snapshot.FoldCapabilityCoverage(ac.Snapshot, cov)
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

// compileRules compiles every *.yar/*.yara file in fsys under root into one rule set. A
// source that fails to load is an error, never an empty pass: see rules.go in the
// promptdefense package for the same reasoning.
func compileRules(fsys fs.FS, root, label string) (*goyara.Rules, error) {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch path.Ext(e.Name()) {
		case ".yar", ".yara":
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.yar rule files found in %s", label)
	}

	compiler, err := goyara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("create yara compiler: %w", err)
	}
	for _, name := range files {
		data, err := fs.ReadFile(fsys, path.Join(root, name))
		if err != nil {
			return nil, fmt.Errorf("read %s (%s): %w", name, label, err)
		}
		if err := compiler.AddString(string(data), "mcp-scanner"); err != nil {
			return nil, fmt.Errorf("compile %s (%s): %w", name, label, err)
		}
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("get compiled yara rules (%s): %w", label, err)
	}
	return rules, nil
}

var (
	rulesCacheMu sync.Mutex
	rulesCache   = map[string]cachedYaraRules{}

	embeddedOnce  sync.Once
	embeddedCache cachedYaraRules
)

type cachedYaraRules struct {
	rules *goyara.Rules
	err   error
}

// resolveRules picks the rule set to use, in the same order and for the
// same reasons as promptdefense's resolveRules: an explicitly configured
// rules_dir fails closed if it is missing or empty (an operator mistake,
// not a relocated binary); a directory found on disk overrides the shipped
// rules without a rebuild; otherwise the rules embedded in the binary at
// build time are what runs, which is what a relocated or installed binary
// actually has available
func resolveRules(ac *analyzer.AnalysisContext) (*goyara.Rules, string, error) {
	dir := ""
	if ac != nil {
		if v, ok := ac.Option(analyzerName, "rules_dir"); ok {
			if s, ok := v.(string); ok && s != "" {
				dir = s
			}
		}
	}
	if dir == "" {
		if found, ok := config.RulesDirBesideExecutable("yara"); ok {
			dir = found
		}
	}
	if dir == "" {
		rules, err := loadCachedEmbedded()
		return rules, "", err
	}
	rules, err := loadCached(dir)
	return rules, dir, err
}

func loadCached(dir string) (*goyara.Rules, error) {
	rulesCacheMu.Lock()
	defer rulesCacheMu.Unlock()
	if v, ok := rulesCache[dir]; ok {
		return v.rules, v.err
	}
	rules, err := compileRules(os.DirFS(dir), ".", "directory "+dir)
	rulesCache[dir] = cachedYaraRules{rules, err}
	return rules, err
}

func loadCachedEmbedded() (*goyara.Rules, error) {
	embeddedOnce.Do(func() {
		embeddedCache.rules, embeddedCache.err = compileRules(embeddedRules, "rulesdata", "the embedded rule set")
	})
	return embeddedCache.rules, embeddedCache.err
}

// findingFromMatch turns one YARA match into a Finding. A signature match
// against parsed-out text is exactly what EvidenceStatic means here: the
// engine matched real byte content, not a heuristic guess.
func findingFromMatch(u unit, m goyara.MatchRule) model.Finding {
	title := m.Rule
	severity := model.SeverityMedium
	category := "yara_match"
	for _, meta := range m.Metas {
		switch meta.Identifier {
		case "title":
			if s, ok := meta.Value.(string); ok {
				title = s
			}
		case "severity":
			if s, ok := meta.Value.(string); ok {
				severity = model.Severity(s)
			}
		case "category":
			if s, ok := meta.Value.(string); ok {
				category = s
			}
		}
	}
	if !severity.Valid() {
		severity = model.SeverityMedium
	}

	var evidence []model.Evidence
	for _, s := range m.Strings {
		evidence = append(evidence, model.Evidence{
			Level:       model.EvidenceStatic,
			Kind:        "yara_match",
			Description: fmt.Sprintf("string %q matched at offset %d in %s", s.Name, s.Offset, u.locator()),
			Snippet:     snippet(string(s.Data)),
		})
	}
	if len(evidence) == 0 {
		evidence = []model.Evidence{{
			Level:       model.EvidenceStatic,
			Kind:        "yara_match",
			Description: fmt.Sprintf("rule %s matched in %s", m.Rule, u.locator()),
		}}
	}

	return model.Finding{
		RuleID:        "yara." + m.Rule,
		Category:      category,
		Title:         title,
		Severity:      severity,
		Confidence:    0.8,
		EvidenceLevel: model.EvidenceStatic,
		File:          u.locator(),
		Tool:          u.capability,
		Description:   fmt.Sprintf("YARA rule %q matched declared text in %s.", m.Rule, u.locator()),
		Analyzer:      analyzerName,
		Evidence:      evidence,
	}
}

func snippet(s string) string {
	const max = 120
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// unit is one piece of declared text worth scanning, scoped to the
// capability it came from so a match can point back at it. This mirrors
// promptdefense's unit type; it is kept separate rather than shared across
// the build-tag boundary, since promptdefense's is package-private.
type unit struct {
	text       string
	field      string
	capKind    string
	capability string
}

func (u unit) locator() string {
	return surface.Locator(u.capKind, u.capability, u.field)
}

// extractUnits returns scannable text and per-capability coverage. targetKind comes from the
// scan because a replayed snapshot retains the transport on which it was captured.
func extractUnits(snap *model.Snapshot, targetKind model.TargetKind) (units []unit, discovered, analyzed, skipped int, skipReasons, limitsHit []string) {
	if snap == nil {
		return nil, 0, 0, 0, nil, nil
	}
	if snap.Instructions != "" {
		discovered++
		analyzed++
		units = append(units, unit{text: snap.Instructions, field: "instructions", capKind: "server"})
	}
	for _, t := range snap.Tools {
		discovered++
		if t.Description == "" {
			skipped++
			skipReasons = append(skipReasons, fmt.Sprintf("tool %q has no description to scan", t.Name))
			continue
		}
		analyzed++
		units = append(units, unit{text: t.Description, field: "description", capKind: "tool", capability: t.Name})
	}
	for _, p := range snap.Prompts {
		discovered++
		any := false
		if p.Description != "" {
			units = append(units, unit{text: p.Description, field: "description", capKind: "prompt", capability: p.Name})
			any = true
		}
		if p.Text != "" {
			units = append(units, unit{text: p.Text, field: "text", capKind: "prompt", capability: p.Name})
			any = true
		}
		if any {
			analyzed++
		} else {
			skipped++
			skipReasons = append(skipReasons, fmt.Sprintf("prompt %q has no description or text to scan", p.Name))
		}
	}
	scanResource := func(kind string, r model.ResourceInfo) {
		discovered++
		id := r.URI
		if id == "" {
			id = r.URITemplate
		}
		if r.Content == "" {
			// YARA does not scan resource names or descriptions, so missing content leaves no unit.
			// An unread live body is a limit. A source or package tree has no body until runtime,
			// so its absence is an explained skip and does not prevent completion.
			switch {
			case r.ReadError != "":
				limitsHit = append(limitsHit, fmt.Sprintf("%s %q: content could not be read (%s)", kind, id, r.ReadError))
			case targetKind == model.TargetSource || targetKind == model.TargetPackage:
				skipped++
				skipReasons = append(skipReasons, fmt.Sprintf(
					"%s %q: a resource body is produced at call time and does not exist in a source tree", kind, id))
			default:
				limitsHit = append(limitsHit, fmt.Sprintf("%s %q: content was not fetched, so nothing about its body was scanned", kind, id))
			}
			return
		}
		analyzed++
		units = append(units, unit{text: r.Content, field: "content", capKind: kind, capability: id})
	}
	for _, r := range snap.Resources {
		scanResource("resource", r)
	}
	for _, r := range snap.Templates {
		scanResource("resource_template", r)
	}
	return units, discovered, analyzed, skipped, skipReasons, limitsHit
}
