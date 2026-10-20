package source

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func init() { analyzer.Register(&Analyzer{}) }

// Analyzer walks a source tree, builds the symbol/call graph and discovers
// MCP registrations. Its own findings are limited to what the discovery
// pass itself can say about a capability's declared metadata; dataflow and
// behavioral comparison are separate analyzers that consume the same graph.
type Analyzer struct{}

func (*Analyzer) Name() string { return "source" }

func (*Analyzer) AppliesTo(kind model.TargetKind) bool {
	return kind == model.TargetSource || kind == model.TargetPackage
}

func (*Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	started := time.Now().UTC()
	var acRoot string
	if ac != nil {
		acRoot = ac.Root
	}
	root, err := ResolveRoot(target.Path, acRoot)
	if err != nil {
		return model.Errorf("source", "config", "%v", err)
	}
	if root == "" {
		return model.Errorf("source", "config", "no source path to scan")
	}

	// displayPath is what an error below names, and it is the path as the
	// caller wrote it, not root: root can be ResolveRoot's symlink-resolved
	// absolute form, which is host filesystem detail a caller does not
	// otherwise get to observe about where their path actually landed
	displayPath := target.Path
	if displayPath == "" {
		displayPath = root
	}

	g, cov, err := graphWithWalkCoverage(ctx, ac, root)
	if err != nil {
		return model.Errorf("source", "internal", "walking %s: %v", displayPath, err)
	}
	// FilesDiscovered counts every candidate source file the walk found, including ones inside
	// an excluded directory - so zero here means the walk genuinely found nothing to analyze
	// anywhere under root, not that everything it found got excluded
	if cov.FilesDiscovered == 0 {
		return model.Errorf("source", "config", "no candidate source file found under %s", displayPath)
	}
	if ac != nil {
		Publish(ac.Artifacts, g, cov)
	}

	status := model.AnalyzerCompleted
	if ctx.Err() != nil {
		status = model.AnalyzerPartial
	}

	res := model.AnalyzerResult{
		Analyzer:  "source",
		Status:    status,
		Required:  true,
		Coverage:  cov,
		Findings:  capabilityFindings(g),
		StartedAt: started,
	}
	res.FinishedAt = time.Now().UTC()
	res.Duration = res.FinishedAt.Sub(started)
	return res
}

// graphWithWalkCoverage reuses a published graph and its original walk coverage, or builds
// both. Missing coverage becomes zero and is rejected by Analyze.
func graphWithWalkCoverage(ctx context.Context, ac *analyzer.AnalysisContext, root string) (*graph.Graph, model.Coverage, error) {
	if ac != nil && ac.Artifacts != nil {
		if g, ok := analyzer.Get[*graph.Graph](ac.Artifacts, ArtifactKey); ok && g != nil {
			cov, _ := analyzer.Get[model.Coverage](ac.Artifacts, WalkCoverageKey)
			return g, cov, nil
		}
	}
	return Build(ctx, root)
}

// ResolveRoot picks the scan root, preferring ac.Root over target.Path: a caller that set
// Root has already fixed the filesystem boundary, so target.Path cannot override it. If
// Root is unset, target.Path is used as-is. When both are present, symlinks are resolved and
// target.Path must remain beneath the established root.
func ResolveRoot(targetPath, acRoot string) (string, error) {
	if acRoot == "" {
		return targetPath, nil
	}
	if targetPath == "" || targetPath == acRoot {
		return acRoot, nil
	}

	rootAbs, err := filepath.Abs(acRoot)
	if err != nil {
		return "", fmt.Errorf("resolving root %q: %w", acRoot, err)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", fmt.Errorf("resolving root %q: %w", acRoot, err)
	}

	pathAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return "", fmt.Errorf("resolving target path %q: %w", targetPath, err)
	}
	pathReal, err := filepath.EvalSymlinks(pathAbs)
	if err != nil {
		return "", fmt.Errorf("resolving target path %q: %w", targetPath, err)
	}

	rel, err := filepath.Rel(rootReal, pathReal)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("target path %q is not under scan root %q", targetPath, acRoot)
	}
	return acRoot, nil
}

// capabilityFindings reports the two things the discovery pass itself is positioned to say
// about a capability's static declaration, without any dataflow: it has no description, or
// its name could not be pinned down
func capabilityFindings(g *graph.Graph) []model.Finding {
	var findings []model.Finding
	for _, c := range g.Capabilities {
		if !c.NameResolved {
			findings = append(findings, model.Finding{
				RuleID:        "source.capability_name_unresolved",
				Category:      "mcp_capability_hygiene",
				Title:         fmt.Sprintf("%s registration (%s form) has a name that cannot be resolved statically", c.Kind, c.Form),
				Severity:      model.SeverityLow,
				Confidence:    0.9,
				EvidenceLevel: model.EvidenceStatic,
				File:          c.File,
				Line:          c.Line,
				Description: fmt.Sprintf(
					"the %s registered at %s:%d computes its name at runtime; static analysis cannot say what it is called or reliably scope other findings to it",
					c.Kind, c.File, c.Line),
				Evidence: []model.Evidence{{
					Level:       model.EvidenceStatic,
					Kind:        "mcp_registration",
					Description: "registration site found by the source discovery pass",
					File:        c.File,
					Line:        c.Line,
				}},
			})
		}
		if c.Handler != "" && !c.DescriptionResolved {
			findings = append(findings, model.Finding{
				RuleID:        "source.capability_no_description",
				Category:      "mcp_capability_hygiene",
				Title:         fmt.Sprintf("%s %q has no statically known description", c.Kind, displayName(c)),
				Severity:      model.SeverityLow,
				Confidence:    0.7,
				EvidenceLevel: model.EvidenceStatic,
				File:          c.File,
				Line:          c.Line,
				Tool:          displayName(c),
				Description: fmt.Sprintf(
					"the %s registered at %s:%d has no description in its registration and no docstring on its handler; a model relying on the declared surface has nothing to judge intent against",
					c.Kind, c.File, c.Line),
				Evidence: []model.Evidence{{
					Level:       model.EvidenceStatic,
					Kind:        "mcp_registration",
					Description: "registration site found by the source discovery pass",
					File:        c.File,
					Line:        c.Line,
				}},
			})
		}
	}
	return findings
}

func displayName(c graph.Capability) string {
	if c.NameResolved {
		return c.Name
	}
	if c.HandlerText != "" {
		return c.HandlerText
	}
	return "<unresolved>"
}

func (*Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name:    "source",
		Purpose: "Walks a source tree, builds a cross-file symbol and call graph, and discovers where MCP tools, prompts and resources are registered.",
		Threats: []string{
			"a tool, prompt or resource registered without a description an operator can audit",
			"a capability whose declared name cannot be determined statically",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceStatic},
		Active:   false,
		Limitations: []string{
			"call resolution is name-based, not type-based: two functions with the same name in different packages can resolve to the wrong one",
			"a registration table or loop built from data computed at runtime is recorded once as discovered but unresolved, not enumerated per element",
			"dynamic dispatch, reflection and code generation are invisible to a static parse",
			"JavaScript and TypeScript decorator-style registration is not resolved (no required fixture form depends on it)",
			"only the registration forms this build actually recognizes are analyzed on a source target; see docs/analyzers/source-and-behavioral.md for the current list of what is, and is not, discovered",
		},
	}
}

// LoadGraph reuses a published graph or builds one independently. A reused graph without walk
// coverage is accepted but reported as PARTIAL, so missing metadata cannot resemble an empty tree.
func LoadGraph(ctx context.Context, ac *analyzer.AnalysisContext, root string) (g *graph.Graph, cov model.Coverage, walkCoverageMissing bool, err error) {
	if ac != nil && ac.Artifacts != nil {
		if g, ok := analyzer.Get[*graph.Graph](ac.Artifacts, ArtifactKey); ok && g != nil {
			_, hasWalkCov := analyzer.Get[model.Coverage](ac.Artifacts, WalkCoverageKey)
			return g, model.Coverage{}, !hasWalkCov, nil
		}
	}
	g, cov, err = Build(ctx, root)
	return g, cov, false, err
}
