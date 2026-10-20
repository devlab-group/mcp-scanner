// Package readiness checks the declared security posture of an MCP server: whether it says
// anything about authentication, whether tools document themselves and mark destructive
// operations as such, and whether resource URIs constrain what they can reach. It does not
// look for attacks; that is promptdefense's job.
package readiness

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/mcp/snapshot"
	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

const analyzerName = "readiness"

// Interface satisfaction is otherwise only checked by a runtime type
// assertion (Applicable, Describer are both optional), so a signature typo
// here would silently drop the method instead of failing to build
var (
	_ analyzer.Analyzer   = (*Analyzer)(nil)
	_ analyzer.Applicable = (*Analyzer)(nil)
	_ analyzer.Describer  = (*Analyzer)(nil)
)

func init() {
	analyzer.Register(&Analyzer{})
}

// Analyzer reports on the declared security posture of a snapshot
type Analyzer struct{}

func (a *Analyzer) Name() string { return analyzerName }

// AppliesTo is every target kind: it only reads the snapshot
func (a *Analyzer) AppliesTo(model.TargetKind) bool { return true }

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	if ac == nil || ac.Snapshot == nil {
		return model.Skipped(analyzerName, "no MCP snapshot available for this target")
	}
	snap := ac.Snapshot

	status := model.AnalyzerCompleted
	if ctx.Err() != nil {
		status = model.AnalyzerPartial
	}

	var findings []model.Finding
	var skipReasons []string

	// A snapshot synthesized from a source tree carries the text a server declares and nothing
	// else. Input schemas, annotations, instructions and authorization metadata are not
	// resolvable from a registration call, so their absence here says nothing about the server.
	declaredOnly := snap.Transport.Kind == model.TransportSource

	findings = append(findings, checkToolDocumentation(snap, declaredOnly)...)
	if declaredOnly {
		skipReasons = append(skipReasons,
			"input schemas, annotations, server instructions and authorization metadata are "+
				"not visible in a source tree, so the checks that read them did not run")
	} else {
		findings = append(findings, checkInstructions(snap)...)
		findings = append(findings, checkDestructiveAnnotation(snap)...)
		findings = append(findings, checkAuthSignal(snap)...)
		findings = append(findings, checkResourceURIs(snap)...)
	}

	n := snap.CapabilityCount()
	cov := model.Coverage{
		CapabilitiesDiscovered: n,
		CapabilitiesAnalyzed:   n,
		SkipReasons:            skipReasons,
	}
	// Every check here reads whatever discovery kept, so CapabilitiesAnalyzed
	// is right; CapabilityCount alone cannot see what discovery itself
	// stopped short of (a paged tool list, a repeated cursor), which is what
	// this folds in
	cov = snapshot.FoldCapabilityCoverage(snap, cov)
	// A source or package target is built by walking a file tree; a capability in a directory
	// the walk excluded never reaches the snapshot this analyzer reads, and CapabilityCount
	// alone cannot see that
	if target.Kind == model.TargetSource || target.Kind == model.TargetPackage {
		cov = source.FoldWalkCoverage(ac.Artifacts, cov)
	}
	return model.AnalyzerResult{
		Analyzer: analyzerName,
		Status:   status,
		Findings: findings,
		Coverage: cov,
	}
}

func (a *Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name: analyzerName,
		Purpose: "Checks the declared security posture of an MCP server: whether it documents " +
			"itself, marks destructive tools as such, signals authentication, and constrains " +
			"resource URIs.",
		Threats: []string{
			"missing server instructions",
			"undocumented tools (no description or input schema)",
			"a destructive tool with no destructiveHint annotation",
			"no declared authentication requirement",
			"a resource URI or template with no visible path constraint",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceStatic, model.EvidenceHeuristic},
		Active:   false,
		Limitations: []string{
			"absence of a signal in the snapshot is not proof the server lacks it; a live " +
				"protocol probe (the auth analyzer) is needed to confirm authentication behavior",
			"only as good as the declarations the server chooses to make",
		},
	}
}

func finding(id, category, title string, sev model.Severity, level model.EvidenceLevel, confidence float64, tool, desc, remediation, snippet string) model.Finding {
	return model.Finding{
		RuleID: id, Category: category, Title: title,
		Severity: sev, Confidence: confidence, EvidenceLevel: level,
		Tool: tool, Description: desc, Remediation: remediation, Analyzer: analyzerName,
		Evidence: []model.Evidence{{Level: level, Description: desc, Snippet: snippet}},
	}
}

func checkInstructions(snap *model.Snapshot) []model.Finding {
	if snap.Instructions != "" {
		return nil
	}
	return []model.Finding{finding(
		"readiness.no-instructions", "posture", "Server declares no instructions",
		model.SeverityInfo, model.EvidenceStatic, 0.9, "",
		"The server did not declare any instructions field for clients to show a model. "+
			"That is not unsafe by itself, but it means there is nothing to review for how "+
			"the server wants to be used.",
		"If the server has operating conventions a model should follow, declare them so they can be reviewed.",
		"",
	)}
}

// checkToolDocumentation reports tools that document nothing. declaredOnly
// drops the schema half: a source tree does not carry input schemas, so their
// absence there is the scanner's blind spot rather than the server's omission
func checkToolDocumentation(snap *model.Snapshot, declaredOnly bool) []model.Finding {
	var noDesc, noSchema []string
	for _, t := range snap.Tools {
		if strings.TrimSpace(t.Description) == "" {
			noDesc = append(noDesc, t.Name)
		}
		if !declaredOnly && len(t.InputSchema) == 0 {
			noSchema = append(noSchema, t.Name)
		}
	}
	var out []model.Finding
	if len(noDesc) > 0 {
		out = append(out, finding(
			"readiness.tool-missing-description", "posture", "Tool has no description",
			model.SeverityLow, model.EvidenceStatic, 0.9, strings.Join(noDesc, ", "),
			fmt.Sprintf("%d tool(s) declare no description: %s. A user approving a tool call has nothing to read.", len(noDesc), strings.Join(noDesc, ", ")),
			"Add a description explaining what the tool does before it is exposed to clients.",
			"",
		))
	}
	if len(noSchema) > 0 {
		out = append(out, finding(
			"readiness.tool-missing-schema", "posture", "Tool has no input schema",
			model.SeverityLow, model.EvidenceStatic, 0.9, strings.Join(noSchema, ", "),
			fmt.Sprintf("%d tool(s) declare no input schema: %s. A client cannot validate arguments before sending them.", len(noSchema), strings.Join(noSchema, ", ")),
			"Declare an input schema so clients and this scanner can reason about what the tool accepts.",
			"",
		))
	}
	return out
}

// destructiveVerbs mirrors the write-verb vocabulary promptdefense's
// conflicting-metadata rule uses, since both checks answer the same
// question - does the annotation match what the description says
var destructiveVerbs = regexp.MustCompile(`(?i)\b(delete|deletes|deleting|remove|removes|removing|overwrite|overwrites|drop|drops|truncate|truncates|format|formats|uninstall|uninstalls|terminate|terminates|kill|kills|destroy|destroys|wipe|wipes)\b`)
var destructiveNegate = regexp.MustCompile(`(?i)\b(does not|doesn't|never|without (deleting|removing|overwriting))\b`)

func checkDestructiveAnnotation(snap *model.Snapshot) []model.Finding {
	var missing []string
	for _, t := range snap.Tools {
		if !destructiveVerbs.MatchString(t.Description) || destructiveNegate.MatchString(t.Description) {
			continue
		}
		if destructiveHint(t.Annotations) {
			continue
		}
		missing = append(missing, t.Name)
	}
	if len(missing) == 0 {
		return nil
	}
	return []model.Finding{finding(
		"readiness.destructive-not-annotated", "posture", "Destructive tool not annotated as such",
		model.SeverityMedium, model.EvidenceHeuristic, 0.7, strings.Join(missing, ", "),
		fmt.Sprintf("%d tool(s) describe a destructive action but do not set destructiveHint: true: %s. "+
			"A client that offers a lighter confirmation for non-destructive tools would under-warn here.", len(missing), strings.Join(missing, ", ")),
		"Set destructiveHint: true on any tool whose description says it deletes, overwrites or otherwise destroys state.",
		"",
	)}
}

func destructiveHint(ann map[string]any) bool {
	for k, v := range ann {
		if strings.EqualFold(k, "destructiveHint") {
			b, ok := v.(bool)
			return ok && b
		}
	}
	return false
}

func checkAuthSignal(snap *model.Snapshot) []model.Finding {
	if authDeclared(snap) {
		return nil
	}
	return []model.Finding{finding(
		"readiness.no-auth-declared", "posture", "No declared authentication requirement observed",
		model.SeverityInfo, model.EvidenceHeuristic, 0.3, "",
		"Nothing in the snapshot (response headers or declared capabilities) indicates the "+
			"server requires authentication. This is a weak signal, not proof the server is "+
			"open: it only means discovery did not observe one.",
		"Confirm the server's authentication requirement directly (see the auth analyzer) rather than relying on this note alone.",
		"",
	)}
}

func authDeclared(snap *model.Snapshot) bool {
	for k := range snap.Transport.Headers {
		if strings.EqualFold(k, "WWW-Authenticate") {
			return true
		}
	}
	for k := range snap.Capabilities {
		if strings.Contains(strings.ToLower(k), "auth") {
			return true
		}
	}
	return false
}

// unconstrainedTemplate matches a template whose entire path is one RFC 6570
// expansion with no literal prefix to anchor it, or that contains an
// explicit ".." traversal token
var unconstrainedTemplate = regexp.MustCompile(`^\w+:///?\{[+#]?[\w,]+\}/?$`)

func checkResourceURIs(snap *model.Snapshot) []model.Finding {
	var flagged []string
	check := func(r model.ResourceInfo) {
		id := r.URITemplate
		if id == "" {
			id = r.URI
		}
		if id == "" {
			return
		}
		if strings.Contains(id, "..") || unconstrainedTemplate.MatchString(id) {
			flagged = append(flagged, id)
		}
	}
	for _, r := range snap.Resources {
		check(r)
	}
	for _, r := range snap.Templates {
		check(r)
	}
	if len(flagged) == 0 {
		return nil
	}
	return []model.Finding{finding(
		"readiness.resource-unconstrained-uri", "posture", "Resource URI has no visible path constraint",
		model.SeverityLow, model.EvidenceHeuristic, 0.6, "",
		fmt.Sprintf("%d resource URI(s) have no literal prefix constraining what they can reach, or contain a \"..\" segment: %s.", len(flagged), strings.Join(flagged, ", ")),
		"Anchor resource templates to a fixed prefix directory and reject \"..\" segments when resolving them.",
		strings.Join(flagged, ", "),
	)}
}
