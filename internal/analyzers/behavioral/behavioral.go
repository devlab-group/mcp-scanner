// Package behavioral compares what an MCP capability says it does against what its handler
// actually reaches, using only the graph the source pass already built: no LLM, just a
// fixed vocabulary matched against the description and a fixed catalogue of
// filesystem/network/process/credential calls matched against everything the handler
// statically reaches. Reachability is co-occurrence evidence, not a traced dataflow proof.
package behavioral

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/revinand/mcp-scanner/internal/source"
	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func init() { analyzer.Register(&Analyzer{}) }

type Analyzer struct{}

func (*Analyzer) Name() string { return "behavioral" }

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
		return model.Errorf("behavioral", "config", "%v", err)
	}
	if root == "" {
		return model.Errorf("behavioral", "config", "no source path to scan")
	}

	g, cov, walkCoverageMissing, err := source.LoadGraph(ctx, ac, root)
	if err != nil {
		return model.Errorf("behavioral", "internal", "building source graph: %v", err)
	}

	var findings []model.Finding
	// cov's capability counts are source.Build's own so far ("every
	// discovered one was inspected for name/handler"); the loop below
	// computes behavioral's own, so start those three fields fresh rather
	// than incrementing on top of source.Build's numbers
	cov.CapabilitiesDiscovered = len(g.Capabilities)
	cov.CapabilitiesAnalyzed, cov.CapabilitiesSkipped = 0, 0

	// None of the three continues below touches CapabilitiesSkipped: each one is behavioral
	// saying it could not compare this capability at all, which leaves it unaccounted so
	// Coverage.Gaps() reports it and the scan downgrades. A skip would balance the arithmetic
	// and let one uncomparable capability alongside one ordinary one report full coverage.
	for _, cap := range g.Capabilities {
		if ctx.Err() != nil {
			break
		}
		if cap.Handler == "" {
			cov.AddSkipReason("capability handler is not statically known")
			continue
		}
		if _, ok := g.Symbols[cap.Handler]; !ok {
			cov.AddSkipReason("handler symbol not found in the graph")
			continue
		}
		if !cap.DescriptionResolved {
			// Missing source text is a coverage gap, not an empty declaration
			cov.AddSkipReason("capability description could not be resolved statically")
			continue
		}
		cov.CapabilitiesAnalyzed++
		actual, sawUnknown := actualCapabilities(g, cap.Handler)
		findings = append(findings, mismatches(cap, actual, sawUnknown)...)
	}

	model.SortFindings(findings)

	var warnings []string
	status := model.AnalyzerCompleted
	if ctx.Err() != nil {
		status = model.AnalyzerPartial
	}
	if walkCoverageMissing {
		// The graph came from ac.Artifacts but nobody published the walk's
		// own Coverage next to it (source.WalkCoverageKey) - behavioral has
		// no file-level coverage to report and would otherwise claim
		// complete coverage over a tree it never walked itself. See loadGraph.
		status = model.AnalyzerPartial
		warnings = append(warnings, "the published source graph carried no walk coverage; file-level coverage cannot be reported for this scan")
	}

	var arts *analyzer.Artifacts
	if ac != nil {
		arts = ac.Artifacts
	}
	cov = source.FoldWalkCoverage(arts, cov)

	res := model.AnalyzerResult{
		Analyzer:  "behavioral",
		Status:    status,
		Required:  true,
		Coverage:  cov,
		Findings:  findings,
		Warnings:  warnings,
		StartedAt: started,
	}
	res.FinishedAt = time.Now().UTC()
	res.Duration = res.FinishedAt.Sub(started)
	return res
}

// actualCapabilities walks every call reachable from handler (itself
// included) and reports which categories it touches, and the literal
// sensitive paths it found along the way
func actualCapabilities(g *graph.Graph, handler graph.SymbolID) (capSet, bool) {
	reached, sawUnknown := g.Reachable(handler)
	reached[handler] = true

	var cs capSet
	for id := range reached {
		for _, call := range g.CallsFrom(id) {
			if cat, ok := categoryOf(call.CalleeText); ok {
				mark(&cs, cat)
			}
			if isEnvRead(call.CalleeText) {
				for _, a := range call.Args {
					name := a.Value
					if name == "" {
						name = a.Text
					}
					if credentialLikeName(name) {
						cs.Credentials = true
						cs.SensitiveHits = append(cs.SensitiveHits, "env:"+name)
						break
					}
				}
			}
			for _, a := range call.Args {
				v := a.Value
				if v == "" {
					v = a.Text
				}
				if frag, ok := sensitiveFragment(v); ok {
					cs.Credentials = true
					cs.SensitiveHits = append(cs.SensitiveHits, frag)
				}
			}
		}
	}
	return cs, sawUnknown
}

func mark(cs *capSet, cat category) {
	switch cat {
	case catFilesystem:
		cs.Filesystem = true
	case catNetwork:
		cs.Network = true
	case catProcess:
		cs.Process = true
	case catCredentials:
		cs.Credentials = true
	}
}

// mismatches compares declarations with reachable behavior. A credential-plus-network mismatch
// emits one CRITICAL and suppresses its weaker component findings. Undeclared process execution
// starts LOW, contradicted process execution starts MEDIUM, and either rises to HIGH when
// undeclared network or credential access is also reachable.
func mismatches(cap graph.Capability, actual capSet, sawUnknown bool) []model.Finding {
	if !actual.any() {
		return nil
	}
	declared, contradicted := declaredCapabilities(cap.Description)
	local := claimsLocalOnly(cap.Description)

	undeclaredNetwork := actual.Network && !declared.Network
	undeclaredCredentials := actual.Credentials && !declared.Credentials
	undeclaredProcess := actual.Process && !declared.Process
	undeclaredFilesystem := actual.Filesystem && !declared.Filesystem

	var findings []model.Finding

	exfil := actual.Credentials && actual.Network && !(declared.Credentials && declared.Network)
	if exfil {
		findings = append(findings, mkFinding(cap, "behavioral.credential_exfiltration_mismatch",
			"handler reaches a credential source and makes an outbound network call; neither is fully declared",
			model.SeverityCritical, 0.9, actual, sawUnknown))
	} else {
		switch {
		case actual.Network && contradicted.Network:
			findings = append(findings, mkFinding(cap, "behavioral.contradicted_network",
				"description explicitly says the handler does not use the network, but it does",
				model.SeverityHigh, 0.85, actual, sawUnknown))
		case undeclaredNetwork && local:
			findings = append(findings, mkFinding(cap, "behavioral.undeclared_network",
				"description implies local-only behavior, but the handler reaches the network",
				model.SeverityHigh, 0.75, actual, sawUnknown))
		}
		switch {
		case actual.Credentials && contradicted.Credentials:
			findings = append(findings, mkFinding(cap, "behavioral.contradicted_credential_access",
				"description explicitly says the handler does not touch credentials, but it reaches a credential file or a credential-named environment variable",
				model.SeverityHigh, 0.85, actual, sawUnknown))
		case undeclaredCredentials:
			findings = append(findings, mkFinding(cap, "behavioral.undeclared_credential_access",
				"handler reaches a credential file or a credential-named environment variable not mentioned in its description",
				model.SeverityMedium, 0.7, actual, sawUnknown))
		}
	}

	if undeclaredProcess || (actual.Process && contradicted.Process) {
		severity, confidence := model.SeverityLow, 0.5
		ruleID := "behavioral.undeclared_process_execution"
		why := "handler executes an external process; its description does not mention that"
		if actual.Process && contradicted.Process {
			severity, confidence = model.SeverityMedium, 0.7
			ruleID = "behavioral.contradicted_process_execution"
			why = "description explicitly says the handler does not execute a process, but it does"
		}
		var also []string
		if undeclaredNetwork {
			also = append(also, "the network")
		}
		if undeclaredCredentials {
			also = append(also, "a credential source")
		}
		if len(also) > 0 {
			severity, confidence = model.SeverityHigh, 0.75
			why = fmt.Sprintf(
				"handler executes an external process and also reaches %s, with none of it declared; together this is a materially more capable handler than its description states",
				strings.Join(also, " and "))
		}
		findings = append(findings, mkFinding(cap, ruleID, why, severity, confidence, actual, sawUnknown))
	}

	switch {
	case actual.Filesystem && contradicted.Filesystem:
		findings = append(findings, mkFinding(cap, "behavioral.contradicted_filesystem_access",
			"description explicitly says the handler does not touch the filesystem, but it does",
			model.SeverityMedium, 0.7, actual, sawUnknown))
	case undeclaredFilesystem && local:
		findings = append(findings, mkFinding(cap, "behavioral.undeclared_filesystem_access",
			"description does not mention file access, but the handler reaches the filesystem",
			model.SeverityLow, 0.5, actual, sawUnknown))
	}
	return findings
}

func mkFinding(cap graph.Capability, ruleID, why string, severity model.Severity, confidence float64, actual capSet, sawUnknown bool) model.Finding {
	name := cap.Name
	if name == "" {
		name = cap.HandlerText
	}
	desc := fmt.Sprintf("%s %q: %s. Declared description: %q.", cap.Kind, name, why, cap.Description)
	if len(actual.SensitiveHits) > 0 {
		desc += fmt.Sprintf(" Sensitive path pattern(s) reached: %s.", strings.Join(actual.SensitiveHits, ", "))
	}
	if sawUnknown {
		desc += " The handler also crosses at least one unresolved call, so its full reachable behavior may be larger than what is reported here."
	}
	return model.Finding{
		RuleID:        ruleID,
		Category:      "behavioral_mismatch",
		Title:         fmt.Sprintf("%s %q behaves outside its declared description", cap.Kind, name),
		Severity:      severity,
		Confidence:    confidence,
		EvidenceLevel: model.EvidenceStatic,
		File:          cap.File,
		Line:          cap.Line,
		Tool:          name,
		Description:   desc,
		Evidence: []model.Evidence{{
			Level:       model.EvidenceStatic,
			Kind:        "capability_reachability",
			Description: why,
			File:        cap.File,
			Line:        cap.Line,
		}},
	}
}

func (*Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name:    "behavioral",
		Purpose: "Compares an MCP capability's declared description against what its handler statically reaches (filesystem, network, process, credentials), using a fixed vocabulary on both sides - no LLM.",
		Threats: []string{
			"a tool described as narrow or local-only whose handler reaches the network",
			"a handler that reads a credential file or a credential-named environment variable its description does not mention",
			"a handler that shells out to another process without saying so, especially alongside an undeclared network or credential reach",
			"a tool that reads project metadata but also reads ~/.ssh/id_rsa and sends it somewhere",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceStatic},
		Active:   false,
		Limitations: []string{
			"a capability whose handler cannot be resolved to a symbol - a bound method, a handler chosen at runtime, a value assembled from a table - is not compared against its description at all; it is reported as an unanalyzed capability, which downgrades the scan rather than passing",
			"the description side is fixed keyword matching, not language understanding: a paraphrase using none of the listed words is invisible to it",
			"the handler side is reachability, not a traced flow: it reports that a credential source and a network call are both reachable from the same handler, not that the credential's own value reaches that call",
			"a call reached only through an unresolved (external) function is invisible; the finding still fires on whatever was resolved, and notes that more may be reachable",
			"dynamic dispatch, reflection and generated code are invisible to a static call graph",
			"undeclared process execution alone is LOW: most honest descriptions say what a tool does, not that it runs a subprocess to do it, so the absence of a process word is weak evidence by itself. It rises to HIGH only alongside an undeclared network or credential reach",
			"reading an environment variable only counts as a credential access when the variable's own name looks credential-like (key/secret/token/password/credential/auth); reading DEBUG or PORT does not",
			"a description that explicitly denies a category (\"never touches the network\") is detected by looking for a fixed set of negator words within a few words of the category word, in the same sentence - not a grammatical parse, so a negation phrased unusually, or too far from the word it negates, reads as an ordinary (undeclared, not contradicted) mention instead",
			"the local-scope check reads a fixed, still-incomplete vocabulary (local/project/metadata/offline/workspace/machine/computer/device); a paraphrase using none of them (\"kept on this laptop\", say) is invisible to behavioral.undeclared_network and behavioral.undeclared_filesystem_access, though not to behavioral.contradicted_network, which does not depend on this list at all",
		},
	}
}
