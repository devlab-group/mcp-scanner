// Package protocol checks MCP conformance from a snapshot. It also runs safe
// active probes when the scan has a live session and permits them.
package protocol

import (
	"context"

	"github.com/devlab-group/mcp-scanner/internal/mcp/snapshot"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Name is the analyzer's registered identifier
const Name = "protocol"

func init() {
	analyzer.Register(protocolAnalyzer{})
}

type protocolAnalyzer struct{}

func (protocolAnalyzer) Name() string { return Name }

// AppliesTo accepts live and saved snapshots. Source, package, and config
// targets do not provide the protocol data this analyzer needs.
func (protocolAnalyzer) AppliesTo(kind model.TargetKind) bool {
	switch kind {
	case model.TargetRemote, model.TargetStdio, model.TargetStatic:
		return true
	default:
		return false
	}
}

func (protocolAnalyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	if ac == nil || ac.Snapshot == nil {
		return model.Skipped(Name, "no snapshot available to analyze")
	}
	snap := ac.Snapshot

	var findings []model.Finding
	findings = append(findings, checkProtocolVersion(snap)...)
	findings = append(findings, checkCapabilityMismatchPassive(snap)...)
	findings = append(findings, checkToolMetadata(snap)...)
	findings = append(findings, checkAnnotationConflicts(snap)...)
	findings = append(findings, checkResourceURIs(snap)...)
	findings = append(findings, checkNameCollisions(snap)...)
	findings = append(findings, checkInstructions(snap)...)
	findings = append(findings, checkCrossOriginRedirect(snap)...)

	res := model.AnalyzerResult{
		Analyzer: Name,
		Status:   model.AnalyzerCompleted,
		Findings: findings,
		Coverage: capabilityCoverage(snap),
	}

	canProbe := ac.Probes.AtLeast(analyzer.ProbeSafe) && ac.Session != nil
	switch {
	case canProbe:
		probeFindings, warnings, complete := runActiveProbes(ctx, target, ac)
		res.Findings = append(res.Findings, probeFindings...)
		res.Warnings = append(res.Warnings, warnings...)
		if !complete {
			res.Status = model.AnalyzerPartial
			res.Warnings = append(res.Warnings, "one or more active probes did not complete")
		}
	case ac.Session == nil:
		res.Warnings = append(res.Warnings, "active probes skipped: no live session (static target or offline scan)")
	default:
		res.Warnings = append(res.Warnings, "active probes skipped: probe level below safe")
	}

	if ctx.Err() != nil && res.Status == model.AnalyzerCompleted {
		res.Status = model.AnalyzerPartial
		res.Warnings = append(res.Warnings, "analyzer deadline reached before it finished")
	}

	return res
}

// capabilityCoverage marks every capability retained in the snapshot as analyzed because each
// passive check walks the full retained surface. Any remaining shortfall comes from discovery
// truncation and must stay visible in the merged coverage.
func capabilityCoverage(snap *model.Snapshot) model.Coverage {
	cov := snapshot.CapabilityCoverage(snap)
	cov.CapabilitiesAnalyzed = snap.CapabilityCount()
	return cov
}
