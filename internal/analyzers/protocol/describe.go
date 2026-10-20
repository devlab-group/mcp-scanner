package protocol

import (
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func (protocolAnalyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name:    Name,
		Purpose: "Checks protocol conformance from a snapshot. With a live session and safe probes enabled, it also tests malformed and unsupported requests.",
		Threats: []string{
			"tool_poisoning", "protocol_conformance", "information_disclosure", "prompt_injection",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceStatic, model.EvidenceHeuristic, model.EvidenceProtocol},
		Active:   true,
		Limitations: []string{
			"passive checks only see what discovery recorded",
			"detecting an unadvertised capability requires an active probe; offline scans can only detect advertised capabilities that failed",
			"active probes require a live session and --active-probes=safe or higher",
			"internal-data leak detection matches a limited set of stack-frame and absolute-path patterns",
		},
	}
}
