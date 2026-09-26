package protocol

import "github.com/revinand/mcp-scanner/pkg/model"

// newFinding sets the fields shared by protocol findings. Callers must provide
// evidence because model.Finding.Validate rejects an empty list.
func newFinding(rule, category, title string, sev model.Severity, level model.EvidenceLevel, confidence float64, tool, description string, evidence ...model.Evidence) model.Finding {
	return model.Finding{
		RuleID:        rule,
		Category:      category,
		Title:         title,
		Severity:      sev,
		Confidence:    confidence,
		EvidenceLevel: level,
		Tool:          tool,
		Description:   description,
		Evidence:      evidence,
		Analyzer:      Name,
	}
}

func evidence(kind, description string) model.Evidence {
	return model.Evidence{Level: model.EvidenceStatic, Kind: kind, Description: description}
}

func protocolEvidence(kind, description string, data map[string]any) model.Evidence {
	return model.Evidence{Level: model.EvidenceProtocol, Kind: kind, Description: description, Data: data}
}
