// Package yara scans text an MCP server declares - tool and prompt descriptions, prompt text,
// resource contents, and server instructions - against YARA signatures. The engine is optional at
// build time; a build without it reports the analyzer unavailable instead of silently skipping it.
package yara

import (
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

const analyzerName = "yara"

// Interface satisfaction is otherwise only checked by a runtime type
// assertion (Applicable, Describer are both optional), so a signature typo
// here would silently drop the method instead of failing to build. Analyze
// itself is provided by whichever of yara_enabled.go / yara_disabled.go the
// build tag selects, so it is asserted there instead of here.
var (
	_ analyzer.Applicable = (*Analyzer)(nil)
	_ analyzer.Describer  = (*Analyzer)(nil)
)

func init() {
	analyzer.Register(&Analyzer{})
}

// Analyzer's Analyze method is provided by yara_enabled.go or
// yara_disabled.go depending on the build tag; exactly one of them compiles
// into any given build, so there is never a duplicate method definition
type Analyzer struct{}

func (a *Analyzer) Name() string { return analyzerName }

// AppliesTo is every target kind: it only reads the snapshot
func (a *Analyzer) AppliesTo(model.TargetKind) bool { return true }

func (a *Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name: analyzerName,
		Purpose: "Matches YARA signatures against the text an MCP server declares: tool and " +
			"prompt descriptions, prompt text, resource contents and server instructions.",
		Threats: []string{
			"whatever the loaded rule set targets - signature-based detection of known " +
				"malicious strings, encoded payloads or tool-poisoning phrasing",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceStatic},
		Active:   false,
		Limitations: []string{
			"only as good as the loaded rule set; it cannot flag something no rule describes",
			"a build without the yara tag has no rule engine at all and reports UNAVAILABLE",
			"regex/string signatures can miss obfuscated or split-across-fields content",
		},
	}
}
