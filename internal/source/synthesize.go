package source

import (
	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// SynthesizeCoverageKey lets snapshot consumers include unresolved source
// declarations in their coverage. The caller publishes the value.
const SynthesizeCoverageKey = "source.synthesize_coverage"

// Synthesize builds a Snapshot from discovered capabilities so analyzers that
// read declared text can run against a source tree. The returned coverage records
// unresolved names or descriptions as reasoned skips; prompt defense later
// converts unresolved fields into an analyzed-count gap.
func Synthesize(g *graph.Graph) (*model.Snapshot, model.Coverage) {
	snap := &model.Snapshot{
		SchemaVersion: model.SchemaVersion,
		Transport:     model.TransportInfo{Kind: model.TransportSource},
	}
	cov := model.Coverage{CapabilitiesDiscovered: len(g.Capabilities)}

	for _, c := range g.Capabilities {
		name := displayName(c)
		switch c.Kind {
		case graph.CapabilityTool:
			snap.Tools = append(snap.Tools, model.ToolInfo{Name: name, Description: c.Description})
		case graph.CapabilityPrompt:
			snap.Prompts = append(snap.Prompts, model.PromptInfo{Name: name, Description: c.Description})
		case graph.CapabilityResource:
			// promptdefense keys a resource's finding location and LimitsHit entry off URI/URITemplate,
			// not Name - a resource registered by URI (@mcp.resource("docs://a", ...)) needs that
			// identifier carried across, or two poisoned resources in one file report as textually
			// identical, unlocatable findings
			snap.Resources = append(snap.Resources, model.ResourceInfo{URI: name, Name: name, Description: c.Description})
		}

		// A capability included with an empty or partial description would read, to an analyzer
		// downstream, as a tool that simply has nothing to say - indistinguishable from one whose
		// description genuinely resolved to ""
		switch {
		case c.NameResolved && c.DescriptionResolved:
			cov.CapabilitiesAnalyzed++
		case !c.NameResolved && !c.DescriptionResolved:
			cov.CapabilitiesSkipped++
			cov.AddSkipReason("capability name and description could not be resolved statically")
		case !c.NameResolved:
			cov.CapabilitiesSkipped++
			cov.AddSkipReason("capability name could not be resolved statically")
		default:
			cov.CapabilitiesSkipped++
			cov.AddSkipReason("capability description could not be resolved statically")
		}
	}
	return snap, cov
}
