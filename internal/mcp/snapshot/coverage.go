package snapshot

import (
	"fmt"
	"slices"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/mcp/discovery"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// CapabilityCoverage converts snapshot truncation into coverage. Known missing
// counts balance as skips; unknown counts and scanner limits remain gaps. The
// caller supplies CapabilitiesAnalyzed. An unknown shortfall deliberately leaves the arithmetic
// unbalanced so a snapshot of uncertain completeness cannot support a clean verdict.
func CapabilityCoverage(snap *model.Snapshot) model.Coverage {
	if snap == nil {
		return model.Coverage{}
	}
	read := snap.CapabilityCount()
	skipped := 0
	unknownGaps := 0
	var skipReasons []string
	var limitsHit []string

	for _, t := range snap.Truncated {
		if t.Unknown {
			unknownGaps++
			skipReasons = append(skipReasons, fmt.Sprintf("%s: %s (an unknown number of items were not read)", t.Method, t.Reason))
			if strings.HasPrefix(t.Reason, discovery.LimitHitReason) {
				limitsHit = append(limitsHit, fmt.Sprintf("%s %s", t.Method, t.Reason))
			}
			continue
		}
		skipped += t.Missed
		skipReasons = append(skipReasons, fmt.Sprintf("%s: %s (%d item(s) not read)", t.Method, t.Reason, t.Missed))
	}

	// Truncated bodies were partly analyzed, so record limits rather than skips
	for _, r := range snap.Resources {
		if r.ContentTruncated {
			limitsHit = append(limitsHit, fmt.Sprintf(
				"resource %q: the body was cut at the scanner's per-resource cap and the rest was not analyzed",
				orURI(r.Name, r.URI)))
		}
	}
	for _, p := range snap.Prompts {
		if p.TextTruncated {
			limitsHit = append(limitsHit, fmt.Sprintf(
				"prompt %q: the rendered text was cut at the scanner's per-prompt cap and the rest was not analyzed", p.Name))
		}
	}

	return model.Coverage{
		CapabilitiesDiscovered: read + skipped + unknownGaps,
		CapabilitiesSkipped:    skipped,
		SkipReasons:            skipReasons,
		LimitsHit:              limitsHit,
	}
}

// FoldCapabilityCoverage merges what the snapshot knows about its own truncation into an
// analyzer's own coverage record, the way source.FoldWalkCoverage does for a file walk. It
// raises discovered and skipped counts without overwriting what the analyzer actually examined.
func FoldCapabilityCoverage(snap *model.Snapshot, cov model.Coverage) model.Coverage {
	tc := CapabilityCoverage(snap)
	cov.CapabilitiesDiscovered = max(cov.CapabilitiesDiscovered, tc.CapabilitiesDiscovered)
	cov.CapabilitiesSkipped = max(cov.CapabilitiesSkipped, tc.CapabilitiesSkipped)
	for _, r := range tc.SkipReasons {
		if !slices.Contains(cov.SkipReasons, r) {
			cov.SkipReasons = append(cov.SkipReasons, r)
		}
	}
	for _, l := range tc.LimitsHit {
		if !slices.Contains(cov.LimitsHit, l) {
			cov.LimitsHit = append(cov.LimitsHit, l)
		}
	}
	return cov
}

// orURI names a resource the way a reader would look for it: by name when
// it has one, and by URI when it does not
func orURI(name, uri string) string {
	if name != "" {
		return name
	}
	return uri
}
