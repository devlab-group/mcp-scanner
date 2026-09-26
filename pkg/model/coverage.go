package model

import (
	"fmt"
	"slices"
)

// Coverage records what an analyzer actually looked at. It exists because
// "found nothing" and "looked at nothing" are indistinguishable without it,
// and only one of those is good news.
type Coverage struct {
	FilesDiscovered int `json:"files_discovered"`
	FilesParsed     int `json:"files_parsed"`
	FilesFailed     int `json:"files_failed"`
	FilesSkipped    int `json:"files_skipped"`

	SymbolsDiscovered   int `json:"symbols_discovered,omitempty"`
	FunctionsDiscovered int `json:"functions_discovered,omitempty"`

	CapabilitiesDiscovered int `json:"mcp_capabilities_discovered"`
	CapabilitiesAnalyzed   int `json:"mcp_capabilities_analyzed"`
	CapabilitiesSkipped    int `json:"mcp_capabilities_skipped"`

	// SkipReasons explains omissions. CapabilitiesSkipped means there was
	// nothing else to inspect, not that analysis failed; failed work stays
	// unaccounted so Gaps reports it.
	SkipReasons []string `json:"skip_reasons,omitempty"`

	// LimitsHit names any resource limit that stopped the analyzer early: a
	// file size cap, a file count cap, a pagination cap. A limit is the
	// scanner protecting itself, never an explanation of why some code is
	// safe, so any entry here is a gap.
	LimitsHit []string `json:"limits_hit,omitempty"`
}

// Merge builds an optimistic scan-level display by taking each counter's
// maximum. It may be internally inconsistent; verdicts use per-analyzer
// coverage instead.
func (c *Coverage) Merge(o Coverage) {
	c.FilesDiscovered = max(c.FilesDiscovered, o.FilesDiscovered)
	c.FilesParsed = max(c.FilesParsed, o.FilesParsed)
	c.FilesFailed = max(c.FilesFailed, o.FilesFailed)
	c.FilesSkipped = max(c.FilesSkipped, o.FilesSkipped)
	c.SymbolsDiscovered = max(c.SymbolsDiscovered, o.SymbolsDiscovered)
	c.FunctionsDiscovered = max(c.FunctionsDiscovered, o.FunctionsDiscovered)
	c.CapabilitiesDiscovered = max(c.CapabilitiesDiscovered, o.CapabilitiesDiscovered)
	c.CapabilitiesAnalyzed = max(c.CapabilitiesAnalyzed, o.CapabilitiesAnalyzed)
	c.CapabilitiesSkipped = max(c.CapabilitiesSkipped, o.CapabilitiesSkipped)
	for _, r := range o.SkipReasons {
		if !slices.Contains(c.SkipReasons, r) {
			c.SkipReasons = append(c.SkipReasons, r)
		}
	}
	for _, l := range o.LimitsHit {
		if !slices.Contains(c.LimitsHit, l) {
			c.LimitsHit = append(c.LimitsHit, l)
		}
	}
}

// Add accumulates coverage within a single analyzer, for example one pass per
// language or per package
func (c *Coverage) Add(o Coverage) {
	c.FilesDiscovered += o.FilesDiscovered
	c.FilesParsed += o.FilesParsed
	c.FilesFailed += o.FilesFailed
	c.FilesSkipped += o.FilesSkipped
	c.SymbolsDiscovered += o.SymbolsDiscovered
	c.FunctionsDiscovered += o.FunctionsDiscovered
	c.CapabilitiesDiscovered += o.CapabilitiesDiscovered
	c.CapabilitiesAnalyzed += o.CapabilitiesAnalyzed
	c.CapabilitiesSkipped += o.CapabilitiesSkipped
	c.SkipReasons = append(c.SkipReasons, o.SkipReasons...)
	c.LimitsHit = append(c.LimitsHit, o.LimitsHit...)
}

// AddSkipReason records reason unless it is already there, so a reason that applies to many
// files or capabilities appears once
func (c *Coverage) AddSkipReason(reason string) {
	if !slices.Contains(c.SkipReasons, reason) {
		c.SkipReasons = append(c.SkipReasons, reason)
	}
}

// Gaps lists coverage losses that prevent a complete result. An unexplained skip is a gap, and an
// analyzer that examined nothing cannot support a clean verdict. Any skip reason excuses both skip
// counts, but the zero-parsed-file and zero-analyzed-capability floors still apply.
func (c Coverage) Gaps() []string {
	var gaps []string
	// The floor under all the others. Every check below is guarded by a positive count, so an
	// empty record satisfies all of them: zero discovered balances zero analyzed, and an
	// analyzer that looked at nothing becomes indistinguishable from one that looked at
	// everything and found it clean - the collapse this package exists to prevent.
	if c.empty() {
		gaps = append(gaps, "the analyzer reported no coverage: nothing was discovered or examined")
	}
	// A coverage record that is about files and parsed none of them is a
	// gap no matter how well the arithmetic balances. Without this floor a
	// scan that excluded every file, or was pointed at the wrong directory,
	// adds up perfectly and reports a clean result.
	if c.FilesParsed == 0 && (c.FilesDiscovered > 0 || c.FilesSkipped > 0 || c.FilesFailed > 0) {
		gaps = append(gaps, "no file was parsed successfully")
	}
	if c.FilesFailed > 0 {
		gaps = append(gaps, fmt.Sprintf("%d file(s) failed to parse", c.FilesFailed))
	}
	if unaccounted := c.FilesDiscovered - c.FilesParsed - c.FilesFailed - c.FilesSkipped; unaccounted > 0 {
		gaps = append(gaps, fmt.Sprintf("%d discovered file(s) were never accounted for", unaccounted))
	}
	if c.FilesSkipped > 0 && len(c.SkipReasons) == 0 {
		gaps = append(gaps, fmt.Sprintf("%d file(s) skipped without a reason", c.FilesSkipped))
	}
	// The same floor for capabilities. An analyzer that skipped every tool it
	// found, with a reason for each, balances perfectly and has still told us
	// nothing about any of them.
	if c.CapabilitiesAnalyzed == 0 && c.CapabilitiesDiscovered > 0 {
		gaps = append(gaps, "no MCP capability was analyzed")
	}
	for _, l := range c.LimitsHit {
		gaps = append(gaps, "a scanner limit stopped the analysis early: "+l)
	}
	unanalyzed := c.CapabilitiesDiscovered - c.CapabilitiesAnalyzed - c.CapabilitiesSkipped
	if unanalyzed > 0 {
		gaps = append(gaps, fmt.Sprintf("%d MCP capability(ies) discovered but not analyzed", unanalyzed))
	}
	if c.CapabilitiesSkipped > 0 && len(c.SkipReasons) == 0 {
		gaps = append(gaps, fmt.Sprintf("%d MCP capability(ies) skipped without a reason", c.CapabilitiesSkipped))
	}
	return gaps
}

// empty reports whether the record says nothing about what was examined. Reasons, limits, symbols,
// and function counts may explain work or failure, but none proves that target content was covered.
func (c Coverage) empty() bool {
	return c.FilesDiscovered == 0 && c.FilesParsed == 0 && c.FilesFailed == 0 && c.FilesSkipped == 0 &&
		c.CapabilitiesDiscovered == 0 && c.CapabilitiesAnalyzed == 0 && c.CapabilitiesSkipped == 0
}

// Complete reports whether coverage accounting adds up
func (c Coverage) Complete() bool { return len(c.Gaps()) == 0 }
