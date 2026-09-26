// Package snapshot canonicalizes, hashes, compares, saves, and loads snapshots
package snapshot

import (
	"encoding/json"
	"sort"

	"github.com/revinand/mcp-scanner/pkg/model"
)

// Canonical returns JSON with tools, prompts, resources, templates, warnings, and map keys sorted.
// Ordering inside other slices remains significant, so this is deterministic only for the fields
// normalized by sortedCopy and encoding/json.
func Canonical(s *model.Snapshot) ([]byte, error) {
	c := sortedCopy(s)
	return json.Marshal(c)
}

// sortedCopy sorts copied slices without changing the caller's snapshot
func sortedCopy(s *model.Snapshot) *model.Snapshot {
	if s == nil {
		return nil
	}
	c := *s

	c.Tools = append([]model.ToolInfo(nil), s.Tools...)
	sort.Slice(c.Tools, func(i, j int) bool { return c.Tools[i].Name < c.Tools[j].Name })

	c.Prompts = append([]model.PromptInfo(nil), s.Prompts...)
	sort.Slice(c.Prompts, func(i, j int) bool { return c.Prompts[i].Name < c.Prompts[j].Name })

	c.Resources = append([]model.ResourceInfo(nil), s.Resources...)
	sort.Slice(c.Resources, func(i, j int) bool { return c.Resources[i].URI < c.Resources[j].URI })

	c.Templates = append([]model.ResourceInfo(nil), s.Templates...)
	sort.Slice(c.Templates, func(i, j int) bool { return c.Templates[i].URITemplate < c.Templates[j].URITemplate })

	c.Warnings = append([]string(nil), s.Warnings...)
	sort.Strings(c.Warnings)

	return &c
}
