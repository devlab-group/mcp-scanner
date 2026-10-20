package promptdefense

import (
	"fmt"
	"maps"
	"slices"

	"github.com/devlab-group/mcp-scanner/internal/mcp/surface"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// unit is one piece of declared text pulled from a snapshot, scoped to the
// capability it came from so a finding can point back at it
type unit struct {
	text string
	// field names the part of the capability this text came from, e.g.
	// "name", "title", "description", "text", or "argument:<name>" for a
	// prompt argument
	field string
	// capKind is "server", "tool", "prompt", "resource" or
	// "resource_template"
	capKind string
	// capability is the tool/prompt/resource name. Empty for the server
	// itself.
	capability string

	// annotations and inputSchema are only set on a tool's "description"
	// unit; they carry what conflicting_metadata and
	// oversized_description need without a second pass over the snapshot
	annotations map[string]any
	inputSchema map[string]any
}

// locator is the human-readable pointer a Finding.File uses when there is
// no filesystem path: which declared capability and field the text came
// from
func (u unit) locator() string {
	return surface.Locator(u.capKind, u.capability, u.field)
}

// extract returns scannable snapshot text and capability coverage. Missing
// unfetched bodies are limits; source-generated bodies are explained skips.
// Tool schemas, annotations, and _meta share one bounded unit budget. targetKind
// must describe the current scan because replayed snapshots retain their original
// transport.
func extract(snap *model.Snapshot, targetKind model.TargetKind) (units []unit, discovered, analyzed, skipped int, skipReasons, limitsHit []string) {
	if snap == nil {
		return nil, 0, 0, 0, nil, nil
	}

	// Server identity can reach the model through client namespacing
	serverText := false
	for _, f := range []struct{ field, text string }{
		{"instructions", snap.Instructions},
		{"server_name", snap.ServerName},
		{"server_title", snap.ServerTitle},
		{"server_version", snap.ServerVersion},
	} {
		if f.text == "" {
			continue
		}
		units = append(units, unit{text: f.text, field: f.field, capKind: "server"})
		serverText = true
	}
	if serverText {
		discovered++
		analyzed++
	}

	for _, t := range snap.Tools {
		discovered++
		any := false
		if t.Name != "" {
			units = append(units, unit{text: t.Name, field: "name", capKind: "tool", capability: t.Name})
			any = true
		}
		if t.Title != "" {
			units = append(units, unit{text: t.Title, field: "title", capKind: "tool", capability: t.Name})
			any = true
		}
		if t.Description != "" {
			units = append(units, unit{
				text: t.Description, field: "description", capKind: "tool", capability: t.Name,
				annotations: t.Annotations, inputSchema: t.InputSchema,
			})
			any = true
		}
		budget := schemaUnitBudget
		for _, surface := range jsonSurfacesOf(t) {
			if len(surface.body) == 0 {
				continue
			}
			surfaceUnits, limit := extractStringLeafUnits(surface.body, t.Name, surface.prefix, &budget)
			units = append(units, surfaceUnits...)
			if len(surfaceUnits) > 0 {
				any = true
			}
			if limit != "" {
				limitsHit = append(limitsHit, limit)
			}
		}

		if any {
			analyzed++
		} else {
			skipped++
			skipReasons = append(skipReasons, fmt.Sprintf("tool %q has no name, title or description to analyze", t.Name))
		}
	}

	for _, p := range snap.Prompts {
		discovered++
		any := false
		if p.Name != "" {
			units = append(units, unit{text: p.Name, field: "name", capKind: "prompt", capability: p.Name})
			any = true
		}
		if p.Title != "" {
			units = append(units, unit{text: p.Title, field: "title", capKind: "prompt", capability: p.Name})
			any = true
		}
		if p.Description != "" {
			units = append(units, unit{text: p.Description, field: "description", capKind: "prompt", capability: p.Name})
			any = true
		}
		for _, a := range p.Arguments {
			// The argument name is rendered as the form the user fills in,
			// so it reaches the model and the reader the same way its
			// description does
			if a.Name != "" {
				units = append(units, unit{text: a.Name, field: "argument-name:" + a.Name, capKind: "prompt", capability: p.Name})
				any = true
			}
			if a.Description != "" {
				units = append(units, unit{text: a.Description, field: "argument:" + a.Name, capKind: "prompt", capability: p.Name})
				any = true
			}
		}
		hadOther := any
		if p.Text != "" {
			units = append(units, unit{text: p.Text, field: "text", capKind: "prompt", capability: p.Name})
			any = true
		}
		switch {
		case p.Rendered || p.Text != "":
			// prompts/get succeeded, whatever text came back - including
			// "". Text alone cannot tell that apart from "nobody asked":
			// Rendered can, and a non-empty Text is kept as a fallback so an
			// older snapshot serialized before Rendered existed still
			// reads correctly here, the same way it always has.
			analyzed++
		case hadOther && p.RenderError != "":
			// prompts/get was attempted and the server refused - a prompt
			// declaring a required argument the scanner has no value for is
			// ordinary, spec-conformant behaviour, not evasion, and it must
			// read differently from a prompt nobody asked to fetch at all
			limitsHit = append(limitsHit, fmt.Sprintf(
				"prompt %q: the server could not render it (%s), only its declared name and description were analyzed",
				p.Name, p.RenderError))
		case hadOther && (targetKind == model.TargetSource || targetKind == model.TargetPackage):
			// A prompt's rendered text in a source tree is produced by a
			// function at call time and does not exist as static text:
			// there is nothing to fetch and no flag closes this, the same
			// situation readiness already handles as a skip rather than a
			// downgrade
			skipped++
			skipReasons = append(skipReasons, fmt.Sprintf(
				"prompt %q: declared name and description were analyzed; rendered text is "+
					"produced at call time and does not exist in a source tree", p.Name))
		case hadOther:
			// The name, title and/or description above were added to
			// units and are scanned normally, so the declared text
			// genuinely was analyzed; what is missing is the rendered
			// text, which stays a gap through limitsHit on its own - a
			// skip reason would satisfy Coverage.Gaps()'s "skipped
			// without a reason" check while the real gap lives here
			// instead, which would read as self-contradicting
			analyzed++
			limitsHit = append(limitsHit, fmt.Sprintf(
				"prompt %q: rendered text was not fetched, only its declared name and description were analyzed; %s",
				p.Name, fetchAdvice(targetKind, "--get-prompts")))
		default:
			skipped++
			skipReasons = append(skipReasons, fmt.Sprintf("prompt %q has no name, title, description or text to analyze", p.Name))
		}
	}

	scanResource := func(kind string, r model.ResourceInfo) {
		discovered++
		id := r.URI
		if id == "" {
			id = r.URITemplate
		}
		any := false
		// resources/list hands the model the URI and the MIME type
		// alongside the name, so a payload placed in one of them is read
		// exactly like a payload in the other
		for _, f := range []struct{ field, text string }{
			{"uri", r.URI},
			{"uri_template", r.URITemplate},
			{"mime_type", r.MIMEType},
		} {
			if f.text == "" {
				continue
			}
			units = append(units, unit{text: f.text, field: f.field, capKind: kind, capability: id})
			any = true
		}
		if r.Name != "" {
			units = append(units, unit{text: r.Name, field: "name", capKind: kind, capability: id})
			any = true
		}
		if r.Title != "" {
			units = append(units, unit{text: r.Title, field: "title", capKind: kind, capability: id})
			any = true
		}
		if r.Description != "" {
			units = append(units, unit{text: r.Description, field: "description", capKind: kind, capability: id})
			any = true
		}
		hadOther := any
		if r.Content != "" {
			units = append(units, unit{text: r.Content, field: "content", capKind: kind, capability: id})
			any = true
		}
		switch {
		case r.Fetched || r.Content != "":
			// resources/read succeeded, whatever content came back -
			// including "". Same reasoning as the prompt case above:
			// Fetched tells an empty body apart from a fetch that never
			// ran, and a non-empty Content is kept as a fallback for a
			// snapshot serialized before Fetched existed.
			analyzed++
		case r.ReadError != "":
			// resources/read was attempted but produced no analyzable text: either the transport
			// failed or discovery declined to decode a binary body
			if hadOther {
				analyzed++
			}
			limitsHit = append(limitsHit, fmt.Sprintf(
				"%s %q: content could not be read (%s), only its declared name and description were analyzed",
				kind, id, r.ReadError))
		case hadOther && (targetKind == model.TargetSource || targetKind == model.TargetPackage):
			// A resource body in a source tree is produced by a function
			// at call time and does not exist as static text: there is
			// nothing to fetch and no flag closes this, the same
			// situation readiness already handles as a skip rather than
			// a downgrade
			skipped++
			skipReasons = append(skipReasons, fmt.Sprintf(
				"%s %q: declared name and description were analyzed; a resource body is "+
					"produced at call time and does not exist in a source tree", kind, id))
		case hadOther:
			// The name or description above was scanned, but that does not cover content hidden in
			// the missing body
			analyzed++
			limitsHit = append(limitsHit, fmt.Sprintf(
				"%s %q: content was not fetched, only its declared name and description were analyzed; %s",
				kind, id, fetchAdvice(targetKind, "--read-resources")))
		default:
			skipped++
			skipReasons = append(skipReasons, fmt.Sprintf("%s %q has no description and its content was not fetched", kind, id))
		}
	}
	for _, r := range snap.Resources {
		scanResource("resource", r)
	}
	for _, r := range snap.Templates {
		scanResource("resource_template", r)
	}

	return expandUnits(units), discovered, analyzed, skipped, skipReasons, limitsHit
}

// fetchAdvice says how an operator would get the body a resource or prompt limitsHit entry
// names, branched on this scan's own target kind - not on snap.Transport.Kind, which
// describes how the snapshot was captured, not whether this run has a session to fetch
// from
func fetchAdvice(targetKind model.TargetKind, flag string) string {
	if targetKind == model.TargetStatic {
		// Naming the capture command keeps the operator's own workflow:
		// whoever scans a snapshot usually has a reason to, and telling
		// them to go scan the live server instead throws that away when
		// re-capturing with the flag closes the gap and leaves them
		// holding a snapshot again
		return fmt.Sprintf("not available from a static snapshot; re-capture it with `mcp-scanner snapshot %s`, or scan the live server directly with %s", flag, flag)
	}
	return fmt.Sprintf("run with %s to include the body", flag)
}

// schemaUnitBudget bounds how many described units a single tool can add across its input schema,
// output schema, annotations, and _meta combined. The shared cap prevents a hostile declaration
// from multiplying the budget by spreading content across all four fields.
const schemaUnitBudget = 200

// schemaMaxDepth bounds how far extractStringLeafUnits recurses into
// properties, items, $defs/definitions or nested _meta values.
// Same reasoning as schemaUnitBudget: nesting depth is attacker-controlled
// JSON, not a property of what the tool actually needs to describe.
const schemaMaxDepth = 8

func joinSchemaPath(path, next string) string {
	if path == "" {
		return next
	}
	return path + "." + next
}

// jsonSurface is one free-form JSON object declared alongside a tool.
type jsonSurface struct {
	prefix string
	body   map[string]any
}

// jsonSurfacesOf lists every such object a client can render into the
// model's context, in the order their units are produced
func jsonSurfacesOf(t model.ToolInfo) []jsonSurface {
	return []jsonSurface{
		{"input_schema", t.InputSchema},
		{"output_schema", t.OutputSchema},
		{"meta", t.Meta},
		{"annotation", t.Annotations},
	}
}

// extractStringLeafUnits walks an arbitrary decoded-JSON object attached to a tool - its
// input or output schema, its _meta, its annotations - and returns one unit per string
// leaf, at whatever depth it sits
func extractStringLeafUnits(meta map[string]any, capability, prefix string, budget *int) (units []unit, limit string) {
	var walk func(v any, path string, depth int)
	walk = func(v any, path string, depth int) {
		if limit != "" {
			return
		}
		if depth > schemaMaxDepth {
			limit = fmt.Sprintf("tool %q: %s nests past %d levels, the rest was not scanned", capability, prefix, schemaMaxDepth)
			return
		}
		switch val := v.(type) {
		case string:
			if val == "" {
				return
			}
			if *budget <= 0 {
				limit = fmt.Sprintf("tool %q: declared schemas, metadata and annotations carry more than %d strings combined, the rest was not scanned", capability, schemaUnitBudget)
				return
			}
			units = append(units, unit{text: val, field: prefix + ":" + path, capKind: "tool", capability: capability})
			*budget--
		case map[string]any:
			for _, k := range slices.Sorted(maps.Keys(val)) {
				walk(val[k], joinSchemaPath(path, k), depth+1)
				if limit != "" {
					return
				}
			}
		case []any:
			for i, item := range val {
				walk(item, fmt.Sprintf("%s[%d]", path, i), depth+1)
				if limit != "" {
					return
				}
			}
		}
	}
	for _, k := range slices.Sorted(maps.Keys(meta)) {
		walk(meta[k], k, 0)
		if limit != "" {
			break
		}
	}
	return units, limit
}

// expandUnits adds the synthetic units the rules are run over in addition to the declared
// text itself: the decoded contents of any hidden-tag run or base64 blob, and a normalized
// fold of anything spelled in something other than plain ASCII (see normalize.go)
func expandUnits(units []unit) []unit {
	out := units
	for _, u := range units {
		for _, decoded := range decodeTagRuns(u.text) {
			out = append(out, unit{
				text: decoded, field: u.field + ":hidden-tag-decoded",
				capKind: u.capKind, capability: u.capability,
			})
		}
	}
	for _, u := range slices.Clip(out) {
		for _, decoded := range decodeBase64Runs(u.text) {
			out = append(out, unit{
				text: decoded, field: u.field + ":base64-decoded",
				capKind: u.capKind, capability: u.capability,
			})
		}
	}
	// Normalization runs over the decoded units too: hidden text carries
	// whatever spelling its author chose, same as visible text
	for _, u := range slices.Clip(out) {
		folded, changed := normalizeForMatching(u.text)
		if !changed {
			continue
		}
		out = append(out, unit{
			text: folded, field: u.field + ":normalized",
			capKind: u.capKind, capability: u.capability,
			annotations: u.annotations, inputSchema: u.inputSchema,
		})
	}
	return out
}

// syntheticFieldSuffixes are the markers expandUnits appends to a field
// name. A finding from one of these describes the same text as a finding
// from the field itself, so the report shows it once.
var syntheticFieldSuffixes = []string{":hidden-tag-decoded", ":base64-decoded", ":normalized"}
