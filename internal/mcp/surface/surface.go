// Package surface renders a snapshot's declared MCP capability surface - instructions,
// tools, prompts, resources, resource templates - as text for something that judges it (a
// model, a third-party classifier), stopping once a caller-supplied character budget is
// used. Keeping every capability kind here prevents callers from counting declarations they
// forgot to render.
package surface

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Formatters renders one capability of each kind as a surface entry. Every
// field must be set: Build calls whichever formatter a declared item needs,
// so a nil formatter panics on the first snapshot that declares that kind
// rather than silently skipping it.
type Formatters struct {
	Instructions func(text string) string
	Tool         func(t model.ToolInfo) string
	Prompt       func(p model.PromptInfo) string
	Resource     func(r model.ResourceInfo) string
	Template     func(t model.ResourceInfo) string
}

// Build renders snap's declared surface, adding entries first-fit until budget characters
// have been used: an entry that does not fit is skipped, but a later, shorter entry can
// still fit, so included/skipped is not "the first N" or "the last N" - just a count of
// what did and did not make it in
func Build(snap *model.Snapshot, budget int, f Formatters) (text string, included, skipped int) {
	var b strings.Builder
	used := 0
	add := func(entry string) bool {
		if used+len(entry) > budget {
			return false
		}
		b.WriteString(entry)
		used += len(entry)
		return true
	}
	count := func(ok bool) {
		if ok {
			included++
		} else {
			skipped++
		}
	}

	if snap.Instructions != "" {
		count(add(f.Instructions(snap.Instructions)))
	}
	for _, t := range snap.Tools {
		count(add(f.Tool(t)))
	}
	for _, p := range snap.Prompts {
		count(add(f.Prompt(p)))
	}
	for _, r := range snap.Resources {
		count(add(f.Resource(r)))
	}
	for _, t := range snap.Templates {
		count(add(f.Template(t)))
	}
	return b.String(), included, skipped
}

// CompactJSON renders v as single-line JSON for embedding in a surface
// entry, or "{}" for an empty or unmarshalable value. Every formatter that
// puts a schema, annotations or _meta block into an entry goes through
// this, so the two do not drift into rendering the same map differently.
func CompactJSON(v map[string]any) string {
	if len(v) == 0 {
		return "{}"
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// ToolExtras renders the parts of a tool declaration beyond name, description and input
// schema: output schema, annotations and _meta. These maps are as attacker-controlled as the
// description, so omitting them would judge less content than coverage claims was analyzed.
func ToolExtras(t model.ToolInfo) string {
	var b strings.Builder
	if len(t.OutputSchema) > 0 {
		fmt.Fprintf(&b, "output_schema: %s\n", CompactJSON(t.OutputSchema))
	}
	if len(t.Annotations) > 0 {
		fmt.Fprintf(&b, "annotations: %s\n", CompactJSON(t.Annotations))
	}
	if len(t.Meta) > 0 {
		fmt.Fprintf(&b, "meta: %s\n", CompactJSON(t.Meta))
	}
	return b.String()
}

// PromptArguments renders one line per declared prompt argument (name,
// whether it is required, and its description). An argument description is
// as much attacker-writable declared text as the prompt's own description
// or rendered body, so it belongs in the same surface.
func PromptArguments(args []model.PromptArgument) string {
	var b strings.Builder
	for _, a := range args {
		req := ""
		if a.Required {
			req = ", required"
		}
		fmt.Fprintf(&b, "argument %q%s: %s\n", a.Name, req, a.Description)
	}
	return b.String()
}

// ResourceIdentity renders a resource or template's URI (or URI template) and declared MIME
// type. The URI is often the most security-relevant field and must not disappear behind a
// friendly name or title.
func ResourceIdentity(r model.ResourceInfo) string {
	uri := r.URI
	if uri == "" {
		uri = r.URITemplate
	}
	var b strings.Builder
	if uri != "" {
		fmt.Fprintf(&b, "uri: %s\n", uri)
	}
	if r.MIMEType != "" {
		fmt.Fprintf(&b, "mime_type: %s\n", r.MIMEType)
	}
	return b.String()
}

// Locator is the pointer a finding on declared text carries instead of a file path: the
// capability kind, the capability's name unless it is the server itself, and the field
func Locator(capKind, capability, field string) string {
	if capability == "" {
		return capKind + "/" + field
	}
	return capKind + "/" + capability + "/" + field
}
