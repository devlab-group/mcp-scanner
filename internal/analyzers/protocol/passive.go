package protocol

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/revinand/mcp-scanner/internal/mcp/discovery"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// Passive checks look only at a model.Snapshot, so they run for a live
// target and a static/replayed one alike

var knownProtocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
	"2025-11-25": true,
	"2026-07-28": true,
}

var dateShaped = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func checkProtocolVersion(snap *model.Snapshot) []model.Finding {
	v := snap.ProtocolVersion
	if v == "" {
		return []model.Finding{newFinding(
			RuleVersionMissing, "protocol_conformance", "Protocol version not recorded",
			model.SeverityMedium, model.EvidenceStatic, 0.8, "",
			"The snapshot has no protocol version, so it is impossible to tell which MCP revision the server speaks.",
			evidence("missing_field", "protocol_version is empty"),
		)}
	}
	if knownProtocolVersions[v] {
		return nil
	}
	sev, conf := model.SeverityMedium, 0.6
	desc := fmt.Sprintf("Protocol version %q is not a recognized MCP revision.", v)
	if dateShaped.MatchString(v) {
		// Shaped like a version, just not one this build knows about yet -
		// most likely newer than this scanner, not necessarily wrong
		sev, conf = model.SeverityLow, 0.4
		desc = fmt.Sprintf("Protocol version %q is date-shaped but not in this scanner's known list; it may be newer than this build supports.", v)
	}
	return []model.Finding{newFinding(
		RuleVersionUnknown, "protocol_conformance", "Unrecognized protocol version",
		sev, model.EvidenceStatic, conf, "", desc,
		evidence("protocol_version", v),
	)}
}

// capabilityListMethods maps a list method name back to the capability
// recordListFailure associates it with, in internal/mcp/discovery. It is
// the same association discovery itself used when it wrote the Truncation
// this check reads.
var capabilityListMethods = map[string]string{
	"tools/list":               "tools",
	"prompts/list":             "prompts",
	"resources/list":           "resources",
	"resources/templates/list": "resources",
}

// checkCapabilityMismatchPassive flags a capability the server advertised in initialize
// whose list call then failed outright, using the typed Truncation record discovery already
// wrote rather than matching a sentence in snap.Warnings: a server puts arbitrary text into
// a failed call's error message, so pattern-matching Warnings would let it dictate this
// finding by choosing its wording
func checkCapabilityMismatchPassive(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, t := range snap.Truncated {
		capability, known := capabilityListMethods[t.Method]
		if !known || !t.Unknown || t.Read != 0 || strings.HasPrefix(t.Reason, discovery.LimitHitReason) {
			continue
		}
		findings = append(findings, newFinding(
			RuleCapabilityMismatch, "protocol_conformance", "Advertised capability failed to answer",
			model.SeverityMedium, model.EvidenceStatic, 0.7, "",
			fmt.Sprintf("The server advertised the %s capability but %s failed: %s", capability, t.Method, t.Reason),
			evidence("truncation", t.Reason),
		))
	}
	return findings
}

// checkCrossOriginRedirect flags a cross-origin redirect the scanner's transport refused to
// follow, reading model.Snapshot.RedirectsRefused rather than matching a marker phrase in
// snap.Warnings: that phrase could also appear inside a server-controlled error message
// landing in Warnings from an unrelated failed call, which would forge this finding for a
// redirect that was never attempted
func checkCrossOriginRedirect(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, note := range snap.RedirectsRefused {
		findings = append(findings, newFinding(
			RuleCrossOriginRedirect, "credential_exposure", "Server attempted a cross-origin redirect",
			model.SeverityHigh, model.EvidenceStatic, 0.8, "",
			"The server tried to redirect the connection to a different origin. A conformant MCP endpoint has no reason to do this; following it would have carried the operator's headers, including any bearer token, to that origin. The scanner refused the redirect.",
			evidence("redirect_refused", note),
		))
	}
	return findings
}

var validNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

// sensitiveArgNames flags execution-shaped arguments that contradict readOnlyHint. Ordinary
// path, file, URL, and query arguments are excluded because read-only tools commonly accept them.
var sensitiveArgNames = []string{
	"command", "cmd", "shell", "exec", "execute", "script", "eval",
}

// isSensitiveArgName checks name for one of sensitiveArgNames as a whole word, not a
// substring: splitIdentifierWords breaks it into words on '_', '-' and a camelCase
// transition, and mentionsWord does the same whole-word check already used for description
// text
func isSensitiveArgName(name string) bool {
	words := splitIdentifierWords(name)
	for _, s := range sensitiveArgNames {
		if mentionsWord(words, s) {
			return true
		}
	}
	return false
}

// splitIdentifierWords rewrites an identifier as its words, lowercased and
// space-separated, splitting on '_', '-' and a camelCase transition
// (aB -> "a b"). The result can be checked with mentionsWord exactly as
// description text already is, rather than a second word-matching scheme.
func splitIdentifierWords(name string) string {
	var b strings.Builder
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-':
			b.WriteByte(' ')
			continue
		case i > 0 && r >= 'A' && r <= 'Z' && !(runes[i-1] >= 'A' && runes[i-1] <= 'Z'):
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

// checkToolMetadata covers name charset and uniqueness, missing
// descriptions, and schema shape problems: absent/non-object schemas, and a
// required list that disagrees with either properties or the description
// text
func checkToolMetadata(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	seen := map[string]bool{}

	for _, t := range snap.Tools {
		if seen[t.Name] {
			findings = append(findings, newFinding(
				RuleNameDuplicate, "protocol_conformance", "Duplicate tool name",
				model.SeverityMedium, model.EvidenceStatic, 0.9, t.Name,
				fmt.Sprintf("More than one tool is named %q; a client cannot tell them apart.", t.Name),
				evidence("tool_name", t.Name),
			))
		}
		seen[t.Name] = true

		// This fires on anything outside [A-Za-z0-9_.-], which includes a raw control character but
		// also an ordinary non-English name, an emoji, or a space - mostly a hygiene problem
		// (log/cache key handling, shell quoting), not deception, so LOW is right for it
		if !validNamePattern.MatchString(t.Name) {
			findings = append(findings, newFinding(
				RuleNameCharset, "protocol_conformance", "Tool name uses an unsafe character set",
				model.SeverityLow, model.EvidenceStatic, 0.6, t.Name,
				fmt.Sprintf("Tool name %q contains characters outside [A-Za-z0-9_.-]; some hosts mishandle it (path traversal in log/cache keys, shell quoting).", t.Name),
				evidence("tool_name", t.Name),
			))
		}

		if strings.TrimSpace(t.Description) == "" {
			findings = append(findings, newFinding(
				RuleMissingDescription, "protocol_conformance", "Tool has no description",
				model.SeverityLow, model.EvidenceStatic, 0.7, t.Name,
				"A tool with no description gives the model (and a reviewer) nothing to judge intent by before it is invoked.",
				evidence("tool", t.Name),
			))
		}

		findings = append(findings, checkToolSchema(t)...)
	}
	return findings
}

func checkToolSchema(t model.ToolInfo) []model.Finding {
	var findings []model.Finding

	if !isObjectSchema(t.InputSchema) {
		findings = append(findings, newFinding(
			RuleSchemaInvalid, "protocol_conformance", "Tool input schema is missing or not an object",
			model.SeverityMedium, model.EvidenceStatic, 0.8, t.Name,
			"MCP tool input schemas must be JSON Schema objects; a client cannot validate arguments against anything else.",
			evidence("input_schema", fmt.Sprintf("%v", t.InputSchema)),
		))
		return findings // nothing further to check without a real schema
	}

	if t.OutputSchema != nil && !isObjectSchema(t.OutputSchema) {
		findings = append(findings, newFinding(
			RuleOutputSchemaInvalid, "protocol_conformance", "Tool output schema is not an object",
			model.SeverityLow, model.EvidenceStatic, 0.7, t.Name,
			"A declared output schema that is not a JSON Schema object cannot be used to validate structured results.",
			evidence("output_schema", fmt.Sprintf("%v", t.OutputSchema)),
		))
	}

	props, required := schemaShape(t.InputSchema)
	for r := range required {
		if !props[r] {
			findings = append(findings, newFinding(
				RuleSchemaRequiredMismatch, "protocol_conformance", "Schema requires a property it never declares",
				model.SeverityMedium, model.EvidenceStatic, 0.8, t.Name,
				fmt.Sprintf("%q is listed in required but is not one of the schema's properties.", r),
				evidence("required_property", r),
			))
		}
	}
	desc := strings.ToLower(t.Description)
	if strings.Contains(desc, "required") || strings.Contains(desc, "mandatory") {
		for p := range props {
			if required[p] {
				continue
			}
			if mentionsWord(desc, strings.ToLower(p)) {
				findings = append(findings, newFinding(
					RuleSchemaRequiredMismatch, "protocol_conformance", "Description claims an argument is required that the schema marks optional",
					model.SeverityLow, model.EvidenceHeuristic, 0.5, t.Name,
					fmt.Sprintf("The description says %q is required or mandatory, but the schema's required list does not include it.", p),
					evidence("description", t.Description),
				))
			}
		}
	}
	return findings
}

func mentionsWord(text, word string) bool {
	if word == "" {
		return false
	}
	return slices.Contains(strings.FieldsFunc(text, func(r rune) bool { return !('a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '_') }), word)
}

func isObjectSchema(schema map[string]any) bool {
	if schema == nil {
		return false
	}
	if t, ok := schema["type"]; ok {
		return t == "object"
	}
	// No explicit "type" but declares object-shaped keywords: still usable
	_, hasProps := schema["properties"]
	return hasProps
}

func schemaShape(schema map[string]any) (props map[string]bool, required map[string]bool) {
	props, required = map[string]bool{}, map[string]bool{}
	if p, ok := schema["properties"].(map[string]any); ok {
		for k := range p {
			props[k] = true
		}
	}
	if r, ok := schema["required"].([]any); ok {
		for _, v := range r {
			if s, ok := v.(string); ok {
				required[s] = true
			}
		}
	}
	return props, required
}

// checkAnnotationConflicts checks only readOnlyHint against execution-named schema arguments.
// Other annotations and ordinary path or address inputs do not trigger this rule.
func checkAnnotationConflicts(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	for _, t := range snap.Tools {
		if t.Annotations == nil {
			continue
		}
		readOnly, _ := t.Annotations["readOnlyHint"].(bool)
		if !readOnly {
			continue
		}
		props, _ := schemaShape(t.InputSchema)
		var sensitive []string
		for p := range props {
			if isSensitiveArgName(p) {
				sensitive = append(sensitive, p)
			}
		}
		if len(sensitive) == 0 {
			continue
		}
		findings = append(findings, newFinding(
			RuleAnnotationConflict, "tool_poisoning", "Read-only tool accepts an argument that names execution",
			model.SeverityHigh, model.EvidenceStatic, 0.6, t.Name,
			fmt.Sprintf("Tool %q claims readOnlyHint=true but accepts argument(s) %s, which name code or a command to run. Annotations are self-reported and should not be trusted over the schema.", t.Name, strings.Join(sensitive, ", ")),
			evidence("annotations_vs_schema", strings.Join(sensitive, ", ")),
		))
	}
	return findings
}

// unsafeResourceSchemes are schemes worth flagging on sight: they read local
// state or something not obviously scoped to the server's own data
var unsafeResourceSchemes = map[string]model.Severity{
	"file": model.SeverityMedium,
}

func checkResourceURIs(snap *model.Snapshot) []model.Finding {
	var findings []model.Finding
	check := func(uri string) {
		if uri == "" {
			return
		}
		scheme, _, ok := strings.Cut(uri, ":")
		if !ok || scheme == "" {
			findings = append(findings, newFinding(
				RuleResourceURIUnsafe, "protocol_conformance", "Resource URI has no scheme",
				model.SeverityLow, model.EvidenceStatic, 0.6, "",
				fmt.Sprintf("Resource URI %q has no scheme; its meaning depends entirely on the client's own guess.", uri),
				evidence("resource_uri", uri),
			))
			return
		}
		scheme = strings.ToLower(scheme)
		switch scheme {
		case "http", "https":
			return
		}
		sev, known := unsafeResourceSchemes[scheme]
		if !known {
			sev = model.SeverityLow
		}
		desc := fmt.Sprintf("Resource URI %q uses the %q scheme.", uri, scheme)
		if scheme == "file" {
			desc += " file:// resources read local filesystem state on whatever host resolves them."
		} else {
			desc += " This scheme is not one a generic MCP client is guaranteed to know how to handle safely."
		}
		findings = append(findings, newFinding(
			RuleResourceURIUnsafe, "protocol_conformance", "Resource uses a scheme worth reviewing",
			sev, model.EvidenceStatic, 0.5, "", desc,
			evidence("resource_uri", uri),
		))
	}
	for _, r := range snap.Resources {
		check(r.URI)
	}
	return findings
}

// checkNameCollisions flags a name shared across tools, prompts and
// resources - a client indexing capabilities by name alone would silently
// drop one of them
func checkNameCollisions(snap *model.Snapshot) []model.Finding {
	kindsByName := map[string][]string{}
	for _, t := range snap.Tools {
		kindsByName[t.Name] = append(kindsByName[t.Name], "tool")
	}
	for _, p := range snap.Prompts {
		kindsByName[p.Name] = append(kindsByName[p.Name], "prompt")
	}
	for _, r := range snap.Resources {
		if r.Name != "" {
			kindsByName[r.Name] = append(kindsByName[r.Name], "resource")
		}
	}

	var findings []model.Finding
	for name, kinds := range kindsByName {
		if len(kinds) < 2 {
			continue
		}
		findings = append(findings, newFinding(
			RuleNameCollision, "protocol_conformance", "Name reused across capability types",
			model.SeverityLow, model.EvidenceStatic, 0.6, name,
			fmt.Sprintf("%q is used by more than one capability (%s); a client that indexes by name alone will only see one.", name, strings.Join(kinds, ", ")),
			evidence("colliding_kinds", strings.Join(kinds, ", ")),
		))
	}
	return findings
}

const largeInstructionsThreshold = 8000

func checkInstructions(snap *model.Snapshot) []model.Finding {
	n := len(snap.Instructions)
	if n == 0 {
		return nil
	}
	if n < largeInstructionsThreshold {
		return nil
	}
	return []model.Finding{newFinding(
		RuleInstructionsLarge, "prompt_injection", "Server instructions are unusually large",
		model.SeverityLow, model.EvidenceStatic, 0.5, "",
		fmt.Sprintf("Server instructions are %d characters. Instructions land in the model's context on every session; review them for hidden directives.", n),
		evidence("instructions_length", fmt.Sprintf("%d", n)),
	)}
}
