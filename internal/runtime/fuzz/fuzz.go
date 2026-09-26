// Package fuzz generates schema-driven payloads for a tool's declared JSON Schema input. Payloads
// use inert markers rather than destructive commands or real hosts, and a seed makes them reproducible.
package fuzz

import (
	"fmt"
	"maps"
	"math"
	"math/rand"
	"path"
	"slices"
	"strings"

	"github.com/revinand/mcp-scanner/pkg/model"
)

// Class identifies a payload family
type Class string

const (
	ClassPathTraversal      Class = "path_traversal"
	ClassCommandInjection   Class = "command_injection"
	ClassShellMetacharacter Class = "shell_metacharacters"
	ClassFileURI            Class = "file_uri"
	ClassTemplateInjection  Class = "template_injection"
	ClassUnicodeEdge        Class = "unicode_edge_case"
	ClassOversized          Class = "oversized_input"
)

// stringClasses are the classes generated only for string-typed properties
var stringClasses = []Class{
	ClassPathTraversal, ClassCommandInjection, ClassShellMetacharacter,
	ClassFileURI, ClassTemplateInjection, ClassUnicodeEdge,
}

// Payload is one injected value and the marker that identifies it in output
type Payload struct {
	Class  Class
	Marker string
	Value  any
	// Canary is the ID of the planted canary this payload was aimed at,
	// empty when it aimed at none. A canary_hit observation names the
	// canary that fired; without knowing which one a payload targeted,
	// any hit read as proof that whatever payload happened to be running
	// had worked.
	Canary string
}

// Case is one full set of tool arguments with exactly one property carrying
// a fuzz payload; every other required property is filled with a benign
// value so the tool is likely to actually accept the call
type Case struct {
	Tool      string
	Property  string
	Arguments map[string]any
	Payload   Payload
}

// Options steers payload targets so they never point outside scanner-owned
// infrastructure
type Options struct {
	// CanaryFiles are the real planted canary files (see
	// internal/runtime/canary) that path_traversal and file_uri payloads
	// target when available
	CanaryFiles []CanaryFile
	// CanaryHome is where the sandbox plants those files inside the container
	CanaryHome string
}

// CanaryFile is one planted canary a payload can aim at: its ID, so a
// canary_hit can be traced back to the payload that targeted it, and its
// path relative to CanaryHome
type CanaryFile struct {
	ID      string
	RelPath string
}

// Generate produces one Case per (fuzzable property x applicable class),
// sorted by property name and class so the output order is stable
func Generate(tool model.ToolInfo, seed int64, opts Options) []Case {
	rng := rand.New(rand.NewSource(seed))
	props, required := schemaProperties(tool.InputSchema)

	base := map[string]any{}
	for name, spec := range props {
		base[name] = benignValue(spec, rng)
	}
	// Required properties absent from "properties" still need a value
	for _, name := range required {
		if _, ok := base[name]; !ok {
			base[name] = "x"
		}
	}

	names := slices.Sorted(maps.Keys(base))

	var cases []Case
	n := 0
	for _, name := range names {
		spec, _ := props[name].(map[string]any)
		typ := schemaType(spec)
		for _, class := range applicableClasses(typ) {
			marker := fmt.Sprintf("MCP-CANARY-%d-%s-%d", seed, class, n)
			n++
			value := payloadValue(class, marker, typ, opts, rng)
			if value == nil {
				continue
			}
			args := maps.Clone(base)
			args[name] = value
			cases = append(cases, Case{
				Tool:      tool.Name,
				Property:  name,
				Arguments: args,
				Payload:   Payload{Class: class, Marker: marker, Value: value, Canary: aimedCanary(class, opts)},
			})
		}
	}

	// A schema with no declared properties still gets a best-effort probe
	// under a conventional argument name, so tools with an untyped object
	// schema are not skipped entirely
	if len(names) == 0 {
		for _, class := range stringClasses {
			marker := fmt.Sprintf("MCP-CANARY-%d-%s-%d", seed, class, n)
			n++
			value := payloadValue(class, marker, "string", opts, rng)
			if value == nil {
				continue
			}
			cases = append(cases, Case{
				Tool:      tool.Name,
				Property:  "input",
				Arguments: map[string]any{"input": value},
				Payload:   Payload{Class: class, Marker: marker, Value: value, Canary: aimedCanary(class, opts)},
			})
		}
	}

	return cases
}

func applicableClasses(typ string) []Class {
	switch typ {
	case "string", "":
		return append(append([]Class{}, stringClasses...), ClassOversized)
	case "integer", "number":
		return []Class{ClassOversized}
	default:
		return nil
	}
}

// aimedCanary is the canary ID a payload of this class was built from, or
// "" when the class targets no canary at all
func aimedCanary(class Class, opts Options) string {
	switch class {
	case ClassPathTraversal, ClassFileURI:
		if len(opts.CanaryFiles) > 0 {
			return opts.CanaryFiles[0].ID
		}
	}
	return ""
}

func payloadValue(class Class, marker, typ string, opts Options, rng *rand.Rand) any {
	switch class {
	case ClassPathTraversal:
		target := "../../../../../../etc/passwd"
		if len(opts.CanaryFiles) > 0 {
			target = "../" + strings.TrimPrefix(opts.CanaryFiles[0].RelPath, "/")
		}
		return target + "#" + marker
	case ClassCommandInjection:
		return fmt.Sprintf("; echo %s #", marker)
	case ClassShellMetacharacter:
		return fmt.Sprintf("$(echo %s)`echo %s`|%s&&%s;", marker, marker, marker, marker)
	case ClassFileURI:
		target := "/etc/passwd"
		if len(opts.CanaryFiles) > 0 {
			target = path.Join(opts.CanaryHome, opts.CanaryFiles[0].RelPath)
		}
		return "file://" + target + "#" + marker
	case ClassTemplateInjection:
		return fmt.Sprintf("{{7*7}}${%s}#{7*7}<%%= %s %%>", marker, marker)
	case ClassUnicodeEdge:
		// U+202E (right-to-left override) and U+200B (zero-width space): classic
		// edge cases for code that assumes one rune is one byte or one display
		// column
		return "\u202e" + marker + "\u200b\U0001f600"
	case ClassOversized:
		if typ == "integer" || typ == "number" {
			return math.MaxInt64
		}
		return marker + strings.Repeat("A", 65536)
	default:
		return nil
	}
}

func benignValue(rawSpec any, rng *rand.Rand) any {
	spec, _ := rawSpec.(map[string]any)
	if enum, ok := spec["enum"].([]any); ok && len(enum) > 0 {
		return enum[0]
	}
	switch schemaType(spec) {
	case "integer":
		return 1
	case "number":
		return 1.0
	case "boolean":
		return true
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	default:
		return "x"
	}
}

func schemaType(spec map[string]any) string {
	if spec == nil {
		return ""
	}
	if t, ok := spec["type"].(string); ok {
		return t
	}
	return ""
}

// schemaProperties reads the top-level "properties" and "required" arrays of
// a JSON Schema object, one level deep. Deeper nesting is out of scope; most
// MCP tool schemas are flat, and a nested schema still gets its top-level
// properties fuzzed.
func schemaProperties(schema map[string]any) (props map[string]any, required []string) {
	props = map[string]any{}
	if schema == nil {
		return props, nil
	}
	if p, ok := schema["properties"].(map[string]any); ok {
		props = p
	}
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			if s, ok := r.(string); ok {
				required = append(required, s)
			}
		}
	}
	return props, required
}
