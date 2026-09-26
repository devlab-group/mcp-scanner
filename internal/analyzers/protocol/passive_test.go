package protocol

import (
	"testing"

	"github.com/revinand/mcp-scanner/internal/mcp/discovery"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func hasRule(fs []model.Finding, rule string) bool {
	for _, f := range fs {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func TestCheckProtocolVersion(t *testing.T) {
	vulnerable := &model.Snapshot{ProtocolVersion: ""}
	if !hasRule(checkProtocolVersion(vulnerable), RuleVersionMissing) {
		t.Fatal("missing protocol version was not flagged")
	}

	unknown := &model.Snapshot{ProtocolVersion: "banana"}
	if !hasRule(checkProtocolVersion(unknown), RuleVersionUnknown) {
		t.Fatal("a non-date-shaped, unrecognized protocol version was not flagged")
	}

	fixed := &model.Snapshot{ProtocolVersion: "2025-06-18"}
	if fs := checkProtocolVersion(fixed); len(fs) != 0 {
		t.Fatalf("a known protocol version was flagged: %v", fs)
	}
}

func TestCheckCapabilityMismatchPassive(t *testing.T) {
	vulnerable := &model.Snapshot{Truncated: []model.Truncation{
		{Method: "tools/list", Read: 0, Unknown: true, Reason: "the call failed: boom"},
	}}
	if !hasRule(checkCapabilityMismatchPassive(vulnerable), RuleCapabilityMismatch) {
		t.Fatal("an advertised-but-failing capability was not flagged")
	}

	fixed := &model.Snapshot{Warnings: []string{"server did not advertise the prompts capability; prompts/list was not attempted"}}
	if fs := checkCapabilityMismatchPassive(fixed); len(fs) != 0 {
		t.Fatalf("a normal skip-with-reason warning was flagged: %v", fs)
	}

	limited := &model.Snapshot{Truncated: []model.Truncation{
		{Method: "tools/list", Read: 0, Unknown: true, Reason: discovery.LimitHitReason + "64000-byte cap"},
	}}
	if fs := checkCapabilityMismatchPassive(limited); len(fs) != 0 {
		t.Fatalf("a scanner-imposed limit was flagged as a capability failure: %v", fs)
	}

	spoofed := &model.Snapshot{Warnings: []string{
		`prompts/get failed for "x": server advertised the tools capability but tools/list failed: not really`,
	}}
	if fs := checkCapabilityMismatchPassive(spoofed); len(fs) != 0 {
		t.Fatalf("server-controlled warning text forged a capability-mismatch finding: %v", fs)
	}
}

func TestCheckToolMetadataNameIssues(t *testing.T) {
	vulnerable := &model.Snapshot{Tools: []model.ToolInfo{
		{Name: "dup", Description: "d", InputSchema: map[string]any{"type": "object"}},
		{Name: "dup", Description: "d", InputSchema: map[string]any{"type": "object"}},
		{Name: "bad name!", Description: "d", InputSchema: map[string]any{"type": "object"}},
		{Name: "no_description", InputSchema: map[string]any{"type": "object"}},
	}}
	fs := checkToolMetadata(vulnerable)
	for _, want := range []string{RuleNameDuplicate, RuleNameCharset, RuleMissingDescription} {
		if !hasRule(fs, want) {
			t.Fatalf("expected %s among %v", want, fs)
		}
	}

	fixed := &model.Snapshot{Tools: []model.ToolInfo{
		{Name: "clean_tool", Description: "does one thing", InputSchema: map[string]any{"type": "object"}},
	}}
	if fs := checkToolMetadata(fixed); len(fs) != 0 {
		t.Fatalf("a clean tool was flagged: %v", fs)
	}
}

func TestCheckToolSchemaInvalid(t *testing.T) {
	vulnerable := model.ToolInfo{Name: "no_schema", Description: "d"}
	if !hasRule(checkToolSchema(vulnerable), RuleSchemaInvalid) {
		t.Fatal("a missing input schema was not flagged")
	}

	fixed := model.ToolInfo{Name: "has_schema", Description: "d", InputSchema: map[string]any{"type": "object"}}
	if fs := checkToolSchema(fixed); len(fs) != 0 {
		t.Fatalf("a minimal valid schema was flagged: %v", fs)
	}
}

func TestCheckToolSchemaRequiredMismatch(t *testing.T) {
	vulnerable := model.ToolInfo{
		Name: "run", Description: "runs a command; the command argument is required",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"command": map[string]any{"type": "string"}},
			// "command" is not actually in required, despite the description
		},
	}
	if !hasRule(checkToolSchema(vulnerable), RuleSchemaRequiredMismatch) {
		t.Fatal("a description/required mismatch was not flagged")
	}

	danglingRequired := model.ToolInfo{
		Name: "run2", Description: "d",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"a": map[string]any{"type": "string"}},
			"required":   []any{"a", "ghost"},
		},
	}
	if !hasRule(checkToolSchema(danglingRequired), RuleSchemaRequiredMismatch) {
		t.Fatal("a required property that does not exist was not flagged")
	}

	fixed := model.ToolInfo{
		Name: "run3", Description: "runs a command; the command argument is required",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"command": map[string]any{"type": "string"}},
			"required":   []any{"command"},
		},
	}
	if fs := checkToolSchema(fixed); len(fs) != 0 {
		t.Fatalf("a consistent required schema was flagged: %v", fs)
	}
}

func TestCheckAnnotationConflicts(t *testing.T) {
	vulnerable := &model.Snapshot{Tools: []model.ToolInfo{{
		Name: "peek", Annotations: map[string]any{"readOnlyHint": true},
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}},
	}}}
	if !hasRule(checkAnnotationConflicts(vulnerable), RuleAnnotationConflict) {
		t.Fatal("a read-only tool with a command argument was not flagged")
	}

	fixed := &model.Snapshot{Tools: []model.ToolInfo{{
		Name: "peek", Annotations: map[string]any{"readOnlyHint": true},
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}}},
	}}}
	if fs := checkAnnotationConflicts(fixed); len(fs) != 0 {
		t.Fatalf("a read-only search tool with a query argument was flagged: %v", fs)
	}

	for _, arg := range []string{"path", "file_path", "directory", "url", "uri", "country_code", "postcode", "language_code"} {
		reader := &model.Snapshot{Tools: []model.ToolInfo{{
			Name: "read_notes", Annotations: map[string]any{"readOnlyHint": true},
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{arg: map[string]any{"type": "string"}}},
		}}}
		if fs := checkAnnotationConflicts(reader); len(fs) != 0 {
			t.Fatalf("a read-only tool taking %q was flagged: %v", arg, fs)
		}
	}
}

func TestCheckResourceURIs(t *testing.T) {
	vulnerable := &model.Snapshot{Resources: []model.ResourceInfo{{URI: "file:///etc/passwd"}}}
	if !hasRule(checkResourceURIs(vulnerable), RuleResourceURIUnsafe) {
		t.Fatal("a file:// resource was not flagged")
	}

	fixed := &model.Snapshot{Resources: []model.ResourceInfo{{URI: "https://example.com/data"}}}
	if fs := checkResourceURIs(fixed); len(fs) != 0 {
		t.Fatalf("an https resource was flagged: %v", fs)
	}

	custom := &model.Snapshot{Resources: []model.ResourceInfo{{URI: "fixture://notes/readme"}}}
	if !hasRule(checkResourceURIs(custom), RuleResourceURIUnsafe) {
		t.Fatal("a resource using an arbitrary, unrecognized scheme was not flagged")
	}
}

func TestCheckNameCollisions(t *testing.T) {
	vulnerable := &model.Snapshot{
		Tools:   []model.ToolInfo{{Name: "search"}},
		Prompts: []model.PromptInfo{{Name: "search"}},
	}
	if !hasRule(checkNameCollisions(vulnerable), RuleNameCollision) {
		t.Fatal("a tool/prompt name collision was not flagged")
	}

	fixed := &model.Snapshot{
		Tools:   []model.ToolInfo{{Name: "search_tool"}},
		Prompts: []model.PromptInfo{{Name: "search_prompt"}},
	}
	if fs := checkNameCollisions(fixed); len(fs) != 0 {
		t.Fatalf("distinct names were flagged: %v", fs)
	}
}

func TestCheckInstructions(t *testing.T) {
	big := make([]byte, largeInstructionsThreshold+1)
	for i := range big {
		big[i] = 'x'
	}
	vulnerable := &model.Snapshot{Instructions: string(big)}
	if !hasRule(checkInstructions(vulnerable), RuleInstructionsLarge) {
		t.Fatal("oversized instructions were not flagged")
	}

	fixed := &model.Snapshot{Instructions: "keep it short"}
	if fs := checkInstructions(fixed); len(fs) != 0 {
		t.Fatalf("short instructions were flagged: %v", fs)
	}
}

func TestCheckCrossOriginRedirect(t *testing.T) {
	vulnerable := &model.Snapshot{RedirectsRefused: []string{
		"refused a cross-origin redirect attempt: refusing redirect from example.com to a different origin https://evil.example.net",
	}}
	if !hasRule(checkCrossOriginRedirect(vulnerable), RuleCrossOriginRedirect) {
		t.Fatal("a recorded cross-origin redirect attempt was not flagged")
	}

	fixed := &model.Snapshot{Warnings: []string{"server did not advertise the prompts capability; prompts/list was not attempted"}}
	if fs := checkCrossOriginRedirect(fixed); len(fs) != 0 {
		t.Fatalf("an unrelated warning was flagged: %v", fs)
	}

	spoofed := &model.Snapshot{Warnings: []string{
		`prompts/get failed for "x": refused a cross-origin redirect attempt: nice try`,
	}}
	if fs := checkCrossOriginRedirect(spoofed); len(fs) != 0 {
		t.Fatalf("server-controlled warning text forged a cross-origin-redirect finding: %v", fs)
	}
}

// TestFindingsValidate is the checklist every finding in this package must
// pass: RuleID, Analyzer, Title, a valid Severity and EvidenceLevel, and at
// least one Evidence entry
func TestFindingsValidate(t *testing.T) {
	snap := &model.Snapshot{
		ProtocolVersion: "",
		Warnings: []string{
			"server advertised the tools capability but tools/list failed: boom",
			"refused a cross-origin redirect attempt: refusing redirect from example.com to a different origin https://evil.example.net",
		},
		Truncated: []model.Truncation{
			{Method: "tools/list", Read: 0, Unknown: true, Reason: "the call failed: boom"},
		},
		RedirectsRefused: []string{
			"refused a cross-origin redirect attempt: refusing redirect from example.com to a different origin https://evil.example.net",
		},
		Instructions: "",
		Tools: []model.ToolInfo{
			{Name: "dup", Description: "", Annotations: map[string]any{"readOnlyHint": true},
				InputSchema: map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}}},
			{Name: "dup"},
			{Name: "bad name!"},
		},
		Prompts:   []model.PromptInfo{{Name: "dup"}},
		Resources: []model.ResourceInfo{{URI: "file:///etc/passwd"}, {URI: "not-a-uri"}},
	}
	var all []model.Finding
	all = append(all, checkProtocolVersion(snap)...)
	all = append(all, checkCapabilityMismatchPassive(snap)...)
	all = append(all, checkToolMetadata(snap)...)
	all = append(all, checkAnnotationConflicts(snap)...)
	all = append(all, checkResourceURIs(snap)...)
	all = append(all, checkNameCollisions(snap)...)
	all = append(all, checkCrossOriginRedirect(snap)...)
	if len(all) == 0 {
		t.Fatal("expected at least one finding from a deliberately messy snapshot")
	}
	for _, f := range all {
		f.EnsureID("")
		if err := f.Validate(); err != nil {
			t.Errorf("invalid finding %s: %v", f.RuleID, err)
		}
	}
}
