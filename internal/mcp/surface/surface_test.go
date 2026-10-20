package surface

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func fullSnapshot() *model.Snapshot {
	return &model.Snapshot{
		Instructions: "be careful",
		Tools:        []model.ToolInfo{{Name: "t1", Description: "d1"}},
		Prompts:      []model.PromptInfo{{Name: "p1", Description: "d1"}},
		Resources:    []model.ResourceInfo{{Name: "r1", Description: "d1"}},
		Templates:    []model.ResourceInfo{{URITemplate: "file:///{path}", Description: "d1"}},
	}
}

func plainFormatters() Formatters {
	return Formatters{
		Instructions: func(text string) string { return "instructions:" + text + "\n" },
		Tool:         func(t model.ToolInfo) string { return "tool:" + t.Name + "\n" },
		Prompt:       func(p model.PromptInfo) string { return "prompt:" + p.Name + "\n" },
		Resource:     func(r model.ResourceInfo) string { return "resource:" + r.Name + "\n" },
		Template:     func(t model.ResourceInfo) string { return "template:" + t.URITemplate + "\n" },
	}
}

func TestBuild_IncludedPlusSkippedMatchesCapabilityCount(t *testing.T) {
	snap := fullSnapshot()
	want := snap.CapabilityCount()
	if want != 5 {
		t.Fatalf("fixture drifted: CapabilityCount() = %d, want 5", want)
	}

	if _, included, skipped := Build(snap, 1000, plainFormatters()); included+skipped != want {
		t.Fatalf("included(%d)+skipped(%d) = %d, want %d (CapabilityCount) with a generous budget", included, skipped, included+skipped, want)
	}
	if _, included, skipped := Build(snap, 0, plainFormatters()); included+skipped != want {
		t.Fatalf("included(%d)+skipped(%d) = %d, want %d (CapabilityCount) with a zero budget", included, skipped, included+skipped, want)
	}
}

func TestBuild_RendersTemplates(t *testing.T) {
	snap := &model.Snapshot{Templates: []model.ResourceInfo{{URITemplate: "file:///{path}", Description: "attacker text here"}}}
	text, included, skipped := Build(snap, 1000, plainFormatters())
	if included != 1 || skipped != 0 {
		t.Fatalf("included=%d skipped=%d, want 1/0", included, skipped)
	}
	if text != "template:file:///{path}\n" {
		t.Fatalf("template was not rendered: %q", text)
	}
}

func TestBuild_BudgetIsFirstFitNotStopOnFirstMiss(t *testing.T) {
	snap := &model.Snapshot{Tools: []model.ToolInfo{
		{Name: "big"},   // formatter below renders 10 chars, budget is 5: does not fit
		{Name: "small"}, // formatter renders 1 char: still fits after the miss
	}}
	f := Formatters{
		Tool: func(t model.ToolInfo) string {
			if t.Name == "big" {
				return "0123456789"
			}
			return "x"
		},
	}
	_, included, skipped := Build(snap, 5, f)
	if included != 1 || skipped != 1 {
		t.Fatalf("included=%d skipped=%d, want 1/1 (a short entry after an oversized one should still fit)", included, skipped)
	}
}

// Render prompt argument descriptions and resource template identities into the scan surface
func TestPromptArgumentsAndTemplateIdentityAreRendered(t *testing.T) {
	args := PromptArguments([]model.PromptArgument{{Name: "topic", Description: "What to summarize", Required: true}})
	if args != "argument \"topic\", required: What to summarize\n" {
		t.Fatalf("PromptArguments = %q", args)
	}
	id := ResourceIdentity(model.ResourceInfo{URITemplate: "notes://{day}", MIMEType: "text/plain"})
	if id != "uri: notes://{day}\nmime_type: text/plain\n" {
		t.Fatalf("ResourceIdentity = %q", id)
	}
}
