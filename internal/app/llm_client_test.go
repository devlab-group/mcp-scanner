package app

import (
	"context"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/config"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

// An environment key alone must not opt the scanner into third-party calls
func TestBuildLLMClientRequiresOptIn(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-not-really-a-key")
	if c := BuildLLMClient(config.LLMConfig{}, nil); c != nil {
		t.Fatalf("expected nil without an explicit opt-in, got %#v", c)
	}
}

// Analyzer selection and provider configuration are both explicit opt-ins
func TestBuildLLMClientNamedAnalyzerOptsIn(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-not-really-a-key")
	if c := BuildLLMClient(config.LLMConfig{}, []string{"protocol", "llm"}); c == nil {
		t.Fatal("expected a client when \"llm\" is named in the analyzers selection")
	}
	if c := BuildLLMClient(config.LLMConfig{Provider: "anthropic"}, nil); c == nil {
		t.Fatal("expected a client when llm.provider is set in config")
	}
}

// After opt-in, a missing key must fail instead of skipping the analyzer
func TestBuildLLMClientOptedInWithNoKeyFailsLoudly(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	c := BuildLLMClient(config.LLMConfig{}, []string{"llm"})
	if c == nil {
		t.Fatal("expected a client that fails loudly, got nil (which the analyzer treats as a clean skip)")
	}
	if _, err := c.Complete(context.Background(), analyzer.LLMRequest{}); err == nil {
		t.Fatal("expected Complete to fail when the operator opted in but no key is configured")
	}
}
