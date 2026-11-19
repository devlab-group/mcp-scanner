package taint

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// llmCall matches a call that asks a language model for a completion: the OpenAI and Anthropic
// clients, Gemini, the Vercel AI SDK, LiteLLM, Ollama
var llmCall = regexp.MustCompile(`\bchat\.completions\.create\s*\(|\bcompletions\.create\s*\(|\bmessages\.create\s*\(|\bresponses\.create\s*\(|\bgenerate_?[cC]ontent\s*\(|\bgenerateText\s*\(|\bstreamText\s*\(|\bgenerateObject\s*\(|\blitellm\.a?completion\s*\(|\bollama\.(?:chat|generate)\s*\(|\bChatCompletion\.create\s*\(`)

// llmStep returns the step of a path whose value is a language model's answer: the step's own call
// is a completion request, or it is a project function whose body makes one
func llmStep(g *graph.Graph, path []model.FlowStep) (string, bool) {
	for _, st := range path[1:] {
		if st.Kind != "transform" && st.Kind != "unknown" {
			continue
		}
		if llmCall.MatchString(st.Symbol + "(") {
			return st.Symbol, true
		}
		if body := uniqueFunctionBody(g, parser.LastSegment(st.Symbol)); body != "" && llmCall.MatchString(body) {
			return st.Symbol, true
		}
	}
	return "", false
}

// uniqueFunctionBody is the source text of the one project function or method with that name
func uniqueFunctionBody(g *graph.Graph, name string) string {
	var found *graph.Symbol
	for _, s := range g.Symbols {
		if s.Name != name || (s.Kind != graph.KindFunction && s.Kind != graph.KindMethod) {
			continue
		}
		if found != nil {
			return ""
		}
		found = s
	}
	if found == nil || found.EndLine <= found.Line {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(g.Root, found.File))
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if found.EndLine > len(lines) {
		return ""
	}
	return strings.Join(lines[found.Line-1:found.EndLine], "\n")
}
