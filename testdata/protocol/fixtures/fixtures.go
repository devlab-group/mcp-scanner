// Package fixtures builds real, in-process MCP servers (and a few deliberately broken
// hand-rolled HTTP handlers) for hermetic tests of internal/mcp/... and
// internal/analyzers/protocol
package fixtures

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// textResult is the boring, correct response every fixture tool returns
// unless a test needs something else
func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// WellBehaved builds a server with a representative, spec-clean surface: a
// read-only tool, a non-read-only tool, a prompt and a resource
func WellBehaved() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "well-behaved", Title: "Well Behaved", Version: "1.0.0"}, &mcp.ServerOptions{
		Instructions: "A conformant test fixture. Use search to look things up and write_note to save one.",
	})
	s.AddTool(&mcp.Tool{
		Name:        "search",
		Description: "Search the fixture's notes.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"query": map[string]any{"type": "string"}},
			"required":   []any{"query"},
		},
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return textResult("no results"), nil
	})
	s.AddTool(&mcp.Tool{
		Name:        "write_note",
		Description: "Save a note.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"text": map[string]any{"type": "string"}},
			"required":   []any{"text"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return textResult("saved"), nil
	})
	s.AddPrompt(&mcp.Prompt{
		Name:        "summarize",
		Description: "Summarize the fixture's notes.",
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "Summarize the notes."}}},
		}, nil
	})
	s.AddResource(&mcp.Resource{
		URI: "fixture://notes/readme", Name: "readme", MIMEType: "text/plain",
		Description: "A short readme.",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
			{URI: req.Params.URI, MIMEType: "text/plain", Text: "hello from the fixture"},
		}}, nil
	})
	return s
}

// ToolsOnly builds a server that only declares tools
func ToolsOnly() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "tools-only", Version: "1.0.0"}, nil)
	s.AddTool(&mcp.Tool{
		Name: "ping", Description: "Replies pong.",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return textResult("pong"), nil
	})
	return s
}

// PromptsOnly builds a server that only declares prompts
func PromptsOnly() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "prompts-only", Version: "1.0.0"}, nil)
	s.AddPrompt(&mcp.Prompt{Name: "greet", Description: "A greeting prompt."},
		func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "hi"}}}}, nil
		})
	return s
}

// ResourcesOnly builds a server that only declares resources
func ResourcesOnly() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "resources-only", Version: "1.0.0"}, nil)
	s.AddResource(&mcp.Resource{URI: "fixture://only/one", Name: "one", MIMEType: "text/plain"},
		func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: "one"}}}, nil
		})
	return s
}

// ManyResources builds a server with n resources, each returning a text blob textLen bytes
// long, every byte identical, so a test can tell how much content survived a budget by
// length alone
func ManyResources(n, textLen int) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "many-resources", Version: "1.0.0"}, nil)
	blob := strings.Repeat("x", textLen)
	for i := range n {
		uri := fmt.Sprintf("fixture://many/%03d", i)
		s.AddResource(&mcp.Resource{URI: uri, Name: fmt.Sprintf("res_%03d", i), MIMEType: "text/plain"},
			func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: blob}}}, nil
			})
	}
	return s
}

// ManyPrompts builds a server with n prompts, each rendering to a single text message
// textLen bytes long, every byte identical, so a test can tell how much text survived a
// budget by length alone
func ManyPrompts(n, textLen int) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "many-prompts", Version: "1.0.0"}, nil)
	text := strings.Repeat("x", textLen)
	for i := range n {
		name := fmt.Sprintf("prompt_%03d", i)
		s.AddPrompt(&mcp.Prompt{Name: name, Description: "one of many"},
			func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
				return &mcp.GetPromptResult{
					Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}},
				}, nil
			})
	}
	return s
}

// PaginatedTools builds a server with n tools and a page size small enough
// that listing them all requires following tools/list's cursor
func PaginatedTools(n, pageSize int) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "paginated", Version: "1.0.0"}, &mcp.ServerOptions{PageSize: pageSize})
	for i := range n {
		name := fmt.Sprintf("tool_%03d", i)
		s.AddTool(&mcp.Tool{Name: name, Description: "one of many", InputSchema: map[string]any{"type": "object"}},
			func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return textResult("ok"), nil
			})
	}
	return s
}

// CapabilityMismatch builds a server that answers tools/list even though it never registers
// a tool (so the tools capability is never inferred and never advertised), and separately
// advertises the prompts capability while prompts/list always errors
func CapabilityMismatch() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "capability-mismatch", Version: "1.0.0"}, nil)
	// No AddTool call, so the tools capability is not advertised. The
	// middleware below answers tools/list anyway, by intercepting the
	// method directly rather than going through the normal tool machinery.
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/list" {
				return &mcp.ListToolsResult{Tools: []*mcp.Tool{
					{Name: "hidden", Description: "answers despite not being advertised", InputSchema: map[string]any{"type": "object"}},
				}}, nil
			}
			return next(ctx, method, req)
		}
	})
	s.AddPrompt(&mcp.Prompt{Name: "broken", Description: "advertised but never answers"},
		func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return nil, fmt.Errorf("prompts/list is broken on purpose")
		})
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "prompts/list" {
				return nil, fmt.Errorf("prompts/list is broken on purpose")
			}
			return next(ctx, method, req)
		}
	})
	return s
}

// UnboundedPagination builds a server whose tools/list always returns one tool and a fresh,
// non-empty NextCursor, no matter what cursor it is asked for - it never signals the list
// is complete
func UnboundedPagination() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "unbounded-pagination", Version: "1.0.0"}, &mcp.ServerOptions{
		// AddTool is never called, so this has to be declared explicitly
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
	})
	var n int
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/list" {
				return next(ctx, method, req)
			}
			n++
			return &mcp.ListToolsResult{
				Tools: []*mcp.Tool{{
					Name: fmt.Sprintf("tool_%d", n), Description: "one of infinitely many",
					InputSchema: map[string]any{"type": "object"},
				}},
				NextCursor: fmt.Sprintf("cursor-%d", n),
			}, nil
		}
	})
	return s
}

// RepeatedCursorPagination builds a server whose tools/list always returns
// the same NextCursor, regardless of what cursor it is asked for - the
// cheapest version of the attack UnboundedPagination exercises, since the
// server does not even need to keep minting new cursors
func RepeatedCursorPagination() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "repeated-cursor", Version: "1.0.0"}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
	})
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/list" {
				return next(ctx, method, req)
			}
			return &mcp.ListToolsResult{
				Tools:      []*mcp.Tool{{Name: "same_tool", Description: "repeats", InputSchema: map[string]any{"type": "object"}}},
				NextCursor: "same-cursor",
			}, nil
		}
	})
	return s
}

// ConnectInMemory connects a fresh client to server over an in-memory
// transport pair and returns the resulting session and a cleanup func
func ConnectInMemory(ctx context.Context, server *mcp.Server) (*mcp.ClientSession, func(), error) {
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		return nil, nil, fmt.Errorf("connecting fixture server: %w", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "fixture-client", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting fixture client: %w", err)
	}
	return cs, func() { _ = cs.Close() }, nil
}

// StreamableHTTPServer serves server over Streamable HTTP on an httptest
// server. The caller must Close() the returned server.
func StreamableHTTPServer(server *mcp.Server) *httptest.Server {
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	return httptest.NewServer(handler)
}

// SSEServer serves server over the legacy SSE transport on an httptest
// server. The caller must Close() the returned server.
func SSEServer(server *mcp.Server) *httptest.Server {
	handler := mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return server }, nil)
	return httptest.NewServer(handler)
}
