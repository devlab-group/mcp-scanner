// Package anthropic implements analyzer.LLMClient with the Anthropic Messages API
package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/llm"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
)

const (
	defaultBaseURL = "https://api.anthropic.com/v1"
	apiVersion     = "2023-06-01"
	// DefaultModel is used when config does not name one
	DefaultModel = "claude-sonnet-5"
)

// KnownModels lists recognized Anthropic model IDs. Other IDs still use the
// same default capabilities.
var KnownModels = []string{"claude-opus-5", "claude-sonnet-5", "claude-fable-5-1", "claude-haiku-4-5-20251001"}

// Client is an analyzer.LLMClient backed by the Anthropic API
type Client struct {
	cfg     llm.Config
	baseURL string
	caps    analyzer.ModelCapabilities
}

// New builds a client and defaults cfg.Model to DefaultModel
func New(cfg llm.Config) *Client {
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	base := strings.TrimSuffix(cfg.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	return &Client{cfg: cfg, baseURL: base, caps: Capabilities()}
}

// Capabilities describes how a client uses the Anthropic Messages API. It requests structured
// output through a forced tool call and does not expose JSON mode to the analyzer layer. Bedrock
// serves the same models through the same request shape, so its client reports these too.
func Capabilities() analyzer.ModelCapabilities {
	return analyzer.ModelCapabilities{
		SupportsTemperature: true,
		SupportsJSONSchema:  true,
		SupportsJSONMode:    false,
		SupportsSeed:        false,
		SupportsSystemRole:  true,
		MaxInputTokens:      200000,
	}
}

func (c *Client) Name() string                             { return "anthropic" }
func (c *Client) Model() string                            { return c.cfg.Model }
func (c *Client) Capabilities() analyzer.ModelCapabilities { return c.caps }

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// tool forces output to match req.Schema. It is not exposed to scanned content,
// and only this client's parser reads its arguments.
type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type toolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

const resultToolName = "emit_result"

type request struct {
	Model       string      `json:"model,omitempty"`
	MaxTokens   int         `json:"max_tokens"`
	System      string      `json:"system,omitempty"`
	Messages    []message   `json:"messages"`
	Temperature *float64    `json:"temperature,omitempty"`
	Tools       []tool      `json:"tools,omitempty"`
	ToolChoice  *toolChoice `json:"tool_choice,omitempty"`
}

type response struct {
	Content []struct {
		Type  string          `json:"type"` // "text" or "tool_use"
		Text  string          `json:"text,omitempty"`
		Input json.RawMessage `json:"input,omitempty"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func buildRequest(model string, caps analyzer.ModelCapabilities, req analyzer.LLMRequest) request {
	body := request{
		Model:    model,
		System:   req.System,
		Messages: []message{{Role: "user", Content: req.User}},
	}
	body.MaxTokens = req.MaxTokens
	if body.MaxTokens <= 0 {
		body.MaxTokens = 1024
	}
	if caps.SupportsTemperature && req.Temperature != nil {
		body.Temperature = req.Temperature
	}
	if len(req.Schema) > 0 && caps.SupportsJSONSchema {
		body.Tools = []tool{{Name: resultToolName, Description: "Record the structured analysis result.", InputSchema: req.Schema}}
		body.ToolChoice = &toolChoice{Type: "tool", Name: resultToolName}
	}
	return body
}

func parseResponse(data []byte) (analyzer.LLMResponse, error) {
	var parsed response
	if err := json.Unmarshal(data, &parsed); err != nil || len(parsed.Content) == 0 {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "anthropic", Kind: llm.ErrMalformed, Message: "could not parse messages response"}
	}

	var text strings.Builder
	for _, block := range parsed.Content {
		switch block.Type {
		case "tool_use":
			text.Write(block.Input)
		case "text":
			text.WriteString(block.Text)
		}
	}
	if text.Len() == 0 {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "anthropic", Kind: llm.ErrMalformed, Message: "response contained no text or tool_use block"}
	}
	return analyzer.LLMResponse{
		Text:         text.String(),
		InputTokens:  parsed.Usage.InputTokens,
		OutputTokens: parsed.Usage.OutputTokens,
		Truncated:    parsed.StopReason == "max_tokens",
	}, nil
}

// Complete sends one Messages API request. The model receives only the prompts
// and optional output tool, with no resources or tools that can act on input.
func (c *Client) Complete(ctx context.Context, req analyzer.LLMRequest) (analyzer.LLMResponse, error) {
	key := config.Secret(c.cfg.APIKeyEnv)
	if key == "" {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "anthropic", Kind: llm.ErrAuth, Message: "no API key configured"}
	}
	if err := c.cfg.CheckBaseURL(c.baseURL); err != nil {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "anthropic", Kind: llm.ErrProvider, Message: "configured base_url rejected: " + err.Error()}
	}

	if req.MaxTokens <= 0 {
		req.MaxTokens = c.cfg.MaxTokens
	}
	body := buildRequest(c.cfg.Model, c.caps, req)
	raw, err := json.Marshal(body)
	if err != nil {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "anthropic", Kind: llm.ErrProvider, Message: "encode request: " + err.Error()}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/messages", bytes.NewReader(raw))
	if err != nil {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "anthropic", Kind: llm.ErrProvider, Message: "build request: " + err.Error()}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", key)
	httpReq.Header.Set("anthropic-version", apiVersion)

	respBody, err := llm.Do(ctx, c.cfg.Client(), httpReq, "anthropic")
	if err != nil {
		return analyzer.LLMResponse{}, err
	}
	return parseResponse(respBody)
}
