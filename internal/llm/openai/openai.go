// Package openai implements analyzer.LLMClient against the OpenAI chat
// completions API
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/config"
	"github.com/devlab-group/mcp-scanner/internal/llm"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

const (
	defaultBaseURL = "https://api.openai.com/v1"
	// DefaultModel is used when config does not name one
	DefaultModel = "gpt-4o-mini"
)

// Client is an analyzer.LLMClient backed by the OpenAI API
type Client struct {
	cfg     llm.Config
	baseURL string
	caps    analyzer.ModelCapabilities
}

// New builds a client. cfg.Model defaults to DefaultModel
func New(cfg llm.Config) *Client {
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	base := strings.TrimSuffix(cfg.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	return &Client{cfg: cfg, baseURL: base, caps: capabilitiesFor(cfg.Model)}
}

// capabilitiesFor reports what a model accepts. Reasoning models (o1/o3/o4)
// reject temperature and use a "developer" role instead of "system"; every
// other chat model accepts both.
func capabilitiesFor(model string) analyzer.ModelCapabilities {
	if isReasoningModel(model) {
		return analyzer.ModelCapabilities{
			SupportsTemperature: false,
			SupportsJSONSchema:  true,
			SupportsJSONMode:    true,
			SupportsSeed:        false,
			SupportsSystemRole:  false,
			MaxInputTokens:      128000,
		}
	}
	return analyzer.ModelCapabilities{
		SupportsTemperature: true,
		SupportsJSONSchema:  true,
		SupportsJSONMode:    true,
		SupportsSeed:        true,
		SupportsSystemRole:  true,
		MaxInputTokens:      128000,
	}
}

func isReasoningModel(model string) bool {
	for _, prefix := range []string{"o1", "o3", "o4"} {
		if strings.HasPrefix(model, prefix) {
			return true
		}
	}
	return false
}

func (c *Client) Name() string                             { return "openai" }
func (c *Client) Model() string                            { return c.cfg.Model }
func (c *Client) Capabilities() analyzer.ModelCapabilities { return c.caps }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model               string          `json:"model"`
	Messages            []chatMessage   `json:"messages"`
	MaxCompletionTokens int             `json:"max_completion_tokens,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	Seed                *int            `json:"seed,omitempty"`
	ResponseFormat      json.RawMessage `json:"response_format,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Complete sends one chat completion request. It never places req.System or
// req.User content anywhere but the message body OpenAI defines for it - the
// scanned content passed in as req.User gets no function/tool definitions,
// so the model has nothing to invoke, only text to judge.
func (c *Client) Complete(ctx context.Context, req analyzer.LLMRequest) (analyzer.LLMResponse, error) {
	key := config.Secret(c.cfg.APIKeyEnv)
	if key == "" {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "openai", Kind: llm.ErrAuth, Message: "no API key configured"}
	}
	if err := c.cfg.CheckBaseURL(c.baseURL); err != nil {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "openai", Kind: llm.ErrProvider, Message: "configured base_url rejected: " + err.Error()}
	}

	var messages []chatMessage
	if req.System != "" {
		if c.caps.SupportsSystemRole {
			messages = append(messages, chatMessage{Role: "system", Content: req.System})
		} else {
			messages = append(messages, chatMessage{Role: "developer", Content: req.System})
		}
	}
	messages = append(messages, chatMessage{Role: "user", Content: req.User})

	body := chatRequest{Model: c.cfg.Model, Messages: messages}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = c.cfg.MaxTokens
	}
	if maxTokens > 0 {
		body.MaxCompletionTokens = maxTokens
	}
	if c.caps.SupportsTemperature && req.Temperature != nil {
		body.Temperature = req.Temperature
	}
	if len(req.Schema) > 0 {
		switch {
		case c.caps.SupportsJSONSchema:
			body.ResponseFormat = jsonSchemaFormat(req.Schema)
		case c.caps.SupportsJSONMode:
			body.ResponseFormat = json.RawMessage(`{"type":"json_object"}`)
		}
	}

	raw, err := json.Marshal(body)
	if err != nil {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "openai", Kind: llm.ErrProvider, Message: "encode request: " + err.Error()}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "openai", Kind: llm.ErrProvider, Message: "build request: " + err.Error()}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+key)

	respBody, err := llm.Do(ctx, c.cfg.Client(), httpReq, "openai")
	if err != nil {
		return analyzer.LLMResponse{}, err
	}

	var parsed chatResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil || len(parsed.Choices) == 0 {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "openai", Kind: llm.ErrMalformed, Message: "could not parse chat completion response"}
	}

	choice := parsed.Choices[0]
	return analyzer.LLMResponse{
		Text:         choice.Message.Content,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
		Truncated:    choice.FinishReason == "length",
	}, nil
}

func jsonSchemaFormat(schema json.RawMessage) json.RawMessage {
	out, _ := json.Marshal(struct {
		Type       string `json:"type"`
		JSONSchema struct {
			Name   string          `json:"name"`
			Strict bool            `json:"strict"`
			Schema json.RawMessage `json:"schema"`
		} `json:"json_schema"`
	}{
		Type: "json_schema",
		JSONSchema: struct {
			Name   string          `json:"name"`
			Strict bool            `json:"strict"`
			Schema json.RawMessage `json:"schema"`
		}{Name: "result", Strict: true, Schema: strictSchema(schema)},
	})
	return out
}

// strictSchema makes a JSON Schema satisfy OpenAI's strict structured-output mode, which
// rejects an object node unless every key in "properties" also appears in "required" and
// "additionalProperties" is false
func strictSchema(schema json.RawMessage) json.RawMessage {
	var node any
	if err := json.Unmarshal(schema, &node); err != nil {
		return schema // malformed input; let the provider reject it as sent
	}
	strictNode(node)
	out, err := json.Marshal(node)
	if err != nil {
		return schema
	}
	return out
}

func strictNode(node any) {
	obj, ok := node.(map[string]any)
	if !ok {
		return
	}
	if props, ok := obj["properties"].(map[string]any); ok {
		required := make([]string, 0, len(props))
		for k := range props {
			required = append(required, k)
		}
		sort.Strings(required)
		obj["required"] = required
		if _, set := obj["additionalProperties"]; !set {
			obj["additionalProperties"] = false
		}
		for _, v := range props {
			strictNode(v)
		}
	}
	if items, ok := obj["items"]; ok {
		strictNode(items)
	}
}
