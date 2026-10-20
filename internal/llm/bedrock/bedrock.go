// Package bedrock implements analyzer.LLMClient against Anthropic Claude models hosted on
// AWS Bedrock, calling bedrock-runtime InvokeModel directly over net/http with a
// hand-rolled SigV4 signature
package bedrock

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/config"
	"github.com/devlab-group/mcp-scanner/internal/llm"
	"github.com/devlab-group/mcp-scanner/internal/llm/anthropic"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

const (
	envAccessKeyID     = "AWS_ACCESS_KEY_ID"
	envSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	envSessionToken    = "AWS_SESSION_TOKEN"
	envRegion          = "AWS_REGION"
	defaultRegion      = "us-east-1"

	anthropicVersion = "bedrock-2023-05-31"
	// DefaultModel is the Bedrock model id used when config does not name
	// one - Anthropic's current Sonnet, matching the direct-API default
	DefaultModel = "anthropic.claude-sonnet-5-v1:0"
)

// Client is an analyzer.LLMClient backed by Bedrock's InvokeModel API
type Client struct {
	cfg    llm.Config
	caps   analyzer.ModelCapabilities
	region string
}

// New builds a client. cfg.Model defaults to DefaultModel. cfg.BaseURL, if
// set, overrides the bedrock-runtime endpoint (tests point it at an
// httptest.Server)
func New(cfg llm.Config) *Client {
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	region := os.Getenv(envRegion)
	if region == "" {
		region = defaultRegion
	}
	return &Client{cfg: cfg, region: region, caps: anthropic.Capabilities()}
}

func (c *Client) Name() string                             { return "bedrock" }
func (c *Client) Model() string                            { return c.cfg.Model }
func (c *Client) Capabilities() analyzer.ModelCapabilities { return c.caps }

// message, tool, toolChoice and request mirror the Anthropic Messages API
// body Bedrock expects for Claude models, minus the top-level "model" field
// (the model id is part of the URL) and plus "anthropic_version"
type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

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
	AnthropicVersion string      `json:"anthropic_version"`
	MaxTokens        int         `json:"max_tokens"`
	System           string      `json:"system,omitempty"`
	Messages         []message   `json:"messages"`
	Temperature      *float64    `json:"temperature,omitempty"`
	Tools            []tool      `json:"tools,omitempty"`
	ToolChoice       *toolChoice `json:"tool_choice,omitempty"`
}

type response struct {
	Content []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text,omitempty"`
		Input json.RawMessage `json:"input,omitempty"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func buildRequest(caps analyzer.ModelCapabilities, req analyzer.LLMRequest) request {
	body := request{
		AnthropicVersion: anthropicVersion,
		System:           req.System,
		Messages:         []message{{Role: "user", Content: req.User}},
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
		return analyzer.LLMResponse{}, &llm.Error{Provider: "bedrock", Kind: llm.ErrMalformed, Message: "could not parse invoke-model response"}
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
		return analyzer.LLMResponse{}, &llm.Error{Provider: "bedrock", Kind: llm.ErrMalformed, Message: "response contained no text or tool_use block"}
	}
	return analyzer.LLMResponse{
		Text:         text.String(),
		InputTokens:  parsed.Usage.InputTokens,
		OutputTokens: parsed.Usage.OutputTokens,
		Truncated:    parsed.StopReason == "max_tokens",
	}, nil
}

func (c *Client) endpoint() string {
	if c.cfg.BaseURL != "" {
		return strings.TrimSuffix(c.cfg.BaseURL, "/")
	}
	return "https://bedrock-runtime." + c.region + ".amazonaws.com"
}

func (c *Client) secretKeyEnv() string {
	if c.cfg.APIKeyEnv != "" {
		return c.cfg.APIKeyEnv
	}
	return envSecretAccessKey
}

// Complete invokes the model. The scanned content only ever reaches
// req.System / req.User; nothing here grants the model tools, network or
// filesystem access beyond the InvokeModel call itself.
func (c *Client) Complete(ctx context.Context, req analyzer.LLMRequest) (analyzer.LLMResponse, error) {
	accessKey := config.Secret(envAccessKeyID)
	secretKey := config.Secret(c.secretKeyEnv())
	if accessKey == "" || secretKey == "" {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "bedrock", Kind: llm.ErrAuth, Message: "no AWS credentials configured"}
	}
	if err := c.cfg.CheckBaseURL(c.endpoint()); err != nil {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "bedrock", Kind: llm.ErrProvider, Message: "configured base_url rejected: " + err.Error()}
	}
	sessionToken := config.Secret(envSessionToken)

	if req.MaxTokens <= 0 {
		req.MaxTokens = c.cfg.MaxTokens
	}
	body := buildRequest(c.caps, req)
	raw, err := json.Marshal(body)
	if err != nil {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "bedrock", Kind: llm.ErrProvider, Message: "encode request: " + err.Error()}
	}

	target := c.endpoint() + "/model/" + url.PathEscape(c.cfg.Model) + "/invoke"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return analyzer.LLMResponse{}, &llm.Error{Provider: "bedrock", Kind: llm.ErrProvider, Message: "build request: " + err.Error()}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	signSigV4(httpReq, raw, accessKey, secretKey, sessionToken, c.region, time.Now())

	respBody, err := llm.Do(ctx, c.cfg.Client(), httpReq, "bedrock")
	if err != nil {
		return analyzer.LLMResponse{}, err
	}
	return parseResponse(respBody)
}
