package anthropic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/llm"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

const testKeyEnv = "ANTHROPIC_TEST_KEY"
const testKeyValue = "sk-ant-super-secret-value-98765"

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv(testKeyEnv, testKeyValue)
	return New(llm.Config{BaseURL: srv.URL, APIKeyEnv: testKeyEnv, HTTPClient: srv.Client()})
}

func textOK(w http.ResponseWriter, text string) {
	json.NewEncoder(w).Encode(map[string]any{
		"content":     []map[string]any{{"type": "text", "text": text}},
		"stop_reason": "end_turn",
		"usage":       map[string]any{"input_tokens": 12, "output_tokens": 6},
	})
}

func TestDefaultModel(t *testing.T) {
	c := New(llm.Config{})
	if c.Model() != DefaultModel {
		t.Fatalf("default model = %s, want %s", c.Model(), DefaultModel)
	}
}

func TestNoAPIKeyDoesNotDial(t *testing.T) {
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dialed = true }))
	defer srv.Close()
	c := New(llm.Config{BaseURL: srv.URL, APIKeyEnv: "ANTHROPIC_NOT_SET_XYZ", HTTPClient: srv.Client()})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	if err == nil {
		t.Fatal("expected an auth error")
	}
	if dialed {
		t.Fatal("client dialed the API with no key configured")
	}
}

func TestPlainHTTPBaseURLRejectedWithoutOverride(t *testing.T) {
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dialed = true }))
	defer srv.Close()
	t.Setenv(testKeyEnv, testKeyValue)
	c := New(llm.Config{BaseURL: srv.URL, APIKeyEnv: testKeyEnv})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	if err == nil {
		t.Fatal("expected a plain http base_url to be rejected")
	}
	if dialed {
		t.Fatal("must reject the base_url before dialing, not after")
	}
}

// Temperature must be absent from the request when the caller does not ask
// for it - the field is a pointer for exactly this reason
func TestTemperatureOmittedWhenNotRequested(t *testing.T) {
	var captured map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		textOK(w, "ok")
	})
	if _, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := captured["temperature"]; ok {
		t.Fatal("temperature present though the request did not set one")
	}
}

func TestSchemaRequestUsesForcedTool(t *testing.T) {
	var captured request
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{
				{"type": "tool_use", "input": map[string]any{"findings": []any{}}},
			},
			"stop_reason": "tool_use",
			"usage":       map[string]any{"input_tokens": 1, "output_tokens": 1},
		})
	})
	resp, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi", Schema: json.RawMessage(`{"type":"object"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(captured.Tools) != 1 || captured.Tools[0].Name != resultToolName {
		t.Fatalf("expected a single forced tool named %s, got %+v", resultToolName, captured.Tools)
	}
	if captured.ToolChoice == nil || captured.ToolChoice.Name != resultToolName {
		t.Fatal("tool_choice did not force the result tool")
	}
	if !strings.Contains(resp.Text, "findings") {
		t.Fatalf("tool_use input was not surfaced as response text: %q", resp.Text)
	}
}

func TestRateLimitReturnsRetryAfter(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	lerr, ok := err.(*llm.Error)
	if !ok || lerr.Kind != llm.ErrRateLimit || lerr.RetryAfter != 7*time.Second {
		t.Fatalf("got %v, want rate_limited/7s", err)
	}
}

func TestTimeoutIsClassified(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		textOK(w, "ok")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := c.Complete(ctx, analyzer.LLMRequest{User: "hi"})
	lerr, ok := err.(*llm.Error)
	if !ok || lerr.Kind != llm.ErrTimeout {
		t.Fatalf("got %v, want a timeout llm.Error", err)
	}
}

func TestMalformedResponseIsClassified(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{not json"))
	})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	lerr, ok := err.(*llm.Error)
	if !ok || lerr.Kind != llm.ErrMalformed {
		t.Fatalf("got %v, want a malformed_response llm.Error", err)
	}
}

func TestAPIKeyNeverAppearsInErrorsOrLogs(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"boom"}`))
	})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	if err == nil {
		t.Fatal("expected an error")
	}
	rendered := err.Error()
	if strings.Contains(rendered, testKeyValue) {
		t.Fatalf("API key leaked into error string: %s", rendered)
	}
}

// Use llm.max_tokens when the request does not set its own limit
func TestConfiguredMaxTokensIsSent(t *testing.T) {
	var captured map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		textOK(w, "ok")
	})
	c.cfg.MaxTokens = 2048
	if _, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"}); err != nil {
		t.Fatal(err)
	}
	if captured["max_tokens"] != float64(2048) {
		t.Fatalf("max_tokens = %v, want the configured 2048", captured["max_tokens"])
	}
}

// Mark only replies cut off at the token limit as truncated
func TestStopReasonMaxTokensIsTruncated(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   bool
	}{{"max_tokens", true}, {"end_turn", false}} {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"content":     []map[string]any{{"type": "text", "text": "partial"}},
				"stop_reason": tc.reason,
				"usage":       map[string]any{"input_tokens": 3, "output_tokens": 2},
			})
		})
		resp, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Truncated != tc.want {
			t.Errorf("stop_reason %q: Truncated = %v, want %v", tc.reason, resp.Truncated, tc.want)
		}
	}
}
