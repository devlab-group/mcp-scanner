package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/llm"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

const testKeyEnv = "OPENAI_TEST_KEY"
const testKeyValue = "sk-test-super-secret-value-12345"

func newTestClient(t *testing.T, model string, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv(testKeyEnv, testKeyValue)
	return New(llm.Config{Model: model, BaseURL: srv.URL, APIKeyEnv: testKeyEnv, HTTPClient: srv.Client()})
}

func chatOK(w http.ResponseWriter, body string) {
	resp := map[string]any{
		"choices": []map[string]any{{
			"message":       map[string]any{"content": body},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
	}
	json.NewEncoder(w).Encode(resp)
}

// A reasoning model must never see a temperature field: sending one is a
// request OpenAI rejects outright for that model family
func TestReasoningModelOmitsUnsupportedFields(t *testing.T) {
	var captured map[string]any
	c := newTestClient(t, "o3-mini", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		chatOK(w, "ok")
	})
	temp := 0.7
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{System: "s", User: "hi", Temperature: &temp})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := captured["temperature"]; ok {
		t.Fatal("temperature field present in request to a model that does not support it")
	}
	if _, ok := captured["seed"]; ok {
		t.Fatal("seed field present in request to a model that does not support it")
	}
	msgs, _ := captured["messages"].([]any)
	if len(msgs) == 0 {
		t.Fatal("no messages sent")
	}
	first := msgs[0].(map[string]any)
	if first["role"] != "developer" {
		t.Fatalf("system content role = %v, want developer for a reasoning model", first["role"])
	}
}

// A normal chat model must get the temperature it was asked for
func TestChatModelIncludesSupportedFields(t *testing.T) {
	var captured map[string]any
	c := newTestClient(t, "gpt-4o-mini", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		chatOK(w, "ok")
	})
	temp := 0.2
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{System: "s", User: "hi", Temperature: &temp})
	if err != nil {
		t.Fatal(err)
	}
	if captured["temperature"] != 0.2 {
		t.Fatalf("temperature = %v, want 0.2", captured["temperature"])
	}
	msgs := captured["messages"].([]any)
	if msgs[0].(map[string]any)["role"] != "system" {
		t.Fatal("system message role was not preserved for a model that supports it")
	}
}

func TestStructuredOutputRequestIsStrictModeCompliant(t *testing.T) {
	schema := `{
	  "type": "object",
	  "properties": {
	    "findings": {
	      "type": "array",
	      "items": {
	        "type": "object",
	        "properties": {
	          "capability": {"type": "string"},
	          "category": {"type": "string"},
	          "confidence": {"type": "number"}
	        },
	        "required": ["category"]
	      }
	    }
	  },
	  "required": ["findings"]
	}`

	var captured map[string]any
	c := newTestClient(t, "gpt-4o-mini", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		chatOK(w, "{}")
	})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi", Schema: json.RawMessage(schema)})
	if err != nil {
		t.Fatal(err)
	}

	rf, _ := captured["response_format"].(map[string]any)
	js, _ := rf["json_schema"].(map[string]any)
	if js["strict"] != true {
		t.Fatalf("strict = %v, want true", js["strict"])
	}
	sent, _ := js["schema"].(map[string]any)

	top := requiredSet(t, sent)
	if !top["findings"] {
		t.Fatalf("top-level required = %v, missing findings", sent["required"])
	}
	if sent["additionalProperties"] != false {
		t.Fatalf("top-level additionalProperties = %v, want false", sent["additionalProperties"])
	}

	items := sent["properties"].(map[string]any)["findings"].(map[string]any)["items"].(map[string]any)
	inner := requiredSet(t, items)
	for _, prop := range []string{"capability", "category", "confidence"} {
		if !inner[prop] {
			t.Fatalf("items required = %v, missing %q", items["required"], prop)
		}
	}
	if items["additionalProperties"] != false {
		t.Fatalf("items additionalProperties = %v, want false", items["additionalProperties"])
	}
}

func requiredSet(t *testing.T, node map[string]any) map[string]bool {
	t.Helper()
	req, _ := node["required"].([]any)
	out := map[string]bool{}
	for _, r := range req {
		out[r.(string)] = true
	}
	return out
}

func TestRateLimitReturnsRetryAfter(t *testing.T) {
	c := newTestClient(t, "gpt-4o-mini", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	var lerr *llm.Error
	if err == nil {
		t.Fatal("expected an error")
	}
	if !asError(err, &lerr) {
		t.Fatalf("error is not *llm.Error: %v", err)
	}
	if lerr.Kind != llm.ErrRateLimit || lerr.RetryAfter != 3*time.Second {
		t.Fatalf("got kind=%s retryAfter=%s, want rate_limited/3s", lerr.Kind, lerr.RetryAfter)
	}
}

func TestTimeoutIsClassified(t *testing.T) {
	c := newTestClient(t, "gpt-4o-mini", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		chatOK(w, "ok")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := c.Complete(ctx, analyzer.LLMRequest{User: "hi"})
	var lerr *llm.Error
	if !asError(err, &lerr) || lerr.Kind != llm.ErrTimeout {
		t.Fatalf("got %v, want a timeout llm.Error", err)
	}
}

func TestMalformedResponseIsClassified(t *testing.T) {
	c := newTestClient(t, "gpt-4o-mini", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	var lerr *llm.Error
	if !asError(err, &lerr) || lerr.Kind != llm.ErrMalformed {
		t.Fatalf("got %v, want a malformed_response llm.Error", err)
	}
}

func TestMissingKeyIsSkippedNotDialed(t *testing.T) {
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dialed = true }))
	defer srv.Close()
	c := New(llm.Config{BaseURL: srv.URL, APIKeyEnv: "OPENAI_NOT_SET_XYZ", HTTPClient: srv.Client()})
	os.Unsetenv("OPENAI_NOT_SET_XYZ")
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	if err == nil {
		t.Fatal("expected an auth error")
	}
	if dialed {
		t.Fatal("client made a network call with no API key configured")
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

func TestAPIKeyNeverAppearsInErrorsOrLogs(t *testing.T) {
	c := newTestClient(t, "gpt-4o-mini", func(w http.ResponseWriter, r *http.Request) {
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

func asError(err error, target **llm.Error) bool {
	le, ok := err.(*llm.Error)
	if !ok {
		return false
	}
	*target = le
	return true
}

// Mark only replies cut off at the token limit as truncated
func TestFinishReasonLengthIsTruncated(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   bool
	}{{"length", true}, {"stop", false}} {
		c := newTestClient(t, "gpt-4o", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{{"message": map[string]any{"content": "partial"}, "finish_reason": tc.reason}},
				"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
			})
		})
		resp, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Truncated != tc.want {
			t.Errorf("finish_reason %q: Truncated = %v, want %v", tc.reason, resp.Truncated, tc.want)
		}
	}
}

// A schema request sets the response format without exposing tools or functions
func TestSchemaRequestCarriesNoTools(t *testing.T) {
	var captured map[string]any
	c := newTestClient(t, "gpt-4o", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		chatOK(w, `{"findings":[]}`)
	})
	if _, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi", Schema: json.RawMessage(`{"type":"object"}`)}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tools", "tool_choice", "functions", "function_call"} {
		if _, ok := captured[key]; ok {
			t.Errorf("request carries %q: %v", key, captured[key])
		}
	}
	if _, ok := captured["response_format"]; !ok {
		t.Error("the schema did not reach the request as a response format")
	}
}
