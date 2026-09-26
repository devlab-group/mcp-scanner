package bedrock

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/internal/llm"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
)

func TestDeriveSigningKey(t *testing.T) {
	got := deriveSigningKey("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
	want := "2c94c0cf5378ada6887f09bb697df8fc0affdb34ba1cdd5bda32b664bd55b73c"
	if hex.EncodeToString(got) != want {
		t.Fatalf("signing key = %s, want %s", hex.EncodeToString(got), want)
	}
}

const (
	testAccessKey   = "AKIATESTACCESSKEYID"
	testSecretKey   = "test/secret+access-key-value-do-not-leak"
	testRegionValue = "us-west-2"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv(envAccessKeyID, testAccessKey)
	t.Setenv(envSecretAccessKey, testSecretKey)
	t.Setenv(envRegion, testRegionValue)
	return New(llm.Config{BaseURL: srv.URL, HTTPClient: srv.Client()})
}

func textOK(w http.ResponseWriter, text string) {
	json.NewEncoder(w).Encode(map[string]any{
		"content":     []map[string]any{{"type": "text", "text": text}},
		"stop_reason": "end_turn",
		"usage":       map[string]any{"input_tokens": 3, "output_tokens": 2},
	})
}

func TestCompleteSignsAndReachesInvokeURL(t *testing.T) {
	var gotPath, authHeader string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		authHeader = r.Header.Get("Authorization")
		textOK(w, "ok")
	})
	if _, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotPath, "/model/") || !strings.Contains(gotPath, "/invoke") {
		t.Fatalf("unexpected invoke path: %s", gotPath)
	}
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 Credential="+testAccessKey) {
		t.Fatalf("Authorization header not signed as expected: %s", authHeader)
	}
}

func TestMissingCredentialsDoesNotDial(t *testing.T) {
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dialed = true }))
	defer srv.Close()
	c := New(llm.Config{BaseURL: srv.URL, HTTPClient: srv.Client()})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	if err == nil {
		t.Fatal("expected an auth error")
	}
	if dialed {
		t.Fatal("client dialed bedrock with no credentials configured")
	}
}

func TestPlainHTTPBaseURLRejectedWithoutOverride(t *testing.T) {
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dialed = true }))
	defer srv.Close()
	t.Setenv(envAccessKeyID, testAccessKey)
	t.Setenv(envSecretAccessKey, testSecretKey)
	t.Setenv(envRegion, testRegionValue)
	c := New(llm.Config{BaseURL: srv.URL})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	if err == nil {
		t.Fatal("expected a plain http base_url to be rejected")
	}
	if dialed {
		t.Fatal("must reject the base_url before dialing, not after")
	}
}

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
	if captured["anthropic_version"] != anthropicVersion {
		t.Fatalf("anthropic_version = %v, want %s", captured["anthropic_version"], anthropicVersion)
	}
}

func TestRateLimitReturnsRetryAfter(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	lerr, ok := err.(*llm.Error)
	if !ok || lerr.Kind != llm.ErrRateLimit || lerr.RetryAfter != 2*time.Second {
		t.Fatalf("got %v, want rate_limited/2s", err)
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
		w.Write([]byte("not json"))
	})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	lerr, ok := err.(*llm.Error)
	if !ok || lerr.Kind != llm.ErrMalformed {
		t.Fatalf("got %v, want a malformed_response llm.Error", err)
	}
}

func TestCredentialsNeverAppearInErrorsOrLogs(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"boom"}`))
	})
	_, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi"})
	if err == nil {
		t.Fatal("expected an error")
	}
	rendered := err.Error()
	for _, secret := range []string{testSecretKey, testAccessKey} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("credential leaked into error string: %s", rendered)
		}
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

// Expose only the forced result tool used to capture the model's answer
func TestSchemaRequestUsesOnlyTheForcedResultTool(t *testing.T) {
	var captured request
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		textOK(w, "ok")
	})
	if _, err := c.Complete(context.Background(), analyzer.LLMRequest{User: "hi", Schema: json.RawMessage(`{"type":"object"}`)}); err != nil {
		t.Fatal(err)
	}
	if len(captured.Tools) != 1 || captured.Tools[0].Name != resultToolName {
		t.Fatalf("tools = %+v, want only %s", captured.Tools, resultToolName)
	}
	if captured.ToolChoice == nil || captured.ToolChoice.Name != resultToolName {
		t.Fatalf("tool_choice = %+v, want it forced to %s", captured.ToolChoice, resultToolName)
	}
}
