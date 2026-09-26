// Package llm holds what the provider adapters (openai, anthropic, bedrock)
// share: request configuration, a classified error type, and the HTTP call
// that turns a raw response into one of them. Each provider package still
// owns its own request/response shapes, since those differ per API.
package llm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/revinand/mcp-scanner/internal/httpx"
)

// Config configures a provider client. BaseURL overrides the provider's
// default endpoint; tests point it at an httptest.Server. APIKeyEnv is the
// environment variable name holding the credential - never the credential
// itself, so a Config can be logged or stored without leaking a secret.
type Config struct {
	Model     string
	BaseURL   string
	APIKeyEnv string
	MaxTokens int
	Timeout   time.Duration
	// AllowInsecureEndpoint permits a plain http:// BaseURL. Off by
	// default: every request to BaseURL carries the API key, and for a
	// source/package scan, part of the scanned content, so a plaintext
	// endpoint sends both where anything on the path can read them. Set
	// from internal/config.LLMConfig.AllowInsecureEndpoint by
	// internal/app.BuildLLMClient - see CheckBaseURL.
	AllowInsecureEndpoint bool
	HTTPClient            *http.Client // overridden in tests
}

// CheckBaseURL rejects base if it is not HTTPS unless AllowInsecureEndpoint is set. A caller that
// supplies its own HTTP client owns that transport choice, which also permits local test servers.
func (c Config) CheckBaseURL(base string) error {
	if c.HTTPClient != nil {
		return nil
	}
	schemes := []string{"https"}
	if c.AllowInsecureEndpoint {
		schemes = []string{"https", "http"}
	}
	// AllowPrivateNetworks matches Client() above: BaseURL may legitimately
	// point at a private network, and this only ever narrows scheme, not
	// destination
	return httpx.Policy{AllowPrivateNetworks: true, AllowedSchemes: schemes}.CheckURL(base)
}

// Client returns the HTTP client to use, applying the configured timeout when the caller
// did not supply one. Configured model gateways may intentionally be private, so this client opts
// into private destinations explicitly rather than weakening the package-wide default policy.
func (c Config) Client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return httpx.Policy{AllowPrivateNetworks: true}.Client(timeout)
}

// ErrorKind classifies a provider failure so analyzers can react to the kind
// without parsing message text
type ErrorKind string

const (
	ErrTimeout   ErrorKind = "timeout"
	ErrRateLimit ErrorKind = "rate_limited"
	ErrMalformed ErrorKind = "malformed_response"
	ErrAuth      ErrorKind = "auth"
	ErrProvider  ErrorKind = "provider"
)

// Error is a provider failure. Message is built from status codes and
// response shape only - never from request headers - so it can never carry
// the API key.
type Error struct {
	Provider   string
	Kind       ErrorKind
	Message    string
	StatusCode int
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("%s: %s: %s (retry after %s)", e.Provider, e.Kind, e.Message, e.RetryAfter)
	}
	return fmt.Sprintf("%s: %s: %s", e.Provider, e.Kind, e.Message)
}

// Do sends req and classifies the outcome. On a 2xx status it returns the
// response body; otherwise it returns a *Error and no body, so callers never
// have to re-derive the error kind from a status code themselves.
func Do(ctx context.Context, client *http.Client, req *http.Request, provider string) ([]byte, error) {
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		var netErr net.Error
		if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
			return nil, &Error{Provider: provider, Kind: ErrTimeout, Message: "request timed out"}
		}
		// err.Error() on a *url.Error wraps the method and URL, never a
		// header, so this cannot leak the Authorization value
		return nil, &Error{Provider: provider, Kind: ErrProvider, Message: "request failed: " + err.Error()}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, &Error{
			Provider: provider, Kind: ErrRateLimit, StatusCode: resp.StatusCode,
			Message:    "rate limited",
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &Error{
			Provider: provider, Kind: ErrAuth, StatusCode: resp.StatusCode,
			Message: fmt.Sprintf("authentication failed (status %d)", resp.StatusCode),
		}
	case resp.StatusCode >= 400:
		return nil, &Error{
			Provider: provider, Kind: ErrProvider, StatusCode: resp.StatusCode,
			Message: fmt.Sprintf("provider returned status %d", resp.StatusCode),
		}
	}
	return body, nil
}

// parseRetryAfter accepts both forms the header may take: a delay in
// seconds, or an HTTP date
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// AnalyzerErrorKind maps a provider error to the AnalyzerError kind vocabulary used
// across the scanner (config | network | timeout | parse | internal |
// policy | unavailable)
func AnalyzerErrorKind(err error) string {
	le, ok := err.(*Error)
	if !ok {
		return "internal"
	}
	switch le.Kind {
	case ErrTimeout:
		return "timeout"
	case ErrAuth:
		return "config"
	case ErrMalformed:
		return "parse"
	default:
		return "network"
	}
}
