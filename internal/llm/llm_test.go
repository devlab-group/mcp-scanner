package llm

import (
	"net/http"
	"testing"
)

func TestCheckBaseURLRejectsPlainHTTPByDefault(t *testing.T) {
	c := Config{}
	if err := c.CheckBaseURL("http://example.com"); err == nil {
		t.Fatal("expected a plain http base_url to be rejected by default")
	}
}

func TestCheckBaseURLAllowsHTTPWithOptIn(t *testing.T) {
	c := Config{AllowInsecureEndpoint: true}
	if err := c.CheckBaseURL("http://example.com"); err != nil {
		t.Fatalf("got %v, want the opt-in to allow http", err)
	}
}

// Matches Client(): BaseURL may legitimately point at a self-hosted gateway
// on a private network, so restricting the scheme must not also restrict
// the destination
func TestCheckBaseURLAllowsPrivateNetworkHTTPS(t *testing.T) {
	c := Config{}
	if err := c.CheckBaseURL("https://127.0.0.1:8443"); err != nil {
		t.Fatalf("got %v, want a private-network https destination to be allowed", err)
	}
}

func TestCheckBaseURLSkippedWhenHTTPClientOverridden(t *testing.T) {
	c := Config{HTTPClient: &http.Client{}}
	if err := c.CheckBaseURL("http://example.com"); err != nil {
		t.Fatalf("got %v, want no check when the caller supplies its own client", err)
	}
}
