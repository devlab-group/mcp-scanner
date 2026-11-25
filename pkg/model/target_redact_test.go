package model

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

const (
	pathKeyHex  = "a3f9c2e1b7d84f6a9e0c5b2d1f7a8e3c"
	pathKeyUUID = "3f2b8c1e-9d4a-4e7b-8a6f-2c1d0e9b7a55"
)

// An mcp-remote entry from a client config carries its token in a header argument and often a
// key in the URL path; neither may reach a report
func TestRedactedArgsHidesHeaderTokensAndURLKeys(t *testing.T) {
	secrets := []string{"SECRET-TOKEN-123", pathKeyHex, "QUERY-SECRET-789", "KEY-SECRET-000", "PACKED-SECRET-1", "XKEY-SECRET-2"}
	target := Target{Kind: TargetStdio, Command: "npx", Args: []string{
		"-y", "mcp-remote",
		"https://mcp.example.com/s/" + pathKeyHex + "/mcp?api_key=QUERY-SECRET-789",
		"--header", "Authorization: Bearer SECRET-TOKEN-123",
		"--header=Authorization: Bearer PACKED-SECRET-1",
		"-H", "X-API-Key: XKEY-SECRET-2",
		"--api-key", "KEY-SECRET-000",
	}}
	out, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(out), s) {
			t.Errorf("report JSON still contains %q: %s", s, out)
		}
	}
	got := target.RedactedArgs()
	for _, want := range []string{"Authorization: redacted", "--header=Authorization: redacted", "X-API-Key: redacted", "-y", "mcp-remote"} {
		if !slices.Contains(got, want) {
			t.Errorf("RedactedArgs() = %q, want an element %q (header names and plain args stay)", got, want)
		}
	}
	if !strings.Contains(strings.Join(got, " "), "https://mcp.example.com/s/redacted/mcp?api_key=redacted") {
		t.Errorf("RedactedArgs() = %q, want the URL's path key and query value redacted", got)
	}
}

func TestRedactedArgsHidesCredentialsWithoutAFlag(t *testing.T) {
	for in, want := range map[string]string{
		"Authorization: Bearer abcdefgh12345":          "Authorization: redacted",
		"--auth=Bearer abcdefgh12345":                  "--auth=Bearer redacted",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789":     "redacted",
		"--model=sk-proj-abcdefghijklmnop1234":         "--model=redacted",
		"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0": "GITHUB_TOKEN=redacted",
	} {
		got := Target{Kind: TargetStdio, Command: "x", Args: []string{in}}.RedactedArgs()
		if got[0] != want {
			t.Errorf("RedactedArgs(%q) = %q, want %q", in, got[0], want)
		}
	}
}

func TestRedactedArgsKeepsOrdinaryArguments(t *testing.T) {
	args := []string{"-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects", "--port", "3000",
		`C:\work`, "--model=claude-3-opus-20240229", "--description=count token usage_statistics", "--keyring", "gnome"}
	got := Target{Kind: TargetStdio, Command: "npx", Args: args}.RedactedArgs()
	if !slices.Equal(got, args) {
		t.Fatalf("RedactedArgs() = %q, want %q unchanged", got, args)
	}
}

func TestRedactedArgsRedactsAValueThatStartsWithADash(t *testing.T) {
	got := Target{Kind: TargetStdio, Command: "x", Args: []string{"--token", "-Zk3_x9QmP2aL"}}.RedactedArgs()
	if got[1] != "redacted" {
		t.Fatalf("RedactedArgs() = %q: a base64url token may start with '-' and is still the value", got)
	}
}

func TestRedactedURLRedactsKeyLikePathSegments(t *testing.T) {
	for in, want := range map[string]string{
		"https://mcp.example.com/s/" + pathKeyUUID + "/sse":          "https://mcp.example.com/s/redacted/sse",
		"https://mcp.example.com/" + pathKeyHex + "/mcp":             "https://mcp.example.com/redacted/mcp",
		"https://actions.example.com/mcp/sk-live-abcdefghijk123/sse": "https://actions.example.com/mcp/redacted/sse",
		"https://api.example.com/v1/mcp":                             "https://api.example.com/v1/mcp",
		"https://api.example.com/servers/weather/tools":              "https://api.example.com/servers/weather/tools",
	} {
		if got := (Target{Kind: TargetRemote, URL: in}).RedactedURL(); got != want {
			t.Errorf("RedactedURL(%q) = %q, want %q", in, got, want)
		}
	}
	// a URL the parser refuses still loses its path key
	got := Target{Kind: TargetRemote, URL: "https://exa mple.test/s/" + pathKeyUUID + "/mcp?k=v"}.RedactedURL()
	if strings.Contains(got, pathKeyUUID) {
		t.Errorf("RedactedURL of an unparsable URL = %q, still has the path key", got)
	}
}

// Finding IDs hash the scope; the key in a path must keep two endpoints apart there, and a URL
// with no key in its path must keep the scope it had before path redaction existed
func TestFingerprintScopeIsStableAndKeepsPathKeysApart(t *testing.T) {
	a := Target{Kind: TargetRemote, URL: "https://mcp.example.com/s/" + pathKeyUUID + "/mcp"}
	b := Target{Kind: TargetRemote, URL: "https://mcp.example.com/s/" + strings.Replace(pathKeyUUID, "3f2b", "4f2b", 1) + "/mcp"}
	if FingerprintScope(a) == FingerprintScope(b) {
		t.Fatalf("two endpoints that differ only by their path key share a scope: %q", FingerprintScope(a))
	}
	plain := Target{Kind: TargetRemote, URL: "https://user:pw@api.example.com/v1/mcp?api_key=x"}
	if got, want := FingerprintScope(plain), "remote|https://redacted:redacted@api.example.com/v1/mcp?api_key=redacted"; got != want {
		t.Fatalf("FingerprintScope = %q, want %q (unchanged for a URL with no key in its path)", got, want)
	}
}
