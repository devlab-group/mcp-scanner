package model

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestConfigIsNotAScannableTarget(t *testing.T) {
	err := Target{Kind: TargetConfig, Path: "/home/u/.cursor/mcp.json"}.Validate()
	if err == nil {
		t.Fatal("a config target was accepted")
	}
	if !strings.Contains(err.Error(), "known-configs") {
		t.Fatalf("the error should point at the command that does handle it: %v", err)
	}
}

func TestRedactedURLStripsCredential(t *testing.T) {
	target := Target{Kind: TargetRemote, URL: "http://svcuser:s3cr3t-token@127.0.0.1:8793/"}

	if got := target.RedactedURL(); strings.Contains(got, "s3cr3t-token") {
		t.Fatalf("RedactedURL() = %q, still contains the password", got)
	} else if strings.Contains(got, "svcuser") || !strings.Contains(got, "redacted") {
		t.Fatalf("RedactedURL() = %q, want both halves of the userinfo replaced with \"redacted\"", got)
	}
}

func TestRedactedURLStripsATokenCarriedAsTheUsername(t *testing.T) {
	for _, raw := range []string{
		"https://ghp_SECRETTOKEN123@mcp.example/mcp",
		"https://ghp_SECRETTOKEN123:x-oauth-basic@mcp.example/mcp",
		"https://glpat-SECRETTOKEN456@mcp.example/mcp",
	} {
		got := Target{Kind: TargetRemote, URL: raw}.RedactedURL()
		for _, secret := range []string{"ghp_SECRETTOKEN123", "glpat-SECRETTOKEN456"} {
			if strings.Contains(got, secret) {
				t.Errorf("RedactedURL(%q) = %q, the token survived", raw, got)
			}
		}
		if !strings.Contains(got, "redacted@") {
			t.Errorf("RedactedURL(%q) = %q, want the userinfo kept as a marker that a credential was there", raw, got)
		}
		if !strings.Contains(got, "mcp.example") {
			t.Errorf("RedactedURL(%q) = %q, lost the host that identifies the target", raw, got)
		}
	}
}

func TestRedactedURLStripsQueryToken(t *testing.T) {
	target := Target{Kind: TargetRemote, URL: "https://example.test/sse?api_key=SUPERSECRET123"}

	got := target.RedactedURL()
	if strings.Contains(got, "SUPERSECRET123") {
		t.Fatalf("RedactedURL() = %q, still contains the query token", got)
	}
	if !strings.Contains(got, "api_key=redacted") {
		t.Fatalf("RedactedURL() = %q, want the parameter name kept and the value redacted", got)
	}
}

// The direction chosen is redact-by-default: an unrecognized query
// parameter is treated as a possible credential, not passed through
func TestRedactedURLRedactsAnUnrecognizedQueryParamByDefault(t *testing.T) {
	target := Target{Kind: TargetRemote, URL: "https://example.test/mcp?session=abc123"}

	got := target.RedactedURL()
	if strings.Contains(got, "abc123") {
		t.Fatalf("RedactedURL() = %q, an unrecognized query parameter must be redacted by default", got)
	}
}

// The small allowlist of parameters known not to carry a credential is
// the only thing RedactedURL leaves untouched in the query string
func TestRedactedURLKeepsAllowlistedQueryParams(t *testing.T) {
	target := Target{Kind: TargetRemote, URL: "https://example.test/mcp?transport=sse&version=2025-06-18"}

	got := target.RedactedURL()
	if !strings.Contains(got, "transport=sse") || !strings.Contains(got, "version=2025-06-18") {
		t.Fatalf("RedactedURL() = %q, want the allowlisted params kept as-is", got)
	}
}

// RedactedURL must not mutate the raw field: the transport that actually
// dials the target reads Target.URL directly
func TestRedactedURLDoesNotMutateTheRawURL(t *testing.T) {
	target := Target{Kind: TargetRemote, URL: "https://example.test/sse?api_key=SUPERSECRET123"}
	target.RedactedURL()
	if target.URL != "https://example.test/sse?api_key=SUPERSECRET123" {
		t.Fatalf("Target.URL was mutated by RedactedURL: %s", target.URL)
	}
}

func TestRedactedURLLeavesCredentiallessURLUnchanged(t *testing.T) {
	target := Target{Kind: TargetRemote, URL: "https://example.com/mcp"}
	if got := target.RedactedURL(); got != target.URL {
		t.Fatalf("RedactedURL() = %q, want %q unchanged: no userinfo to redact", got, target.URL)
	}
}

func TestRedactedURLKeepsAnUnparsableURLWithNothingToRedact(t *testing.T) {
	target := Target{Kind: TargetRemote, URL: "not a url at all: %zz"}
	if got := target.RedactedURL(); got != target.URL {
		t.Fatalf("RedactedURL() = %q, want the raw value when there is nothing in it to redact", got)
	}
}

func TestRedactedArgsStripsASeparateElementValue(t *testing.T) {
	target := Target{Kind: TargetStdio, Command: "npx", Args: []string{"--api-key", "sk-live-SECRET"}}

	got := target.RedactedArgs()
	if slices.Contains(got, "sk-live-SECRET") {
		t.Fatalf("RedactedArgs() = %v, still contains the secret", got)
	}
	if got[0] != "--api-key" || got[1] != "redacted" {
		t.Fatalf("RedactedArgs() = %v, want [--api-key redacted]", got)
	}
}

func TestRedactedArgsStripsAnEqualsPackedValue(t *testing.T) {
	target := Target{Kind: TargetStdio, Command: "npx", Args: []string{"--api-key=sk-live-SECRET"}}

	got := target.RedactedArgs()
	if slices.Contains(got, "--api-key=sk-live-SECRET") || strings.Contains(strings.Join(got, " "), "sk-live-SECRET") {
		t.Fatalf("RedactedArgs() = %v, still contains the secret", got)
	}
	if got[0] != "--api-key=redacted" {
		t.Fatalf("RedactedArgs() = %v, want [--api-key=redacted]", got)
	}
}

func TestRedactedArgsLeavesALookalikeFlagNameAlone(t *testing.T) {
	target := Target{Kind: TargetStdio, Command: "npx", Args: []string{"--keyring", "gnome", "--tokenizer", "cl100k"}}

	got := target.RedactedArgs()
	if !slices.Equal(got, target.Args) {
		t.Fatalf("RedactedArgs() = %v, want %v unchanged: neither flag ends in a sensitive word", got, target.Args)
	}
}

// A flag whose value is missing - the sensitive name is the last element -
// must not index past the end of the slice
func TestRedactedArgsHandlesATrailingFlagWithNoValue(t *testing.T) {
	target := Target{Kind: TargetStdio, Command: "npx", Args: []string{"--verbose", "--api-key"}}

	got := target.RedactedArgs()
	if !slices.Equal(got, target.Args) {
		t.Fatalf("RedactedArgs() = %v, want %v: no following element to redact", got, target.Args)
	}
}

// RedactedArgs must not mutate the raw slice: the transport that actually
// launches the process reads Target.Args directly
func TestRedactedArgsDoesNotMutateTheRawArgs(t *testing.T) {
	target := Target{Kind: TargetStdio, Command: "npx", Args: []string{"--api-key", "sk-live-SECRET"}}
	target.RedactedArgs()
	if target.Args[1] != "sk-live-SECRET" {
		t.Fatalf("Target.Args was mutated by RedactedArgs: %v", target.Args)
	}
}

func TestMarshalJSONRedactsArgs(t *testing.T) {
	target := Target{Kind: TargetStdio, Name: "svc", Command: "npx", Args: []string{"--api-key", "sk-live-SECRET"}}

	data, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), "sk-live-SECRET") {
		t.Fatalf("marshaled Target leaked the secret: %s", data)
	}

	wrapper := struct {
		Target Target `json:"target"`
	}{Target: target}
	data, err = json.Marshal(wrapper)
	if err != nil {
		t.Fatalf("Marshal(wrapper): %v", err)
	}
	if strings.Contains(string(data), "sk-live-SECRET") {
		t.Fatalf("marshaled wrapper leaked the secret: %s", data)
	}

	if target.Args[1] != "sk-live-SECRET" {
		t.Fatalf("Target.Args was mutated by MarshalJSON: %v", target.Args)
	}
}

func TestDescribeRedactsARemoteTargetWithNoName(t *testing.T) {
	target := Target{Kind: TargetRemote, URL: "http://svcuser:s3cr3t-token@127.0.0.1:8793/"}
	if got := target.Describe(); strings.Contains(got, "s3cr3t-token") {
		t.Fatalf("Describe() = %q, leaked the credential", got)
	}
}

func TestMarshalJSONRedactsCredential(t *testing.T) {
	target := Target{Kind: TargetRemote, Name: "svc", URL: "http://svcuser:s3cr3t-token@127.0.0.1:8793/"}

	data, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), "s3cr3t-token") {
		t.Fatalf("marshaled Target leaked the credential: %s", data)
	}

	wrapper := struct {
		Target Target `json:"target"`
	}{Target: target}
	data, err = json.Marshal(wrapper)
	if err != nil {
		t.Fatalf("Marshal(wrapper): %v", err)
	}
	if strings.Contains(string(data), "s3cr3t-token") {
		t.Fatalf("marshaled wrapper leaked the credential: %s", data)
	}

	if target.URL != "http://svcuser:s3cr3t-token@127.0.0.1:8793/" {
		t.Fatalf("Target.URL was mutated by MarshalJSON: %s", target.URL)
	}
}

func TestRedactedURLRedactsWhatItCannotParse(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "space in the host defeats the parser",
			raw:  "https://exa mple.test/sse?api_key=SUPERSECRET123",
			want: "https://exa mple.test/sse?redacted",
		},
		{
			name: "userinfo as well as a query",
			raw:  "https://svcuser:s3cr3t@exa mple.test/sse?token=SUPERSECRET123",
			want: "https://redacted:redacted@exa mple.test/sse?redacted",
		},
		{
			name: "an at sign in the path is not userinfo",
			raw:  "https://exa mple.test/a@b?token=SUPERSECRET123",
			want: "https://exa mple.test/a@b?redacted",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := url.Parse(tc.raw); err == nil {
				t.Fatalf("the fixture must be one url.Parse rejects, or it is not testing this path")
			}
			got := Target{Kind: TargetRemote, URL: tc.raw}.RedactedURL()
			if got != tc.want {
				t.Errorf("RedactedURL() = %q, want %q", got, tc.want)
			}
		})
	}
}
