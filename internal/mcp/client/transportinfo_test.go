package client

import (
	"net/http"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/internal/mcp/transport"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func TestTransportInfoRedactsTheEndpointCredential(t *testing.T) {
	target := model.Target{Kind: model.TargetRemote, URL: "https://svcuser:s3cr3t-token@example.test/mcp"}

	info := transportInfo(transport.KindStreamable, target, nil, "")

	if strings.Contains(info.Endpoint, "s3cr3t-token") {
		t.Fatalf("endpoint carries the credential: %s", info.Endpoint)
	}
	if strings.Contains(info.Endpoint, "svcuser") {
		t.Errorf("the username goes too: a token passed over basic auth is the username, not the password: %s", info.Endpoint)
	}
	if !strings.Contains(info.Endpoint, "redacted@") {
		t.Errorf("the userinfo marker is worth keeping - a reader needs to know a credential was there: %s", info.Endpoint)
	}
	if !info.TLS {
		t.Errorf("TLS must still be read from the real URL")
	}
}

func TestTransportInfoRecordsOnlyTheAuthChallengeHeader(t *testing.T) {
	target := model.Target{Kind: model.TargetRemote, URL: "https://example.test/mcp"}

	info := transportInfo(transport.KindStreamable, target, nil, "Bearer realm=\"mcp\"")
	if got := info.Headers["WWW-Authenticate"]; got != `Bearer realm="mcp"` {
		t.Fatalf("WWW-Authenticate = %q, want the challenge value", got)
	}
	if len(info.Headers) != 1 {
		t.Fatalf("Headers carries %d entries, want exactly the one header read", len(info.Headers))
	}

	empty := transportInfo(transport.KindStreamable, target, nil, "")
	if empty.Headers != nil {
		t.Fatalf("Headers should be nil when no challenge was seen, got %v", empty.Headers)
	}
}

func TestStatusSnifferCapsAuthChallenge(t *testing.T) {
	sniff := &responseSniff{}
	long := strings.Repeat("a", authChallengeCap+50)
	rt := statusSniffer{base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 401,
			Header:     http.Header{"Www-Authenticate": []string{long}},
			Body:       http.NoBody,
		}, nil
	}), sniff: sniff}

	req, _ := http.NewRequest(http.MethodGet, "https://example.test/mcp", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	got := sniff.authHeader()
	if len(got) <= authChallengeCap {
		t.Fatalf("expected the truncation suffix to push length past the cap, got %d bytes", len(got))
	}
	if !strings.HasPrefix(got, strings.Repeat("a", authChallengeCap)) {
		t.Fatalf("truncated value does not keep the first %d bytes", authChallengeCap)
	}
	if !strings.HasSuffix(got, "...(truncated)") {
		t.Fatalf("truncated value missing the truncation marker: %q", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
