package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func TestNewRejectsUnknownKind(t *testing.T) {
	if _, _, err := New(model.Target{}, "carrier-pigeon", Policy{}); err == nil {
		t.Fatal("unknown transport kind was accepted")
	}
}

func TestNewStdioNeedsCommand(t *testing.T) {
	if _, _, err := New(model.Target{Kind: model.TargetStdio}, KindStdio, Policy{}); err == nil {
		t.Fatal("stdio transport built without a command")
	}
}

func TestNewStreamableEnforcesURLPolicy(t *testing.T) {
	target := model.Target{Kind: model.TargetRemote, URL: "http://127.0.0.1:9999/mcp"}
	if _, _, err := New(target, KindStreamable, Policy{}); err == nil {
		t.Fatal("loopback streamable target was accepted")
	}
	if _, _, err := New(target, KindStreamable, Policy{AllowPrivateNetworks: true}); err != nil {
		t.Fatalf("opted-in loopback target rejected: %v", err)
	}
}

func TestNewStreamableReturnsARedirectAttemptsTracker(t *testing.T) {
	target := model.Target{Kind: model.TargetRemote, URL: "http://127.0.0.1:9999/mcp"}
	_, attempts, err := New(target, KindStreamable, Policy{AllowPrivateNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	if attempts == nil {
		t.Fatal("expected a non-nil *RedirectAttempts for an HTTP-based transport")
	}
}

func TestNewStdioHasNoRedirectAttemptsTracker(t *testing.T) {
	_, attempts, err := New(model.Target{Kind: model.TargetStdio, Command: "env"}, KindStdio, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != nil {
		t.Fatal("expected a nil *RedirectAttempts for stdio, which has no redirects")
	}
}

func TestNewStdioEnvIsAllowlisted(t *testing.T) {
	os.Setenv("MCP_SCANNER_TEST_SECRET", "should-not-leak")
	defer os.Unsetenv("MCP_SCANNER_TEST_SECRET")

	target := model.Target{
		Kind:    model.TargetStdio,
		Command: "env",
		Env:     map[string]string{"DECLARED": "yes"},
	}
	tr, _, err := New(target, KindStdio, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	ct, ok := tr.(*mcp.CommandTransport)
	if !ok {
		t.Fatalf("got %T, want *mcp.CommandTransport", tr)
	}
	env := ct.Command.Env
	found := map[string]bool{}
	for _, kv := range env {
		found[kv] = true
	}
	if !found["DECLARED=yes"] {
		t.Fatal("declared env var was not passed through")
	}
	for _, kv := range env {
		if kv == "MCP_SCANNER_TEST_SECRET=should-not-leak" {
			t.Fatal("the scanner's own environment leaked into the child process")
		}
	}
}

func TestHTTPClientBoundsResponseBody(t *testing.T) {
	old := maxResponseBytes
	maxResponseBytes = 16
	defer func() { maxResponseBytes = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 64))) // well past the 16-byte cap
	}))
	defer srv.Close()

	mt := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	client, _ := httpClient(mt, Policy{AllowPrivateNetworks: true})

	resp, err := client.Get(mt.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("expected an error reading a body over the cap, got nil")
	}
}

func TestHTTPClientDoesNotBoundEventStreamResponsesLikeAOneShotReply(t *testing.T) {
	old := maxResponseBytes
	maxResponseBytes = 16
	defer func() { maxResponseBytes = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(strings.Repeat("x", 64))) // over the one-shot cap, but this is a stream
	}))
	defer srv.Close()

	mt := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	client, _ := httpClient(mt, Policy{AllowPrivateNetworks: true})

	resp, err := client.Get(mt.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("an event-stream response was bounded like a one-shot reply: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("got %d bytes, want the full 64: an event-stream body must not be capped by the one-shot reply cap", len(got))
	}
}

// The SDK has no per-message SSE bound, so the transport caps total stream bytes instead.
// Crossing that cap must return an error rather than a normal-looking end of stream.
func TestHTTPClientBoundsEventStreamTotalBytes(t *testing.T) {
	old := maxEventStreamBytes
	maxEventStreamBytes = 16
	defer func() { maxEventStreamBytes = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(strings.Repeat("x", 64))) // well past the 16-byte event-stream cap
	}))
	defer srv.Close()

	mt := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	client, _ := httpClient(mt, Policy{AllowPrivateNetworks: true})

	resp, err := client.Get(mt.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("expected an error reading an event-stream body over the total cap, got nil")
	}
}

func TestOriginGatedHeadersOnlyInjectsSameOrigin(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	origin, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: originGatedHeaders{
		headers: map[string]string{"Authorization": "Bearer secret"}, origin: origin, base: http.DefaultTransport,
	}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("got Authorization %q, want %q", gotAuth, "Bearer secret")
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("the caller's request object was mutated")
	}
}

func TestOriginGatedHeadersSkipsCrossOrigin(t *testing.T) {
	var sawAuth bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization") != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	// Deliberately not `other`'s origin: this is the shape of a request
	// RoundTrip sees on a redirect hop to a different host
	origin, _ := url.Parse("https://example.com")
	client := &http.Client{Transport: originGatedHeaders{
		headers: map[string]string{"Authorization": "Bearer secret"}, origin: origin, base: http.DefaultTransport,
	}}
	req, _ := http.NewRequest(http.MethodGet, other.URL, nil)
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
	if sawAuth {
		t.Fatal("Authorization was sent to a different origin than the one the connection started from")
	}
}

func TestHTTPClientRefusesCrossOriginRedirectHeaderLeak(t *testing.T) {
	var attackerReached bool
	var attackerSawAuth string
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerReached = true
		attackerSawAuth = r.Header.Get("Authorization")
		w.Write([]byte("landed"))
	}))
	defer attacker.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusFound)
	}))
	defer target.Close()

	mt := model.Target{
		Kind: model.TargetRemote, URL: target.URL,
		Headers: map[string]string{"Authorization": "Bearer secret"},
	}
	client, attempts := httpClient(mt, Policy{AllowPrivateNetworks: true})

	if _, err := client.Get(mt.URL); err == nil {
		t.Fatal("a cross-origin redirect was followed")
	}
	if attackerReached {
		t.Fatal("the redirect target was reached at all")
	}
	if attackerSawAuth != "" {
		t.Fatalf("the Authorization header reached the other origin: %q", attackerSawAuth)
	}
	if len(attempts.Notes()) != 1 {
		t.Fatalf("got %d recorded redirect attempts, want 1: %v", len(attempts.Notes()), attempts.Notes())
	}
}

// Legacy SSE can announce an absolute POST endpoint without using an HTTP redirect.
// The origin guard must refuse that request before the attacker server is reached.
func TestHTTPClientRefusesSSEEndpointEventToAnotherOrigin(t *testing.T) {
	var attackerReached bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerReached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	held := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: endpoint\ndata: %s/msg\n\n", attacker.URL)
		w.(http.Flusher).Flush()
		<-held
	}))
	defer target.Close()
	defer close(held)

	mt := model.Target{Kind: model.TargetRemote, URL: target.URL}
	client, attempts := httpClient(mt, Policy{AllowPrivateNetworks: true})

	tr := &mcp.SSEClientTransport{Endpoint: mt.URL, HTTPClient: client}
	conn, err := tr.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	msg, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","method":"notifications/test"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(context.Background(), msg); err == nil {
		t.Fatal("a POST to the endpoint event's different-origin URL was not refused")
	}
	if attackerReached {
		t.Fatal("the endpoint event's origin was reached")
	}
	if notes := attempts.Notes(); len(notes) != 1 {
		t.Fatalf("got %d recorded attempts, want 1: %v", len(notes), notes)
	}
}

func TestHTTPClientAllowsSSEEndpointEventSameOriginDifferentPath(t *testing.T) {
	var posted bool

	held := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: endpoint\ndata: /message?session=abc\n\n")
		w.(http.Flusher).Flush()
		<-held
	})
	mux.HandleFunc("/message", func(w http.ResponseWriter, r *http.Request) {
		posted = true
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer close(held)

	mt := model.Target{Kind: model.TargetRemote, URL: srv.URL + "/sse"}
	client, attempts := httpClient(mt, Policy{AllowPrivateNetworks: true})

	tr := &mcp.SSEClientTransport{Endpoint: mt.URL, HTTPClient: client}
	conn, err := tr.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	msg, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","method":"notifications/test"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(context.Background(), msg); err != nil {
		t.Fatalf("a same-origin endpoint at a different path was refused: %v", err)
	}
	if !posted {
		t.Fatal("the message endpoint was never reached")
	}
	if notes := attempts.Notes(); len(notes) != 0 {
		t.Fatalf("a same-origin request was recorded as refused: %v", notes)
	}
}

func TestHTTPClientFollowsSameOriginRedirectWithHeader(t *testing.T) {
	var landedAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/landed", http.StatusFound)
	})
	mux.HandleFunc("/landed", func(w http.ResponseWriter, r *http.Request) {
		landedAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mt := model.Target{
		Kind: model.TargetRemote, URL: srv.URL + "/start",
		Headers: map[string]string{"Authorization": "Bearer secret"},
	}
	client, attempts := httpClient(mt, Policy{AllowPrivateNetworks: true})

	resp, err := client.Get(mt.URL)
	if err != nil {
		t.Fatalf("a same-origin redirect was refused: %v", err)
	}
	resp.Body.Close()
	if landedAuth != "Bearer secret" {
		t.Fatalf("Authorization did not reach the same-origin redirect target, got %q", landedAuth)
	}
	if notes := attempts.Notes(); len(notes) != 0 {
		t.Fatalf("a same-origin redirect was recorded as refused: %v", notes)
	}
}

func TestInitializeHeaderForwardsAnOversizedBodyIntact(t *testing.T) {
	big := bytes.Repeat([]byte("x"), maxHandshakePeek+4096)
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		if r.Header.Get("Mcp-Session-Id") != "" {
			t.Errorf("the handshake header was set on a body that is not a handshake")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, _, err := NewWithProposedSessionID(model.Target{Kind: model.TargetRemote, URL: srv.URL},
		KindStreamable, Policy{AllowPrivateNetworks: true}, "PROPOSED")
	if err != nil {
		t.Fatal(err)
	}
	hc := tr.(interface{ HTTPClient() *http.Client }).HTTPClient()

	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if len(got) != len(big) {
		t.Fatalf("the server received %d bytes of a %d byte body", len(got), len(big))
	}
}

func TestEveryHTTPTransportCarriesItsClient(t *testing.T) {
	for _, kind := range []string{KindStreamable, KindSSE} {
		tr, _, err := New(model.Target{Kind: model.TargetRemote, URL: "https://example.test/mcp"}, kind, Policy{})
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		carrier, ok := tr.(interface{ HTTPClient() *http.Client })
		if !ok {
			t.Fatalf("%s transport does not carry its client, so a caller must guess at its concrete type", kind)
		}
		if carrier.HTTPClient() == nil {
			t.Fatalf("%s transport carries a nil client", kind)
		}
	}
}

// Every transport wrapper must retain a proxy-free base so the dial guard checks the target
func TestHTTPClientNeverUsesAProxy(t *testing.T) {
	c, _ := httpClient(model.Target{Kind: model.TargetRemote, URL: "https://mcp.example/mcp"}, Policy{})
	var rt http.RoundTripper = c.Transport
	for {
		switch w := rt.(type) {
		case originOnly:
			rt = w.base
			continue
		case originGatedHeaders:
			rt = w.base
			continue
		case boundedBody:
			rt = w.base
			continue
		case *http.Transport:
			if w.Proxy != nil {
				t.Fatal("the MCP client's transport has a Proxy function")
			}
		default:
			t.Fatalf("unexpected transport layer %T; extend this walk when adding one", rt)
		}
		return
	}
}
