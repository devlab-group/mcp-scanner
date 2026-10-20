package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/testdata/protocol/fixtures"
)

func stdioFixtureTarget(kind string) model.Target {
	return model.Target{
		Kind:    model.TargetStdio,
		Command: os.Args[0],
		Env:     map[string]string{stdioFixtureEnv: kind},
	}
}

func TestConnectStdio(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sess, err := dialSession(ctx, stdioFixtureTarget("well-behaved"), Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if sess.Snapshot().ServerName != "well-behaved" {
		t.Fatalf("server name = %q", sess.Snapshot().ServerName)
	}
	if sess.Snapshot().Transport.Kind != "stdio" {
		t.Fatalf("transport kind = %q, want stdio", sess.Snapshot().Transport.Kind)
	}
}

func TestConnectStreamableHTTP(t *testing.T) {
	srv := fixtures.StreamableHTTPServer(fixtures.WellBehaved())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"}
	sess, err := dialSession(ctx, target, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	assertSawTheFixture(t, sess)
	if sess.Snapshot().Transport.Kind != "streamable-http" {
		t.Fatalf("transport kind = %q, want streamable-http", sess.Snapshot().Transport.Kind)
	}
}

func TestConnectSSE(t *testing.T) {
	srv := fixtures.SSEServer(fixtures.WellBehaved())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "sse"}
	sess, err := dialSession(ctx, target, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if sess.Snapshot().Transport.Kind != "sse" {
		t.Fatalf("transport kind = %q, want sse", sess.Snapshot().Transport.Kind)
	}

	assertSawTheFixture(t, sess)
}

func assertSawTheFixture(t *testing.T, sess *session) {
	t.Helper()
	snap := sess.Snapshot()
	if len(snap.Tools) != 2 {
		t.Errorf("saw %d tool(s), want the 2 the fixture declares: %+v", len(snap.Tools), snap.Tools)
	}
	if len(snap.Prompts) == 0 {
		t.Errorf("saw no prompts, but the fixture declares one")
	}
	for _, w := range snap.Warnings {
		t.Errorf("discovery warned against a conformant fixture: %s", w)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := sess.Call(ctx, "tools/list", nil); err != nil {
		t.Errorf("the session is not usable after discovery: %v", err)
	}
}

func TestConnectAutoFallsBackToSSE(t *testing.T) {
	srv := fixtures.SSEServer(fixtures.WellBehaved())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "auto"}
	sess, err := dialSession(ctx, target, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if sess.Snapshot().Transport.Kind != "sse" {
		t.Fatalf("auto resolved to %q, want sse", sess.Snapshot().Transport.Kind)
	}
	assertSawTheFixture(t, sess)
}

func TestConnectFailureIsReported(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	target := model.Target{Kind: model.TargetRemote, URL: "https://127.0.0.1:1/mcp", Transport: "streamable"}
	if _, err := dialSession(ctx, target, Options{Timeout: time.Second}); err == nil {
		t.Fatal("connecting to a port nothing listens on did not error")
	}
}

func TestConnectErrorDoesNotLeakAQueryStringCredential(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const secret = "SUPERSECRET123"
	target := model.Target{
		Kind: model.TargetRemote, Transport: "streamable",
		URL: "https://127.0.0.1:1/sse?api_key=" + secret,
	}
	_, err := dialSession(ctx, target, Options{Timeout: 2 * time.Second, AllowPrivateNetworks: true})
	if err == nil {
		t.Fatal("expected a connection error against a refusing port")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("credential leaked into the connection error: %v", err)
	}
	if !strings.Contains(err.Error(), "redacted") {
		t.Fatalf("expected the redacted marker in place of the credential, got: %v", err)
	}
}

func TestOptionsAllowPrivateNetworksIsARealRoute(t *testing.T) {
	old := allowPrivateNetworksForTests
	allowPrivateNetworksForTests = false
	defer func() { allowPrivateNetworksForTests = old }()

	srv := fixtures.StreamableHTTPServer(fixtures.WellBehaved())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"}

	if _, err := dialSession(ctx, target, Options{Timeout: 5 * time.Second}); err == nil {
		t.Fatal("a loopback target was reachable without opting in")
	}

	sess, err := dialSession(ctx, target, Options{Timeout: 5 * time.Second, AllowPrivateNetworks: true})
	if err != nil {
		t.Fatalf("Options.AllowPrivateNetworks did not open a route to a loopback target: %v", err)
	}
	defer sess.Close()
}

func TestConnectHonoursTheTargetsOwnTransport(t *testing.T) {
	srv := fixtures.SSEServer(fixtures.WellBehaved())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"}
	sess, err := dialSession(ctx, target, Options{Timeout: 5 * time.Second})
	if err == nil {
		sess.Close()
		t.Fatalf("streamable against an SSE-only server connected anyway, as %q", sess.Snapshot().Transport.Kind)
	}

	// And the same target named correctly still connects, so the failure
	// above is the transport choice being honoured rather than the fixture
	// being unreachable
	target.Transport = "sse"
	ok, err := dialSession(ctx, target, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("sse against an SSE-only server: %v", err)
	}
	defer ok.Close()
	if got := ok.Snapshot().Transport.Kind; got != "sse" {
		t.Fatalf("connected as %q, want sse", got)
	}
}

// A deployment-wide default still applies when the target names nothing
func TestConnectFallsBackToTheOptionsTransport(t *testing.T) {
	srv := fixtures.SSEServer(fixtures.WellBehaved())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	sess, err := dialSession(ctx, target, Options{Timeout: 5 * time.Second, Transport: "streamable"})
	if err == nil {
		sess.Close()
		t.Fatal("the deployment default was ignored when the target named no transport")
	}
}

func TestValidateTransportRejectsAnUnknownName(t *testing.T) {
	if err := ValidateTransport("bogus"); err == nil {
		t.Fatal("an unknown transport name was accepted")
	}
	for _, ok := range []string{"", "auto", "streamable", "sse", "stdio"} {
		if err := ValidateTransport(ok); err != nil {
			t.Errorf("ValidateTransport(%q) = %v", ok, err)
		}
	}
}

// Record a refused cross-origin redirect in the snapshot consumed by the protocol analyzer
func TestConnectRecordsARefusedCrossOriginRedirect(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the redirect to another origin was followed")
	}))
	defer elsewhere.Close()

	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return fixtures.WellBehaved() }, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"tools/list"`)) {
			http.Redirect(w, r, elsewhere.URL+"/mcp", http.StatusTemporaryRedirect)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		mcpHandler.ServeHTTP(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := dialSession(ctx, model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"}, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if len(sess.Snapshot().RedirectsRefused) == 0 {
		t.Fatalf("the refused redirect was not recorded; warnings %v", sess.Snapshot().Warnings)
	}
}
