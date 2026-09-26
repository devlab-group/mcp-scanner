package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/testdata/protocol/fixtures"
)

func streamableSession(t *testing.T) (*session, func()) {
	t.Helper()
	return streamableSessionWithOptions(t, Options{Timeout: 5 * time.Second})
}

func streamableSessionWithOptions(t *testing.T, opts Options) (*session, func()) {
	t.Helper()
	srv := fixtures.StreamableHTTPServer(fixtures.WellBehaved())
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	sess, err := dialSession(ctx, model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"}, opts)
	if err != nil {
		cancel()
		srv.Close()
		t.Fatal(err)
	}
	return sess, func() {
		sess.Close()
		cancel()
		srv.Close()
	}
}

func TestCallToolRefusedWithoutPermission(t *testing.T) {
	sess, cleanup := streamableSession(t) // plain Options: no Probes, no AllowedToolCalls
	defer cleanup()

	_, err := sess.CallTool(context.Background(), "write_note", map[string]any{"text": "hi"})
	if !errors.Is(err, ErrToolCallNotAllowed) {
		t.Fatalf("got %v, want ErrToolCallNotAllowed", err)
	}
}

func TestCallToolAllowedByOptions(t *testing.T) {
	sess, cleanup := streamableSessionWithOptions(t, Options{Probes: analyzer.ProbeToolCalls, AllowedToolCalls: []string{"write_note"}})
	defer cleanup()

	res, err := sess.CallTool(context.Background(), "write_note", map[string]any{"text": "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Text) == 0 || res.Text[0] != "saved" {
		t.Fatalf("got %+v", res)
	}
}

func TestCallToolAllowlistIsPerTool(t *testing.T) {
	sess, cleanup := streamableSessionWithOptions(t, Options{Probes: analyzer.ProbeToolCalls, AllowedToolCalls: []string{"search"}})
	defer cleanup()

	// Allowing "search" must not permit calling a different tool
	if _, err := sess.CallTool(context.Background(), "write_note", map[string]any{"text": "hi"}); !errors.Is(err, ErrToolCallNotAllowed) {
		t.Fatalf("got %v, want ErrToolCallNotAllowed", err)
	}
}

func TestCallToolRefusedBelowToolCallsProbeLevel(t *testing.T) {
	// The allowlist alone is not enough: ProbeSafe must not grant tool calls,
	// the same rule AnalysisContext.ToolCallAllowed enforces on the analyzer
	// side of this gate
	sess, cleanup := streamableSessionWithOptions(t, Options{Probes: analyzer.ProbeSafe, AllowedToolCalls: []string{"write_note"}})
	defer cleanup()

	if _, err := sess.CallTool(context.Background(), "write_note", map[string]any{"text": "hi"}); !errors.Is(err, ErrToolCallNotAllowed) {
		t.Fatalf("got %v, want ErrToolCallNotAllowed", err)
	}
}

func TestReadResource(t *testing.T) {
	sess, cleanup := streamableSession(t)
	defer cleanup()

	res, err := sess.ReadResource(context.Background(), "fixture://notes/readme")
	if err != nil {
		t.Fatal(err)
	}
	if res.Text == "" {
		t.Fatal("resource content was empty")
	}
}

func TestCallUnknownMethod(t *testing.T) {
	sess, cleanup := streamableSession(t)
	defer cleanup()

	_, err := sess.Call(context.Background(), "totally/unknown/method", nil)
	if err == nil {
		t.Fatal("server accepted a completely unknown method")
	}
	var perr *analyzer.ProtocolError
	if errors.As(err, &perr) && perr.Code != -32601 {
		t.Fatalf("code = %d, want -32601 (method not found)", perr.Code)
	}
}

func TestCallInvalidParams(t *testing.T) {
	sess, cleanup := streamableSession(t)
	defer cleanup()

	_, err := sess.Call(context.Background(), "tools/call", map[string]any{"name": 12345})
	var perr *analyzer.ProtocolError
	if !errors.As(err, &perr) {
		t.Fatalf("got %v (%T), want *analyzer.ProtocolError", err, err)
	}
	if perr.Code != -32602 && perr.Code != -32600 {
		t.Fatalf("code = %d, want -32602 or -32600", perr.Code)
	}
}

func TestCallMalformedRequest(t *testing.T) {
	sess, cleanup := streamableSession(t)
	defer cleanup()

	_, err := sess.Call(context.Background(), "", 42)
	if err == nil {
		t.Fatal("server accepted a malformed request")
	}
	var perr *analyzer.ProtocolError
	if errors.As(err, &perr) && perr.Code != -32600 && perr.Code != -32700 && perr.Code != -32601 {
		t.Fatalf("code = %d, want -32600, -32700 or -32601", perr.Code)
	}
}

func TestCallProbeChannelIsIndependentOfPrimary(t *testing.T) {
	sess, cleanup := streamableSession(t)
	defer cleanup()

	if _, err := sess.Call(context.Background(), "totally/unknown/method", nil); err == nil {
		t.Fatal("expected an error for an unknown method")
	}
	// The primary session must still work after a probe
	if sess.Snapshot() == nil {
		t.Fatal("snapshot lost after a probe")
	}
	res, err := sess.ReadResource(context.Background(), "fixture://notes/readme")
	if err != nil {
		t.Fatalf("primary session broke after a probe: %v", err)
	}
	if res.Text == "" {
		t.Fatal("resource content was empty after a probe")
	}
}

func TestCallInitializeWithUnsupportedProtocolVersion(t *testing.T) {
	sess, cleanup := streamableSession(t)
	defer cleanup()

	params := map[string]any{
		"protocolVersion": "1999-01-01",
		"clientInfo":      map[string]any{"name": "probe", "version": "0"},
		"capabilities":    map[string]any{},
	}
	raw, err := sess.Call(context.Background(), "initialize", params)
	if err != nil {
		if _, ok := errors.AsType[*analyzer.ProtocolError](err); !ok {
			t.Fatalf("got %v (%T), want a clean protocol rejection", err, err)
		}
		return
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if jerr := json.Unmarshal(raw, &result); jerr != nil {
		t.Fatalf("server accepted the request but returned garbage: %v", jerr)
	}
	if result.ProtocolVersion == "" {
		t.Fatal("server accepted the request without negotiating a supported version")
	}
}

// A request closed without a response has no HTTP status. Requests that receive a response keep
// their own status.
func TestCallFailureCarriesOnlyItsOwnStatus(t *testing.T) {
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return fixtures.WellBehaved() }, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.Contains(body, []byte("drop/me")):
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
			return
		case bytes.Contains(body, []byte("forbid/me")):
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := dialSession(ctx, model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"}, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	_, err = sess.Call(ctx, "drop/me", nil)
	var sc analyzer.StatusCoder
	if errors.As(err, &sc) {
		t.Errorf("a dropped request carries status %d from another request", sc.Status())
	}
	if !errors.Is(err, analyzer.ErrConnectionClosed) {
		t.Errorf("a dropped request is not marked as closed: %v", err)
	}

	_, err = sess.Call(ctx, "forbid/me", nil)
	if !errors.As(err, &sc) || sc.Status() != http.StatusForbidden {
		t.Errorf("a refused request lost its own 403: %v", err)
	}
	if errors.Is(err, analyzer.ErrConnectionClosed) {
		t.Errorf("a request the server answered with 403 is marked as closed: %v", err)
	}
}
