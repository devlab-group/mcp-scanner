package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpclient "github.com/revinand/mcp-scanner/internal/mcp/client"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/testdata/protocol/fixtures"
)

// unknownMethod is the request that makes the crash fixtures exit
const unknownMethod = "mcp-scanner/definitely-not-a-real-method"

// crashingStdioEnv makes the test binary serve stdio and exit on unknownMethod. It dispatches
// requests directly because the Go SDK rejects that method before a handler can crash.
const crashingStdioEnv = "MCP_SCANNER_PROTOCOL_CRASHING_STDIO"

func TestMain(m *testing.M) {
	if os.Getenv(crashingStdioEnv) != "" {
		runCrashingStdioServer()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runCrashingStdioServer() {
	dec := json.NewDecoder(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for {
		var msg struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		if err := dec.Decode(&msg); err != nil {
			return
		}
		if msg.ID == nil {
			continue
		}
		switch msg.Method {
		case "initialize":
			enc.Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{
				"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
				"serverInfo": map[string]any{"name": "crashing", "version": "1"}}})
		case "ping":
			enc.Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{}})
		case unknownMethod:
			os.Exit(3)
		default:
			enc.Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
		}
	}
}

// analyzeThroughTheRealStack preserves the failure classification produced by the real session
func analyzeThroughTheRealStack(t *testing.T, target model.Target) model.AnalyzerResult {
	t.Helper()
	opts := mcpclient.Options{Timeout: 5 * time.Second, AllowPrivateNetworks: true}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ac, cleanup, err := mcpclient.NewPreparer(opts).Prepare(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ac.Probes = analyzer.ProbeSafe
	ac.Dialer = mcpclient.NewDialer(opts)
	return protocolAnalyzer{}.Analyze(ctx, target, ac)
}

func countRule(fs []model.Finding, rule string) int {
	n := 0
	for _, f := range fs {
		if f.RuleID == rule {
			n++
		}
	}
	return n
}

// dropProbeConnection closes the unknown-method request without answering. When alwaysAfter is
// set, later requests also fail as if the server went away.
func dropProbeConnection(alwaysAfter bool) *httptest.Server {
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return fixtures.WellBehaved() }, nil)
	var gone atomic.Bool
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if gone.Load() || bytes.Contains(body, []byte(unknownMethod)) {
			gone.Store(alwaysAfter)
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h.ServeHTTP(w, r)
	}))
}

// A stdio server that exits on a probe must produce a connection-died finding
func TestProbeThatKillsAStdioServerIsReported(t *testing.T) {
	res := analyzeThroughTheRealStack(t, model.Target{
		Kind: model.TargetStdio, Command: os.Args[0], Env: map[string]string{crashingStdioEnv: "1"},
	})
	if n := countRule(res.Findings, RuleProbeConnectionDied); n != 1 {
		t.Fatalf("want one %s finding, got %d: %+v", RuleProbeConnectionDied, n, res.Findings)
	}
}

// A dropped request must not inherit an earlier response status and look accepted
func TestProbeWhoseConnectionIsDroppedIsNotReadAsAccepted(t *testing.T) {
	srv := dropProbeConnection(false)
	defer srv.Close()
	res := analyzeThroughTheRealStack(t, model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"})
	if n := countRule(res.Findings, RuleProbeConnectionDied); n != 1 {
		t.Fatalf("want one %s finding, got %d: %+v", RuleProbeConnectionDied, n, res.Findings)
	}
	for _, f := range res.Findings {
		if f.RuleID == RuleProbeAcceptedUnanswered && bytes.Contains([]byte(f.Description), []byte("unknown method")) {
			t.Fatalf("the dropped probe was read as accepted: %s", f.Description)
		}
	}
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s: the server kept answering, so every probe ran", res.Status)
	}
}

// Once the server is gone, report one death and mark the undelivered probes as partial coverage
func TestServerThatGoesAwayIsReportedOnce(t *testing.T) {
	srv := dropProbeConnection(true)
	defer srv.Close()
	res := analyzeThroughTheRealStack(t, model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"})
	if n := countRule(res.Findings, RuleProbeConnectionDied); n != 1 {
		t.Fatalf("want one %s finding, got %d: %+v", RuleProbeConnectionDied, n, res.Findings)
	}
	if res.Status != model.AnalyzerPartial {
		t.Fatalf("status = %s, want PARTIAL: the remaining probes never ran", res.Status)
	}
}
