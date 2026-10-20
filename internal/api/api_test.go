package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/pkg/scanner"
)

type fakeAnalyzer struct {
	name string
	slow time.Duration
}

func (f fakeAnalyzer) Name() string { return f.name }
func (f fakeAnalyzer) Analyze(ctx context.Context, _ model.Target, _ *analyzer.AnalysisContext) model.AnalyzerResult {
	if f.slow > 0 {
		select {
		case <-time.After(f.slow):
		case <-ctx.Done():
		}
	}

	return model.AnalyzerResult{
		Analyzer: f.name, Status: model.AnalyzerCompleted, Required: true,
		Coverage: model.Coverage{CapabilitiesDiscovered: 1, CapabilitiesAnalyzed: 1},
	}
}

func testScanner(t *testing.T, slow time.Duration) *scanner.Scanner {
	t.Helper()
	reg := analyzer.NewRegistry()
	reg.Register(fakeAnalyzer{name: "a", slow: slow})
	return scanner.New(reg, nil, nil)
}

func newTestServer(t *testing.T, sc *scanner.Scanner, opts Options) *httptest.Server {
	t.Helper()
	srv, err := NewServer(sc, opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func submitAndWait(t *testing.T, ts *httptest.Server, body string) getResponse {
	t.Helper()
	resp, err := http.Post(ts.URL+"/v1/scans", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status = %d", resp.StatusCode)
	}
	var sub submitResponse
	json.NewDecoder(resp.Body).Decode(&sub)

	var final getResponse
	for range 200 {
		final = getScan(t, ts, sub.ID)
		if final.Status == string(statusDone) || final.Status == string(statusError) {
			return final
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scan never finished")
	return final
}

func getScan(t *testing.T, ts *httptest.Server, id string) getResponse {
	t.Helper()
	resp, err := http.Get(ts.URL + "/v1/scans/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var g getResponse
	json.NewDecoder(resp.Body).Decode(&g)
	return g
}

func TestSubmitAndPollHappyPath(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default()})
	final := submitAndWait(t, ts, `{"target": {"kind": "remote", "url": "https://example.com/mcp"}}`)
	if final.Status != string(statusDone) {
		t.Fatalf("status = %s, want DONE (%s)", final.Status, final.Message)
	}
	if final.Result == nil || final.Result.Verdict != model.VerdictSafe {
		t.Fatalf("expected a SAFE verdict, got %+v", final.Result)
	}
	if final.Pass == nil || !*final.Pass || final.ExitCode == nil || *final.ExitCode != policy.ExitOK {
		t.Fatalf("expected pass=true exit_code=0, got pass=%v exit=%v", final.Pass, final.ExitCode)
	}
}

func TestInvalidTargetIsBadRequest(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default()})
	resp, err := http.Post(ts.URL+"/v1/scans", "application/json", strings.NewReader(`{"target": {"kind": "remote"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (a remote target with no url)", resp.StatusCode)
	}
}

func TestSubmitRejectsUnknownTransport(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default()})
	resp, err := http.Post(ts.URL+"/v1/scans", "application/json",
		strings.NewReader(`{"target": {"kind": "remote", "url": "https://example.com/mcp", "transport": "carrier-pigeon"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (an unknown transport)", resp.StatusCode)
	}
}

// TestSubmitAcceptsAKnownTransport is the control: a named transport the
// connection layer actually understands must still reach a scan, not be
// caught by the same check
func TestSubmitAcceptsAKnownTransport(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default()})
	final := submitAndWait(t, ts, `{"target": {"kind": "remote", "url": "https://example.com/mcp", "transport": "streamable"}}`)
	if final.Status != string(statusDone) {
		t.Fatalf("status = %s, want DONE (%s)", final.Status, final.Message)
	}
}

func TestUnknownIDIs404(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default()})
	resp, err := http.Get(ts.URL + "/v1/scans/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHealthzAndReadyz(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default()})
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, resp.StatusCode)
		}
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default(), MaxBodyBytes: 32})
	body := `{"target": {"kind": "source", "path": "` + strings.Repeat("x", 100) + `"}}`
	resp, err := http.Post(ts.URL+"/v1/scans", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an oversized body", resp.StatusCode)
	}
}

func TestConcurrentScanLimitIsRespected(t *testing.T) {
	sc := testScanner(t, 100*time.Millisecond)
	ts := newTestServer(t, sc, Options{Policy: policy.Default(), MaxConcurrentScans: 1})

	var wg sync.WaitGroup
	statuses := make([]string, 3)
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i] = submitAndWait(t, ts, `{"target": {"kind": "remote", "url": "https://example.com/mcp"}}`).Status
		}(i)
	}
	wg.Wait()
	for _, st := range statuses {
		if st != string(statusDone) {
			t.Fatalf("scan did not finish cleanly under the concurrency limit: %s", st)
		}
	}
}

func TestInFlightCapHoldsUnderConcurrentSubmission(t *testing.T) {
	const maxInFlight = 5
	const submitters = 30
	sc := testScanner(t, 200*time.Millisecond)
	ts := newTestServer(t, sc, Options{Policy: policy.Default(), MaxInFlight: maxInFlight, MaxConcurrentScans: maxInFlight})

	var wg sync.WaitGroup
	var accepted atomic.Int64
	for range submitters {
		wg.Go(func() {
			resp, err := http.Post(ts.URL+"/v1/scans", "application/json", strings.NewReader(`{"target": {"kind": "remote", "url": "https://example.com/mcp"}}`))
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusAccepted:
				accepted.Add(1)
			case http.StatusTooManyRequests:
				// expected once the cap is hit
			default:
				t.Errorf("unexpected status %d", resp.StatusCode)
			}
		})
	}
	wg.Wait()

	if got := accepted.Load(); got > maxInFlight {
		t.Fatalf("accepted %d submissions concurrently, cap is %d", got, maxInFlight)
	}
	if accepted.Load() == 0 {
		t.Fatal("nothing was accepted - test is not exercising the cap")
	}
}

// The task's specific regression case: a client-submitted Authorization
// header must never appear anywhere in the stored/returned result
func TestSubmittedAuthorizationHeaderNeverEchoed(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default()})
	secret := "Bearer super-secret-value-should-never-leak"

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/scans", strings.NewReader(`{"target": {"kind": "remote", "url": "https://example.com/mcp", "headers": {"Authorization": "Bearer target-secret-abc"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", secret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sub submitResponse
	json.NewDecoder(resp.Body).Decode(&sub)

	var final getResponse
	for range 200 {
		final = getScan(t, ts, sub.ID)
		if final.Status == string(statusDone) || final.Status == string(statusError) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	raw, _ := json.Marshal(final)
	if strings.Contains(string(raw), "super-secret-value-should-never-leak") {
		t.Fatalf("the API's own Authorization header leaked into the stored result: %s", raw)
	}
	if strings.Contains(string(raw), "target-secret-abc") {
		t.Fatalf("the target's own auth header leaked into the stored result: %s", raw)
	}
}

func TestStdioTargetRejectedByDefault(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default()})
	resp, err := http.Post(ts.URL+"/v1/scans", "application/json",
		strings.NewReader(`{"target": {"kind": "stdio", "command": "/bin/sh", "args": ["-c", "id"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a stdio target with no opt-in", resp.StatusCode)
	}
}

// Process and filesystem target kinds require authentication. BaseDir is set so authentication
// is the only validation failure in each case.
func TestServerRefusesToStartWithSensitiveKindAndNoToken(t *testing.T) {
	for _, kind := range []model.TargetKind{model.TargetStdio, model.TargetSource, model.TargetStatic, model.TargetPackage} {
		_, err := NewServer(testScanner(t, 0), Options{
			Policy:             policy.Default(),
			AllowedTargetKinds: []model.TargetKind{model.TargetRemote, kind},
			BaseDir:            t.TempDir(),
		})
		if err == nil || !strings.Contains(err.Error(), "no auth token") {
			t.Errorf("%s with no auth token: NewServer = %v, want a refusal naming the token", kind, err)
		}
	}
}

// The three required scenarios: unauthenticated stdio is
// rejected, a valid token with the kind enabled is accepted, a wrong token
// is rejected
func TestStdioRequiresValidToken(t *testing.T) {
	t.Setenv("MCP_SCANNER_API_TEST_TOKEN", "correct-horse-battery-staple")
	srv, err := NewServer(testScanner(t, 0), Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetRemote, model.TargetStdio},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := `{"target": {"kind": "stdio", "command": "true"}}`

	post := func(token string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/scans", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if resp := post(""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", resp.StatusCode)
	}
	if resp := post("wrong-token"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", resp.StatusCode)
	}
	resp := post("correct-horse-battery-staple")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("correct token: status = %d, want 202", resp.StatusCode)
	}
	resp.Body.Close()
}

// GET must be gated the same way POST is, once a token is configured
func TestGetRequiresTokenOnceConfigured(t *testing.T) {
	t.Setenv("MCP_SCANNER_API_TEST_TOKEN2", "sekret")
	srv, err := NewServer(testScanner(t, 0), Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetRemote, model.TargetStdio},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN2",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/scans/anything")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET: status = %d, want 401", resp.StatusCode)
	}
}

// /healthz and /readyz stay open even with a token configured
func TestHealthEndpointsStayOpenWithToken(t *testing.T) {
	t.Setenv("MCP_SCANNER_API_TEST_TOKEN3", "sekret")
	srv, err := NewServer(testScanner(t, 0), Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetRemote, model.TargetStdio},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN3",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d, want 200 even with a token configured", path, resp.StatusCode)
		}
	}
}

// Enabling TargetSource without a BaseDir must also refuse to start
func TestServerRefusesToStartWithSourceAndNoBaseDir(t *testing.T) {
	t.Setenv("MCP_SCANNER_API_TEST_TOKEN4", "sekret")
	_, err := NewServer(testScanner(t, 0), Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetSource},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN4",
	})
	if err == nil {
		t.Fatal("NewServer accepted TargetSource with no BaseDir configured")
	}
}

type capturingAnalyzer struct{ captured *string }

func (c capturingAnalyzer) Name() string { return "a" }
func (c capturingAnalyzer) Analyze(ctx context.Context, _ model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	*c.captured = ac.Root
	return model.AnalyzerResult{Analyzer: "a", Status: model.AnalyzerCompleted, Required: true}
}

func TestSourcePathMustStayWithinBaseDir(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "project"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "project", "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_SCANNER_API_TEST_TOKEN5", "sekret")

	var capturedRoot string
	reg := analyzer.NewRegistry()
	reg.Register(capturingAnalyzer{captured: &capturedRoot})
	sc := scanner.New(reg, nil, nil)

	srv, err := NewServer(sc, Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetSource},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN5",
		BaseDir:            base,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	post := func(path string) *http.Response {
		body := `{"target": {"kind": "source", "path": "` + path + `"}}`
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/scans", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sekret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if resp := post("../../etc"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("escaping path: status = %d, want 400", resp.StatusCode)
	}

	resp := post("project")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("contained path: status = %d, want 202", resp.StatusCode)
	}
	var sub submitResponse
	json.NewDecoder(resp.Body).Decode(&sub)
	resp.Body.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/scans/"+sub.ID, nil)
	req.Header.Set("Authorization", "Bearer sekret")
	var final getResponse
	for range 200 {
		gr, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(gr.Body).Decode(&final)
		gr.Body.Close()
		if final.Status == string(statusDone) || final.Status == string(statusError) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if final.Status != string(statusDone) {
		t.Fatalf("scan did not finish: %+v", final)
	}

	wantSuffix := filepath.Join(base, "project")
	if !strings.HasSuffix(capturedRoot, wantSuffix) {
		t.Fatalf("scanner.Options.Root = %q, want it to end with %q", capturedRoot, wantSuffix)
	}
}

// A static target reads an arbitrary caller-chosen path too, and
// must be rejected by default exactly like stdio and source are
func TestStaticTargetRejectedByDefault(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default()})
	resp, err := http.Post(ts.URL+"/v1/scans", "application/json",
		strings.NewReader(`{"target": {"kind": "static", "path": "/etc/passwd"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a static target with no opt-in", resp.StatusCode)
	}
}

// Enabling TargetStatic without a BaseDir must also refuse to start
func TestServerRefusesToStartWithStaticAndNoBaseDir(t *testing.T) {
	t.Setenv("MCP_SCANNER_API_TEST_TOKEN_STATIC1", "sekret")
	_, err := NewServer(testScanner(t, 0), Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetStatic},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN_STATIC1",
	})
	if err == nil {
		t.Fatal("NewServer accepted TargetStatic with no BaseDir configured")
	}
}

// A static path outside the configured base directory is
// rejected, and Target.Path ends up set to the resolved, contained path
func TestStaticPathMustStayWithinBaseDir(t *testing.T) {
	base := t.TempDir()
	snapshot := `{"schema_version":"1.0.0","tools":[{"name":"t","description":"d"}]}`
	if err := os.WriteFile(filepath.Join(base, "snap.json"), []byte(snapshot), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_SCANNER_API_TEST_TOKEN_STATIC2", "sekret")

	reg := analyzer.NewRegistry()
	reg.Register(fakeAnalyzer{name: "a"})
	sc := scanner.New(reg, nil, nil)

	srv, err := NewServer(sc, Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetStatic},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN_STATIC2",
		BaseDir:            base,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	post := func(path string) *http.Response {
		body := `{"target": {"kind": "static", "path": "` + path + `"}}`
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/scans", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sekret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if resp := post("../../etc/passwd"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("escaping path: status = %d, want 400", resp.StatusCode)
	}
	if resp := post("/etc/passwd"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("absolute escaping path: status = %d, want 400", resp.StatusCode)
	}
	// A path can be lexically inside the base while a symlink resolves outside it
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "snap.json"), []byte(snapshot), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if resp := post("link/snap.json"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("path through a symlink out of the base: status = %d, want 400", resp.StatusCode)
	}

	resp := post("snap.json")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("contained path: status = %d, want 202", resp.StatusCode)
	}
	resp.Body.Close()
}

type failingPreparer struct{ err error }

func (p failingPreparer) Prepare(context.Context, model.Target) (*analyzer.AnalysisContext, func(), error) {
	return nil, nil, p.err
}

func TestStaticReadErrorIsRedactedNotLeaked(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "target.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_SCANNER_API_TEST_TOKEN_STATIC3", "sekret")

	reg := analyzer.NewRegistry()
	reg.Register(fakeAnalyzer{name: "a"})
	leaky := errors.New("open /etc/shadow: permission denied")
	sc := scanner.New(reg, failingPreparer{err: leaky}, nil)

	srv, err := NewServer(sc, Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetStatic},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN_STATIC3",
		BaseDir:            base,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/scans", strings.NewReader(`{"target": {"kind": "static", "path": "target.json"}}`))
	req.Header.Set("Authorization", "Bearer sekret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var sub submitResponse
	json.NewDecoder(resp.Body).Decode(&sub)
	resp.Body.Close()

	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/scans/"+sub.ID, nil)
	getReq.Header.Set("Authorization", "Bearer sekret")
	var raw []byte
	var final getResponse
	for range 200 {
		gr, err := http.DefaultClient.Do(getReq)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = io.ReadAll(gr.Body)
		gr.Body.Close()
		json.Unmarshal(raw, &final)
		if final.Status == string(statusDone) || final.Status == string(statusError) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if strings.Contains(string(raw), "permission denied") || strings.Contains(string(raw), "/etc/shadow") {
		t.Fatalf("raw filesystem error leaked into the API response: %s", raw)
	}
	if final.Result == nil {
		t.Fatalf("expected a result, got %+v", final)
	}
	found := false
	for _, a := range final.Result.Analyzers {
		for _, e := range a.Errors {
			if e.Message == "target could not be read" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected a redacted \"target could not be read\" analyzer error, got %+v", final.Result.Analyzers)
	}
}

func TestRedactLocalPathErrorsOnlyTouchesDiscoveryFailures(t *testing.T) {
	res := &model.ScanResult{Analyzers: []model.AnalyzerResult{
		{Analyzer: "a", Errors: []model.AnalyzerError{
			{Kind: "network", Message: "target discovery failed: open /etc/shadow: permission denied"},
		}},
		{Analyzer: "b", Errors: []model.AnalyzerError{
			{Kind: "network", Message: "OSV lookup failed: rate limited"},
		}},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	redactLocalPathErrors(res, logger, "scan_1", "")

	if res.Analyzers[0].Errors[0].Message != "target could not be read" {
		t.Fatalf("discovery-failure message was not redacted: %q", res.Analyzers[0].Errors[0].Message)
	}
	if res.Analyzers[1].Errors[0].Message != "OSV lookup failed: rate limited" {
		t.Fatalf("an unrelated analyzer error was altered: %q", res.Analyzers[1].Errors[0].Message)
	}
}

func TestRedactLocalPathErrorsAlsoRedactsWarnings(t *testing.T) {
	res := &model.ScanResult{Warnings: []string{
		`required analyzer "a" reported a non-fatal network error: target discovery failed: open /etc/shadow: permission denied`,
		"every analyzer that ran was best-effort, so no analyzer's result was required for this verdict",
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	redactLocalPathErrors(res, logger, "scan_1", "")

	if res.Warnings[0] != "target could not be read" {
		t.Fatalf("discovery-failure warning was not redacted: %q", res.Warnings[0])
	}
	if res.Warnings[1] != "every analyzer that ran was best-effort, so no analyzer's result was required for this verdict" {
		t.Fatalf("an unrelated warning was altered: %q", res.Warnings[1])
	}
}

// The store must not grow without bound. A cap of 2 with a
// generous retention window means the third put has to evict the oldest.
func TestStoreEvictsOldestOverCap(t *testing.T) {
	s := newStore(time.Hour, 2, defaultMaxStoredBytes)
	s.put(&record{ID: "a", CreatedAt: time.Now().Add(-2 * time.Second)})
	s.put(&record{ID: "b", CreatedAt: time.Now().Add(-1 * time.Second)})
	s.put(&record{ID: "c", CreatedAt: time.Now()})

	if s.count() > 2 {
		t.Fatalf("count() = %d, want at most 2", s.count())
	}
	if _, ok := s.get("a"); ok {
		t.Fatal("oldest record should have been evicted to stay under the cap")
	}
	if _, ok := s.get("c"); !ok {
		t.Fatal("newest record should not have been evicted")
	}
}

func TestStoreNeverEvictsPendingOrRunningRecords(t *testing.T) {
	s := newStore(time.Millisecond, 1, defaultMaxStoredBytes)
	old := time.Now().Add(-time.Hour)
	s.put(&record{ID: "pending", Status: statusPending, CreatedAt: old})
	time.Sleep(5 * time.Millisecond)
	s.put(&record{ID: "running", Status: statusRunning, CreatedAt: old})
	time.Sleep(5 * time.Millisecond)
	s.put(&record{ID: "done", Status: statusDone, CreatedAt: time.Now()})

	if _, ok := s.get("pending"); !ok {
		t.Fatal("a PENDING record must never be evicted")
	}
	if _, ok := s.get("running"); !ok {
		t.Fatal("a RUNNING record must never be evicted")
	}
}

// A record older than the retention window is evicted on the
// next put even if the store is nowhere near its count cap
func TestStoreEvictsExpiredRecords(t *testing.T) {
	s := newStore(10*time.Millisecond, 1000, defaultMaxStoredBytes)
	s.put(&record{ID: "old", CreatedAt: time.Now().Add(-time.Hour)})
	time.Sleep(20 * time.Millisecond)
	s.put(&record{ID: "new", CreatedAt: time.Now()})

	if _, ok := s.get("old"); ok {
		t.Fatal("expired record should have been evicted")
	}
	if _, ok := s.get("new"); !ok {
		t.Fatal("fresh record should still be present")
	}
}

func TestStoreEvictsOldestOverByteCap(t *testing.T) {
	s := newStore(time.Hour, 1000, 100)
	s.put(&record{ID: "a", Status: statusDone, Bytes: 40, CreatedAt: time.Now().Add(-2 * time.Second)})
	s.put(&record{ID: "b", Status: statusDone, Bytes: 40, CreatedAt: time.Now().Add(-1 * time.Second)})
	s.put(&record{ID: "c", Status: statusDone, Bytes: 40, CreatedAt: time.Now()})

	if _, ok := s.get("a"); ok {
		t.Fatal("oldest record should have been evicted to stay under the byte cap")
	}
	if _, ok := s.get("b"); !ok {
		t.Fatal("record under the cap should not have been evicted")
	}
	if _, ok := s.get("c"); !ok {
		t.Fatal("newest record should not have been evicted")
	}
	if s.totalBytes > s.maxBytes {
		t.Fatalf("totalBytes = %d, want at most maxBytes = %d", s.totalBytes, s.maxBytes)
	}

	assertTotalBytesAccurate(t, s)
	s.update("b", func(r *record) { r.Bytes = 90 })
	assertTotalBytesAccurate(t, s)
	if s.totalBytes > s.maxBytes {
		t.Fatalf("totalBytes = %d, want at most maxBytes = %d", s.totalBytes, s.maxBytes)
	}
	// b (older) and c (newer) together are now over the cap: oldest first
	// evicts b, even though b is the record that just grew
	if _, ok := s.get("b"); ok {
		t.Fatal("growing b past the cap should have evicted it - it is the oldest record")
	}
	if _, ok := s.get("c"); !ok {
		t.Fatal("newer record should not have been evicted")
	}
}

func assertTotalBytesAccurate(t *testing.T, s *store) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var sum int64
	for _, r := range s.data {
		sum += r.Bytes
	}
	if sum != s.totalBytes {
		t.Fatalf("s.totalBytes = %d, but summing stored records gives %d", s.totalBytes, sum)
	}
}

func TestSubmitFailsClosedWhenScanIDCannotBeGenerated(t *testing.T) {
	old := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("entropy source unavailable") }
	defer func() { randRead = old }()

	ts := newTestServer(t, testScanner(t, 0), Options{Policy: policy.Default()})
	resp, err := http.Post(ts.URL+"/v1/scans", "application/json",
		strings.NewReader(`{"target": {"kind": "remote", "url": "https://example.com/mcp"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: a scan must not run under a predictable fallback id", resp.StatusCode)
	}

	randRead = old
	final := submitAndWait(t, ts, `{"target": {"kind": "remote", "url": "https://example.com/mcp"}}`)
	if final.Status != string(statusDone) {
		t.Fatalf("status = %s, want DONE: the failed submission must not have leaked its inFlight slot", final.Status)
	}
}

func TestGetResponseEscapesHostileText(t *testing.T) {
	res := &model.ScanResult{
		Status:  model.StatusCompleted,
		Verdict: model.VerdictUnsafe,
		Findings: []model.Finding{{
			ID: "f_1", RuleID: "r", Title: "tool ‮name​ here",
			Severity: model.SeverityHigh, Analyzer: "promptdefense",
		}},
	}
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, getResponse{ID: "scan_1", Status: "COMPLETED", Result: res})

	body := rec.Body.String()
	for _, r := range []rune{'‮', '​'} {
		if strings.ContainsRune(body, r) {
			t.Errorf("U+%04X reached the API response unescaped", r)
		}
	}
	if !strings.Contains(body, "u202e") {
		t.Errorf("the escaped form is missing, so the character was dropped rather than escaped:\n%s", body)
	}
}

func TestOversizedResultKeepsItsVerdictWithoutTheSnapshot(t *testing.T) {
	huge := strings.Repeat("A", 4096)
	res := &model.ScanResult{
		Status:  model.StatusCompleted,
		Verdict: model.VerdictUnsafe,
		Snapshot: &model.Snapshot{
			ServerName: "hostile",
			Tools:      []model.ToolInfo{{Name: "search", Description: huge}},
		},
		Findings: []model.Finding{{
			ID: "f_1", RuleID: "promptdefense.exfiltration", Analyzer: "promptdefense",
			Title: "exfiltration", Severity: model.SeverityCritical,
			Evidence: []model.Evidence{{Level: model.EvidenceHeuristic, Kind: "text", Description: "d"}},
		}},
	}

	withSnapshot := resultSize(res)
	st := newStore(time.Hour, 100, withSnapshot-1)

	if ceiling := st.byteCeiling(); withSnapshot <= ceiling {
		t.Fatalf("the fixture is not over the ceiling: %d <= %d", withSnapshot, ceiling)
	}
	res.Snapshot = nil
	if shrunk := resultSize(res); shrunk > st.byteCeiling() {
		t.Fatalf("dropping the snapshot did not bring the result under the ceiling: %d > %d", shrunk, st.byteCeiling())
	}

	st.put(&record{ID: "s1", Status: statusPending, CreatedAt: time.Now()})
	st.update("s1", func(r *record) {
		r.Status = statusDone
		r.Result = res
		r.Bytes = resultSize(res)
	})

	got, ok := st.get("s1")
	if !ok {
		t.Fatal("the record was evicted, so the caller polls a 404 for a scan that ran")
	}
	if got.Result.Verdict != model.VerdictUnsafe || len(got.Result.Findings) != 1 {
		t.Fatalf("the verdict and its finding did not survive: %+v", got.Result)
	}
}

// bigSnapshotPreparer returns a snapshot large enough to exceed the result store limit
type bigSnapshotPreparer struct{ description string }

func (p bigSnapshotPreparer) Prepare(ctx context.Context, target model.Target) (*analyzer.AnalysisContext, func(), error) {
	return &analyzer.AnalysisContext{
		Snapshot:  &model.Snapshot{ServerName: "big", Tools: []model.ToolInfo{{Name: "t", Description: p.description}}},
		Artifacts: analyzer.NewArtifacts(),
	}, func() {}, nil
}

// The handler drops an oversized snapshot while preserving the verdict and warning the caller
func TestHandlerDropsTheSnapshotOfAnOversizedResult(t *testing.T) {
	reg := analyzer.NewRegistry()
	reg.Register(fakeAnalyzer{name: "a"})
	sc := scanner.New(reg, bigSnapshotPreparer{description: strings.Repeat("A", 64<<10)}, nil)
	ts := newTestServer(t, sc, Options{Policy: policy.Default(), MaxStoredBytes: 16 << 10})

	final := submitAndWait(t, ts, `{"target": {"kind": "remote", "url": "https://mcp.example/mcp"}}`)
	if final.Status != string(statusDone) || final.Result == nil {
		t.Fatalf("status = %s (%s): the oversized result was not kept", final.Status, final.Message)
	}
	if final.Result.Snapshot != nil {
		t.Fatal("the snapshot of an oversized result was stored")
	}
	if final.Result.Verdict != model.VerdictSafe {
		t.Fatalf("verdict = %s, want the scan's own SAFE to survive the drop", final.Result.Verdict)
	}
	warned := false
	for _, w := range final.Result.Warnings {
		if strings.Contains(w, "snapshot was dropped") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("no warning says the snapshot was dropped: %v", final.Result.Warnings)
	}
}
