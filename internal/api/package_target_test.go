package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/internal/app"
	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/policy"
	"github.com/revinand/mcp-scanner/internal/testutil"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/pkg/scanner"
)

func TestPackageTargetPathIsNeverTrustedWithTheCallersDirectory(t *testing.T) {
	victim := t.TempDir()
	canary := filepath.Join(victim, "canary.txt")
	if err := os.WriteFile(canary, []byte("do not delete me"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("MCP_SCANNER_API_TEST_TOKEN_PKG", "sekret")
	sc := scanner.New(analyzer.Default, app.NewPreparer(config.Config{}), nil)
	ts := newTestServer(t, sc, Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetPackage},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN_PKG",
		ScanTimeout:        30 * time.Second,
	})

	body := `{"target": {"kind": "package", "ecosystem": "not-a-real-ecosystem", "package": "whatever", "path": "` + victim + `"}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/scans", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sekret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status = %d, want 202", resp.StatusCode)
	}
	var sub submitResponse
	json.NewDecoder(resp.Body).Decode(&sub)
	resp.Body.Close()

	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/scans/"+sub.ID, nil)
	getReq.Header.Set("Authorization", "Bearer sekret")
	var final getResponse
	for range 200 {
		gr, err := http.DefaultClient.Do(getReq)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(gr.Body).Decode(&final)
		gr.Body.Close()
		if final.Status == string(statusDone) || final.Status == string(statusError) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if final.Status != string(statusDone) {
		t.Fatalf("scan did not finish: status=%s message=%s", final.Status, final.Message)
	}

	// The actual vulnerability: the caller's directory must survive
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("the caller-supplied directory was wiped: %v", err)
	}

	raw, _ := json.Marshal(final)
	if strings.Contains(string(raw), "package target has no extraction directory set") {
		t.Fatalf("package scanning through the API still cannot run at all: %s", raw)
	}
	if !strings.Contains(string(raw), "not-a-real-ecosystem") {
		t.Fatalf("expected the real download attempt to fail on the bogus ecosystem, got: %s", raw)
	}

	if final.Result == nil {
		t.Fatal("expected a result")
	}
	if final.Result.Target.Path == victim {
		t.Fatalf("Target.Path in the result is still the caller's directory: %q", final.Result.Target.Path)
	}

	if final.Result.Target.Path != "" {
		t.Fatalf("Target.Path in the result leaked the server's extraction directory: %q", final.Result.Target.Path)
	}
}

func TestRejectedPackageSubmissionRemovesItsExtractionDirectory(t *testing.T) {
	// Isolate the temp directory from concurrent CLI package tests that use the same prefix
	t.Setenv("TMPDIR", t.TempDir())

	t.Setenv("MCP_SCANNER_API_TEST_TOKEN_LOW1", "sekret")
	sc := scanner.New(analyzer.Default, app.NewPreparer(config.Config{}), nil)
	ts := newTestServer(t, sc, Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetPackage},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN_LOW1",
		ScanTimeout:        30 * time.Second,
	})

	body := `{"target": {"kind": "package", "ecosystem": "npm", "package": "whatever"}, "analyzers": ["nosuchanalyzer"]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/scans", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sekret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status = %d, want 202", resp.StatusCode)
	}
	var sub submitResponse
	json.NewDecoder(resp.Body).Decode(&sub)
	resp.Body.Close()

	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/scans/"+sub.ID, nil)
	getReq.Header.Set("Authorization", "Bearer sekret")
	var final getResponse
	for range 200 {
		gr, err := http.DefaultClient.Do(getReq)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(gr.Body).Decode(&final)
		gr.Body.Close()
		if final.Status == string(statusDone) || final.Status == string(statusError) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if final.Status != string(statusError) {
		t.Fatalf("scan did not fail as expected: status=%s message=%s", final.Status, final.Message)
	}
	if !strings.Contains(final.Message, "unknown analyzer") {
		t.Fatalf("expected the resolve failure to be the one under test, got: %s", final.Message)
	}

	// The error record may become visible just before deferred cleanup finishes
	deadline := time.Now().Add(5 * time.Second)
	for n := testutil.CountPackageExtractionDirs(t); n != 0; n = testutil.CountPackageExtractionDirs(t) {
		if time.Now().After(deadline) {
			t.Fatalf("extraction directory leaked: %d left", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
