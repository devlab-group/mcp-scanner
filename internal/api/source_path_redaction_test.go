package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/pkg/scanner"
)

func TestSourceScanNeverReturnsTheBaseDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits do not work the same way on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the directory would still be readable")
	}

	base := t.TempDir()
	project := filepath.Join(base, "project")
	locked := filepath.Join(project, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "handler.py"), []byte("def handler():\n    pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "clean.py"), []byte("def other():\n    pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) }) // let TempDir's own cleanup remove it

	t.Setenv("MCP_SCANNER_API_TEST_TOKEN_SRC_REDACT", "sekret")

	reg := analyzer.NewRegistry()
	reg.Register(&source.Analyzer{})
	sc := scanner.New(reg, nil, nil)

	srv, err := NewServer(sc, Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetSource},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN_SRC_REDACT",
		BaseDir:            base,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/scans", strings.NewReader(`{"target": {"kind": "source", "path": "project"}}`))
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

	if final.Status != string(statusDone) {
		t.Fatalf("scan did not finish: %+v", final)
	}
	if strings.Contains(string(raw), base) {
		t.Fatalf("the resolved base directory leaked into the API response: %s", raw)
	}
	if final.Result == nil {
		t.Fatalf("expected a result, got %+v", final)
	}
	if final.Result.Target.Path != "project" {
		t.Fatalf("target.path = %q, want the caller's own submitted path, not a resolved host one", final.Result.Target.Path)
	}
}

// Replace the base directory in every analyzer-controlled text field, including unknown messages
func TestRedactBaseDirReachesEveryFreeTextField(t *testing.T) {
	base := t.TempDir()
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	leak := resolved + "/private/notes.py"
	res := &model.ScanResult{
		Warnings: []string{"could not read " + leak},
		Coverage: model.Coverage{SkipReasons: []string{"skipped " + leak}, LimitsHit: []string{"cut " + leak}},
		Analyzers: []model.AnalyzerResult{{
			Analyzer: "source",
			Errors:   []model.AnalyzerError{{Kind: "io", Message: "open " + leak + ": permission denied"}},
			Coverage: model.Coverage{SkipReasons: []string{"skipped " + leak}, LimitsHit: []string{"cut " + leak}},
		}},
	}
	redactBaseDir(res, slog.New(slog.NewTextHandler(io.Discard, nil)), "scan_1", base)

	// Use formatted output because JSON escapes the placeholder's angle brackets
	raw := fmt.Sprintf("%+v", *res)
	if strings.Contains(raw, resolved) {
		t.Fatalf("the base directory survived redaction: %s", raw)
	}
	if strings.Count(raw, "<base>/private/notes.py") != 6 {
		t.Fatalf("want all six fields to keep the relative part a reader needs: %s", raw)
	}
}
