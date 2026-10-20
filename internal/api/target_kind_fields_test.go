package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/app"
	"github.com/devlab-group/mcp-scanner/internal/config"
	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/pkg/scanner"
)

func TestCommandIsOnlyCarriedByAStdioTarget(t *testing.T) {
	for _, kind := range []string{"source", "static", "package", "remote"} {
		t.Run(kind, func(t *testing.T) {
			var req submitRequest
			req.Target.Kind = kind
			req.Target.Command = "/usr/bin/id"
			req.Target.Args = []string{"-u"}
			req.Target.Path = "/tmp"
			req.Target.URL = "https://mcp.example.com/mcp"
			req.Target.Ecosystem, req.Target.Package = "npm", "left-pad"

			target, err := req.toTarget()
			if err != nil {
				t.Fatalf("toTarget: %v", err)
			}
			if target.Command != "" || len(target.Args) != 0 {
				t.Fatalf("a %s target carries command %q args %v; it must carry neither",
					kind, target.Command, target.Args)
			}
		})
	}

	var stdio submitRequest
	stdio.Target.Kind = "stdio"
	stdio.Target.Command = "/usr/bin/id"
	stdio.Target.Args = []string{"-u"}
	target, err := stdio.toTarget()
	if err != nil {
		t.Fatalf("toTarget(stdio): %v", err)
	}
	if target.Command != "/usr/bin/id" || len(target.Args) != 1 {
		t.Fatalf("stdio target lost its command: %+v", target)
	}
}

func TestSubmittedCommandNeverReachesTheStoredTarget(t *testing.T) {
	base := t.TempDir()
	t.Setenv("MCP_SCANNER_API_TEST_TOKEN_CMD", "sekret")
	sc := scanner.New(analyzer.Default, app.NewPreparer(config.Config{}), nil)
	ts := newTestServer(t, sc, Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetSource},
		TokenEnv:           "MCP_SCANNER_API_TEST_TOKEN_CMD",
		BaseDir:            base,
		ScanTimeout:        60 * time.Second,
	})

	body := `{"target": {"kind": "source", "path": ".", "command": "/usr/bin/id", "args": ["-u"]}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/scans", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sekret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		resp.Body.Close()
		t.Fatalf("submit status = %d, want 202", resp.StatusCode)
	}
	var sub submitResponse
	json.NewDecoder(resp.Body).Decode(&sub)
	resp.Body.Close()

	final := pollWithToken(t, ts, sub, "sekret")
	if final.Result == nil {
		t.Fatalf("no result stored: %+v", final)
	}
	if final.Result.Target.Command != "" || len(final.Result.Target.Args) != 0 {
		t.Fatalf("the scanned target carried command %q args %v",
			final.Result.Target.Command, final.Result.Target.Args)
	}
}

func TestPackageDiscoveryErrorsAreRedacted(t *testing.T) {
	if !redactedPathTargetKinds[model.TargetPackage] {
		t.Fatal("a package scan's discovery errors are not redacted")
	}
	res := &model.ScanResult{
		Analyzers: []model.AnalyzerResult{{
			Analyzer: "supplychain",
			Errors: []model.AnalyzerError{
				{Kind: "io", Message: "target discovery failed: open package extraction directory /tmp/mcp-scanner-package-123: permission denied"},
			},
		}},
	}
	redactLocalPathErrors(res, slog.New(slog.NewTextHandler(io.Discard, nil)), "scan_test", "")
	if got := res.Analyzers[0].Errors[0].Message; got != "target could not be read" {
		t.Fatalf("message = %q, want the redacted one", got)
	}
}

// pollWithToken polls GET /v1/scans/{id} on a server that requires a bearer
// token until the scan finishes
func pollWithToken(t *testing.T, ts *httptest.Server, sub submitResponse, token string) getResponse {
	t.Helper()
	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/scans/"+sub.ID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	var final getResponse
	for range 300 {
		gr, err := http.DefaultClient.Do(getReq)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(gr.Body).Decode(&final)
		gr.Body.Close()
		if final.Status == string(statusDone) || final.Status == string(statusError) {
			return final
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scan never finished: status=%s message=%s", final.Status, final.Message)
	return final
}
