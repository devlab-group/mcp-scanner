package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/api"
	"github.com/devlab-group/mcp-scanner/internal/app"
	"github.com/devlab-group/mcp-scanner/internal/config"
	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/pkg/scanner"
)

// findingRuleIDs returns one analyzer's reported rule IDs
func findingRuleIDs(res *model.ScanResult, analyzerName string) []string {
	var out []string
	for _, a := range res.Analyzers {
		if a.Analyzer != analyzerName {
			continue
		}
		for _, f := range a.Findings {
			out = append(out, f.RuleID)
		}
	}
	return out
}

// Configured rule directories must produce the same findings through CLI and API
func TestConfiguredRulesDirProducesSameFindingsCLIAndAPI(t *testing.T) {
	base := t.TempDir()

	rulesDir := filepath.Join(base, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const ruleID = "custom.marker-test"
	const marker = "zzz-mcp-scanner-parity-marker-9f3c"
	rule := "rules:\n" +
		"  - id: " + ruleID + "\n" +
		"    title: Test marker rule\n" +
		"    category: instruction_override\n" +
		"    severity: LOW\n" +
		"    evidence_level: HEURISTIC\n" +
		"    description: Fires only on the parity test's marker string.\n" +
		"    remediation: none, this is a test fixture\n" +
		"    fields: [\"description\"]\n" +
		"    patterns:\n" +
		"      - \"" + marker + "\"\n"
	if err := os.WriteFile(filepath.Join(rulesDir, "custom.yaml"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}

	snapshot := `{"schema_version":"1.0.0","tools":[{"name":"t","description":"` + marker + `"}]}`
	if err := os.WriteFile(filepath.Join(base, "snap.json"), []byte(snapshot), 0o644); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(base, "config.yaml")
	configYAML := "analyzers: [\"promptdefense\"]\n" +
		"rules:\n" +
		"  prompt_defense_dir: " + rulesDir + "\n"
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Follow the static command's scan path
	r, err := resolve(&commonFlags{configPath: configPath})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	cliTarget := model.Target{Kind: model.TargetStatic, Path: filepath.Join(base, "snap.json")}
	cliScanner := scanner.New(analyzer.Default, app.NewPreparer(r.cfg), logger)
	cliResult, err := cliScanner.Scan(ctx, cliTarget, r.sopts)
	if err != nil {
		t.Fatalf("cli scan: %v", err)
	}

	// API path: what cmd/mcp-scanner-api's main and handleSubmit do
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	sopts, err := app.ScanOptions(cfg)
	if err != nil {
		t.Fatalf("app.ScanOptions: %v", err)
	}
	t.Setenv("MCP_SCANNER_TEST_PARITY_TOKEN", "sekret")
	apiScanner := scanner.New(analyzer.Default, app.NewPreparer(cfg), logger)
	srv, err := api.NewServer(apiScanner, api.Options{
		Policy:             policy.Default(),
		ScanOptions:        sopts,
		AllowedTargetKinds: []model.TargetKind{model.TargetStatic},
		TokenEnv:           "MCP_SCANNER_TEST_PARITY_TOKEN",
		BaseDir:            base,
		Logger:             logger,
	})
	if err != nil {
		t.Fatalf("api.NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/scans", strings.NewReader(`{"target": {"kind": "static", "path": "snap.json"}}`))
	req.Header.Set("Authorization", "Bearer sekret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var sub struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&sub)
	resp.Body.Close()

	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/scans/"+sub.ID, nil)
	getReq.Header.Set("Authorization", "Bearer sekret")
	var final struct {
		Status string            `json:"status"`
		Result *model.ScanResult `json:"result"`
	}
	for range 200 {
		gr, err := http.DefaultClient.Do(getReq)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(gr.Body).Decode(&final)
		gr.Body.Close()
		if final.Status == "DONE" || final.Status == "ERROR" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if final.Status != "DONE" || final.Result == nil {
		t.Fatalf("api scan did not finish cleanly: %+v", final)
	}

	cliRuleIDs := findingRuleIDs(cliResult, "promptdefense")
	apiRuleIDs := findingRuleIDs(final.Result, "promptdefense")

	if !slices.Contains(cliRuleIDs, ruleID) {
		t.Fatalf("CLI scan did not fire the configured rule %s, got %v (the config's rules_dir did not reach the CLI scan)", ruleID, cliRuleIDs)
	}
	if !slices.Contains(apiRuleIDs, ruleID) {
		t.Fatalf("API scan did not fire the configured rule %s, got %v (the config's rules_dir did not reach the API scan)", ruleID, apiRuleIDs)
	}
}
