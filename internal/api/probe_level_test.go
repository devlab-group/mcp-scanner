package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/internal/app"
	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/policy"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/pkg/scanner"
	"github.com/revinand/mcp-scanner/testdata/protocol/fixtures"
)

type probeWitness struct{}

func (probeWitness) Name() string { return "probewitness" }

func (probeWitness) Analyze(ctx context.Context, _ model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	acAllowed := ac.ToolCallAllowed("search")
	sessionAllowed := false
	if ac.Session != nil {
		if _, err := ac.Session.CallTool(ctx, "search", map[string]any{"query": "x"}); err == nil {
			sessionAllowed = true
		}
	}
	msg := fmt.Sprintf("ac_allowed=%v session_allowed=%v", acAllowed, sessionAllowed)
	if acAllowed != sessionAllowed {
		msg += " DISAGREE"
	}
	return model.AnalyzerResult{
		Analyzer: "probewitness", Status: model.AnalyzerCompleted, Required: true,
		Warnings: []string{msg},
		Coverage: model.Coverage{CapabilitiesDiscovered: 1, CapabilitiesAnalyzed: 1},
	}
}

// probeWitnessResult drives one submission through the real Handler and
// returns the probewitness analyzer's warning, i.e. what the live session
// actually did
func probeWitnessResult(t *testing.T, cfg config.Config, body string) string {
	t.Helper()

	sopts, err := app.ScanOptions(cfg)
	if err != nil {
		t.Fatalf("app.ScanOptions: %v", err)
	}
	reg := analyzer.NewRegistry()
	reg.Register(probeWitness{})
	sc := scanner.New(reg, app.NewPreparer(cfg), nil)

	ts := newTestServer(t, sc, Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetRemote},
		ScanOptions:        sopts,
		ScanTimeout:        30 * time.Second,
	})

	resp, err := http.Post(ts.URL+"/v1/scans", "application/json", strings.NewReader(body))
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
	if final.Result == nil {
		t.Fatal("expected a result")
	}
	for _, a := range final.Result.Analyzers {
		if a.Analyzer == "probewitness" {
			if len(a.Warnings) != 1 {
				t.Fatalf("probewitness: unexpected warnings %v", a.Warnings)
			}
			return a.Warnings[0]
		}
	}
	t.Fatalf("probewitness analyzer did not run: %+v", final.Result.Analyzers)
	return ""
}

// The configured probe level must reach both the live session and analysis context
func TestConfigProbeLevelSafeReachesTheLiveSession(t *testing.T) {
	srv := fixtures.StreamableHTTPServer(fixtures.WellBehaved())
	defer srv.Close()

	cfg := config.Defaults()
	cfg.ActiveProbes = string(analyzer.ProbeSafe) // deployment: no tool calls
	cfg.AllowToolCalls = []string{"search"}       // even though this name would be fine
	cfg.AllowPrivateNetworks = true               // the fixture server is loopback

	body := `{"target": {"kind": "remote", "url": "` + srv.URL + `", "transport": "streamable"},
	          "analyzers": ["probewitness"]}`

	got := probeWitnessResult(t, cfg, body)
	if strings.Contains(got, "DISAGREE") {
		t.Fatalf("AnalysisContext and the live session disagreed: %s", got)
	}
	if got != "ac_allowed=false session_allowed=false" {
		t.Fatalf("probe level safe did not reach both the session and the analysis context: %s", got)
	}
}

func TestConfigProbeLevelToolCallsReachesTheLiveSession(t *testing.T) {
	srv := fixtures.StreamableHTTPServer(fixtures.WellBehaved())
	defer srv.Close()

	cfg := config.Defaults()
	cfg.ActiveProbes = string(analyzer.ProbeToolCalls)
	cfg.AllowToolCalls = []string{"search"}
	cfg.AllowPrivateNetworks = true

	body := `{"target": {"kind": "remote", "url": "` + srv.URL + `", "transport": "streamable"},
	          "analyzers": ["probewitness"]}`

	got := probeWitnessResult(t, cfg, body)
	if strings.Contains(got, "DISAGREE") {
		t.Fatalf("AnalysisContext and the live session disagreed: %s", got)
	}
	if got != "ac_allowed=true session_allowed=true" {
		t.Fatalf("probe level tool-calls did not reach both the session and the analysis context: %s", got)
	}
}

func TestRequestCarryingActiveProbesIsRefused(t *testing.T) {
	cfg := config.Defaults()
	sopts, err := app.ScanOptions(cfg)
	if err != nil {
		t.Fatalf("app.ScanOptions: %v", err)
	}
	sc := scanner.New(analyzer.NewRegistry(), app.NewPreparer(cfg), nil)
	ts := newTestServer(t, sc, Options{
		Policy:             policy.Default(),
		AllowedTargetKinds: []model.TargetKind{model.TargetRemote},
		ScanOptions:        sopts,
		ScanTimeout:        30 * time.Second,
	})

	body := `{"target": {"kind": "remote", "url": "https://example.test/mcp"}, "active_probes": "tool-calls"}`
	resp, err := http.Post(ts.URL+"/v1/scans", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: a request that sets active_probes must be told it cannot", resp.StatusCode)
	}
	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload["error"], "deployment configuration") {
		t.Errorf("the refusal does not say why: %q", payload["error"])
	}
}
