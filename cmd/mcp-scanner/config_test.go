package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/revinand/mcp-scanner/internal/policy"
)

// Reject empty baseline reasons while loading the operator's file
func TestLoadBaselineRejectsAnEmptyReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := os.WriteFile(path, []byte("f_1092aa61343536d5: \"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadBaseline(path)
	if err == nil {
		t.Fatal("expected an error for an entry with an empty reason, got nil")
	}
	if !strings.Contains(err.Error(), "f_1092aa61343536d5") {
		t.Fatalf("error = %q, want it to name the offending entry", err)
	}
}

func TestLoadBaselineAcceptsAReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := os.WriteFile(path, []byte("f_1092aa61343536d5: accepted 2026-01-01, tracked in JIRA-123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadBaseline(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["f_1092aa61343536d5"] == "" {
		t.Fatal("expected the reason to be preserved")
	}
}

// Reject unknown best-effort analyzers instead of silently keeping them required
func TestResolveRejectsUnknownBestEffortAnalyzer(t *testing.T) {
	_, err := resolve(&commonFlags{bestEffort: []string{"does-not-exist"}})
	if err == nil {
		t.Fatal("expected an error for an unknown --best-effort analyzer")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Fatalf("error = %q, want it to name the offending analyzer", err)
	}
}

// Configured best-effort analyzers use the same validation as the flag
func TestResolveRejectsUnknownBestEffortFromConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("best_effort: [does-not-exist]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := resolve(&commonFlags{configPath: path})
	if err == nil {
		t.Fatal("expected an error for an unknown best_effort analyzer named in the config file")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Fatalf("error = %q, want it to name the offending analyzer", err)
	}
}

// Accept a registered best-effort analyzer
func TestResolveAcceptsKnownBestEffortAnalyzer(t *testing.T) {
	r, err := resolve(&commonFlags{bestEffort: []string{"protocol"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.cfg.BestEffort) != 1 || r.cfg.BestEffort[0] != "protocol" {
		t.Fatalf("cfg.BestEffort = %v, want [protocol]", r.cfg.BestEffort)
	}
}

// Fetch flags must be merged before shared probe-level validation
func TestResolveRejectsReadResourcesBelowActiveProbesSafe(t *testing.T) {
	_, err := resolve(&commonFlags{readResources: true, activeProbes: "none"})
	if err == nil {
		t.Fatal("expected an error for --read-resources with --active-probes none")
	}
	if !strings.Contains(err.Error(), "read_resources") {
		t.Fatalf("error = %q, want it to name read_resources", err)
	}

	_, err = resolve(&commonFlags{getPrompts: true, activeProbes: "none"})
	if err == nil {
		t.Fatal("expected an error for --get-prompts with --active-probes none")
	}

	if _, err := resolve(&commonFlags{readResources: true, activeProbes: "safe"}); err != nil {
		t.Fatalf("--read-resources with --active-probes safe should be accepted: %v", err)
	}
}

// With no config or flags, incomplete scans fail and private destinations are refused.
// tolerate_unknown disables only the incomplete-scan failure.
func TestResolveDefaultsFailClosed(t *testing.T) {
	r, err := resolve(&commonFlags{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.pol.FailOnUnknown {
		t.Error("an incomplete scan passes the policy by default")
	}
	if r.cfg.AllowPrivateNetworks {
		t.Error("private destinations are allowed by default")
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("tolerate_unknown: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err = resolve(&commonFlags{configPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if r.pol.FailOnUnknown {
		t.Error("tolerate_unknown: true did not reach the policy")
	}
}

// Default remote scans must reject a loopback target before sending a request
func TestRemoteScanRefusesALoopbackTargetByDefault(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "unexpected", http.StatusTeapot)
	}))
	defer srv.Close()

	exitCode = policy.ExitOK
	t.Cleanup(func() { exitCode = policy.ExitOK })
	got := run(func() error {
		root := newRootCmd()
		root.SetArgs([]string{"remote", srv.URL + "/mcp", "--output", filepath.Join(t.TempDir(), "report.txt")})
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		return root.Execute()
	})
	if n := hits.Load(); n != 0 {
		t.Fatalf("the scanner sent %d request(s) to a loopback target with default settings", n)
	}
	if got == policy.ExitOK {
		t.Fatal("a scan that could not reach its target exited 0")
	}
}
