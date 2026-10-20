package main

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/policy"
)

// The runtime subcommand always requires the runtime analyzer
func TestRuntimeSubcommandRequiresTheRuntimeAnalyzer(t *testing.T) {
	cfgWithAnalyzers := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgWithAnalyzers, []byte("analyzers: [protocol]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		flags         commonFlags
		wantSelection []string // nil means "the default selection, left empty"
	}{
		{"no selection at all", commonFlags{}, nil},
		{"--analyzers narrowed it", commonFlags{analyzers: []string{"protocol"}}, []string{"protocol", "runtime"}},
		{"the config file narrowed it", commonFlags{configPath: cfgWithAnalyzers}, []string{"protocol", "runtime"}},
		{"runtime already named", commonFlags{analyzers: []string{"runtime"}}, []string{"runtime"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := resolveWithRuntime(&tc.flags)
			if err != nil {
				t.Fatalf("resolveWithRuntime: %v", err)
			}
			if !slices.Contains(r.sopts.Required, runtimeAnalyzer) {
				t.Fatalf("Required = %v, want it to name %q", r.sopts.Required, runtimeAnalyzer)
			}
			if !slices.Equal(r.sopts.Analyzers, tc.wantSelection) {
				t.Fatalf("Analyzers = %v, want %v", r.sopts.Analyzers, tc.wantSelection)
			}
		})
	}
}

// Runtime cannot be best-effort when the subcommand promises a sandbox pass
func TestRuntimeBestEffortRuntimeIsAUsageError(t *testing.T) {
	_, err := resolveWithRuntime(&commonFlags{bestEffort: []string{"runtime"}})
	if err == nil {
		t.Fatal("expected an error for --best-effort runtime on the runtime subcommand")
	}
}

// The runtime subcommand rejects unsupported remote targets
func TestRuntimeRemoteIsAUsageError(t *testing.T) {
	exitCode = policy.ExitOK
	root := newRootCmd()
	root.SetArgs([]string{"runtime", "remote", "https://mcp.example.com/mcp"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err == nil {
		t.Fatal("expected a usage error, got none")
	}
	if exitCode != policy.ExitUsage {
		t.Errorf("exitCode = %d, want ExitUsage", exitCode)
	}
}

// runtime stdio must not start an untrusted command on the host. Without a configured sandbox,
// this command must not run at all.
func TestRuntimeStdioNeverRunsTheTargetOnTheHost(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran-on-host")
	exitCode = policy.ExitOK
	t.Cleanup(func() { exitCode = policy.ExitOK })
	code := run(func() error {
		root := newRootCmd()
		root.SetArgs([]string{"runtime", "stdio", "--output", filepath.Join(t.TempDir(), "report.txt"),
			"--", "/bin/sh", "-c", "touch " + marker})
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		return root.Execute()
	})
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("runtime stdio started the target on the host")
	}
	if code == policy.ExitOK {
		t.Fatal("a runtime scan whose sandbox never ran exited 0")
	}
}
