package main

import (
	"io"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/policy"
)

// Snapshot and compare must reject inherited flags they cannot honor
func TestSnapshotAndCompareRefuseFlagsTheyCannotActOn(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"snapshot with --format", []string{"snapshot", "remote", "https://x.example/mcp", "--format", "json"}, "--format"},
		{"snapshot with --analyzers", []string{"snapshot", "stdio", "--analyzers", "protocol", "--", "true"}, "--analyzers"},
		{"compare with --allow-private-networks", []string{"compare", "a.json", "b.json", "--allow-private-networks"}, "--allow-private-networks"},
		{"compare with --timeout", []string{"compare", "a.json", "b.json", "--timeout", "5s"}, "--timeout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exitCode = policy.ExitOK
			root := newRootCmd()
			root.SetArgs(tc.args)
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			err := root.Execute()
			if err == nil {
				t.Fatal("expected a usage error, got none")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %s", err, tc.want)
			}
			if exitCode != policy.ExitUsage {
				t.Errorf("exitCode = %d, want ExitUsage", exitCode)
			}
		})
	}
}

// Snapshot capture accepts the connection flags it honors
func TestSnapshotAcceptsTheConnectionFlags(t *testing.T) {
	values := map[string]string{
		"config": "scanner.yaml", "timeout": "5s", "allow-private-networks": "true",
		"active-probes": "safe", "allow-tool-call": "echo",
		"read-resources": "true", "get-prompts": "true",
	}
	for _, name := range snapshotGlobalFlags {
		value, ok := values[name]
		if !ok {
			t.Fatalf("no test value for honoured flag %s", name)
		}
		root := newRootCmd()
		if err := root.PersistentFlags().Set(name, value); err != nil {
			t.Fatalf("set --%s: %v", name, err)
		}
		cmd, _, err := root.Find([]string{"snapshot", "remote"})
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.PreRunE(cmd, nil); err != nil {
			t.Fatalf("--%s was refused: %v", name, err)
		}
	}
}
