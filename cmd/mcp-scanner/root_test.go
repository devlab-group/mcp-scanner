package main

import (
	"io"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/policy"
)

// Static and source targets reject fetch flags that cannot do anything
func TestRejectFetchFlagsOnStaticAndSourceTargets(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"static with --read-resources", []string{"static", "snap.json", "--read-resources"}},
		{"static with --get-prompts", []string{"static", "snap.json", "--get-prompts"}},
		{"source with --read-resources", []string{"source", ".", "--read-resources"}},
		{"source with --get-prompts", []string{"source", ".", "--get-prompts"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exitCode = policy.ExitOK
			root := newRootCmd()
			root.SetArgs(tc.args)
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			if err := root.Execute(); err == nil {
				t.Fatal("expected a usage error, got none")
			}
			if exitCode != policy.ExitUsage {
				t.Errorf("exitCode = %d, want ExitUsage", exitCode)
			}
		})
	}
}

// Commands remain valid when neither fetch flag is set
func TestRejectFetchFlagsAllowsRequestWithNeitherFlagSet(t *testing.T) {
	f := &commonFlags{}
	if err := rejectFetchFlags("static", f)(nil, nil); err != nil {
		t.Fatalf("unexpected error with neither fetch flag set: %v", err)
	}
}
