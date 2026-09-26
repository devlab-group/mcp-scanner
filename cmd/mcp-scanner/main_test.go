package main

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/revinand/mcp-scanner/internal/policy"
)

func TestRun_PanicExitsInternal(t *testing.T) {
	t.Cleanup(func() { exitCode = policy.ExitOK })
	if got := run(func() error { panic("parser blew up") }); got != policy.ExitInternal {
		t.Fatalf("exit code after a panic = %d, want %d", got, policy.ExitInternal)
	}
}

func TestRun_ErrorWithoutExitCodeIsUsage(t *testing.T) {
	t.Cleanup(func() { exitCode = policy.ExitOK })
	exitCode = policy.ExitOK
	if got := run(func() error { return errBadFlag }); got != policy.ExitUsage {
		t.Fatalf("exit code after a plain error = %d, want %d", got, policy.ExitUsage)
	}
}

var errBadFlag = errTest("unknown flag")

type errTest string

func (e errTest) Error() string { return string(e) }

// Drive the root command to verify the exit code returned to the caller, not only the value
// computed inside runScanAndReport
func TestRunReturnsTheScanOutcomeAsTheExitCode(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"clean snapshot", []string{"static", "../../evals/benign/plain-reader-001/server.json"}, policy.ExitOK},
		{"blocking finding", []string{"static", "../../evals/vulnerable/hidden-instructions-001/server.json"}, policy.ExitPolicyFail},
		{"named analyzer that cannot run here", []string{"static", "../../evals/benign/plain-reader-001/server.json", "--analyzers", "auth"}, policy.ExitIncomplete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exitCode = policy.ExitOK
			t.Cleanup(func() { exitCode = policy.ExitOK })
			got := run(func() error {
				root := newRootCmd()
				root.SetArgs(append(tc.args, "--output", filepath.Join(t.TempDir(), "report.txt")))
				root.SetOut(io.Discard)
				root.SetErr(io.Discard)
				return root.Execute()
			})
			if got != tc.want {
				t.Fatalf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}
