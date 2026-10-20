// Command mcp-scanner is the MCP security scanner CLI
package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/devlab-group/mcp-scanner/internal/policy"
)

func main() {
	os.Exit(run(func() error { return newRootCmd().Execute() }))
}

// run maps panics outside analyzers to ExitInternal instead of the policy-failure code. Without
// this recovery, Go exits with status 2, which the CLI documents as a normal policy failure.
func run(execute func() error) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "internal error: %v\n\n%s", r, debug.Stack())
			code = policy.ExitInternal
		}
	}()
	if err := execute(); err != nil {
		if exitCode == policy.ExitOK {
			exitCode = policy.ExitUsage
		}
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	return exitCode
}
