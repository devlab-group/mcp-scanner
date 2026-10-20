package main

import (
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/devlab-group/mcp-scanner/internal/app"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/pkg/scanner"
)

// runtimeAnalyzer is required by the runtime subcommand
const runtimeAnalyzer = "runtime"

// newRuntimeCmd requires sandboxed runtime confirmation
func newRuntimeCmd(flags *commonFlags) *cobra.Command {
	root := &cobra.Command{
		Use:   "runtime",
		Short: "Scan with required sandboxed runtime confirmation",
	}
	root.AddCommand(newRuntimeRemoteCmd(), newRuntimeStdioCmd(flags))
	return root
}

// resolveWithRuntime adds runtime to both analyzer selection and requirements. Requiring it
// prevents an unavailable sandbox from becoming a clean-looking SKIPPED result.
func resolveWithRuntime(flags *commonFlags) (resolved, error) {
	r, err := resolve(flags)
	if err != nil {
		return r, err
	}
	// Best-effort runtime would defeat this subcommand's contract
	if slices.Contains(r.sopts.BestEffort, runtimeAnalyzer) {
		return resolved{}, fmt.Errorf("runtime cannot be best-effort here; remove it from --best-effort or config best_effort, or use mcp-scanner stdio only if the target is trusted to run on the host")
	}
	if len(r.sopts.Analyzers) > 0 && !slices.Contains(r.sopts.Analyzers, runtimeAnalyzer) {
		r.sopts.Analyzers = append(slices.Clone(r.sopts.Analyzers), runtimeAnalyzer)
	}
	r.sopts.Required = append(r.sopts.Required, runtimeAnalyzer)
	return r, nil
}

// newRuntimeRemoteCmd explains why remote targets cannot be sandboxed. A tool call against a
// remote target reaches the live server, not the local sandbox promised by this command.
func newRuntimeRemoteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote <url>",
		Short: "Unavailable for remote servers",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return failUsage(fmt.Errorf("remote tool calls cannot be sandboxed; use mcp-scanner remote to scan the live server, or mcp-scanner runtime stdio for an absolute statically linked ELF executable"))
		},
	}
	cmd.Flags().String("transport", "auto", "auto|streamable|sse")
	return cmd
}

// newRuntimeStdioCmd skips host discovery and runs only in the sandbox.
// A snapshot supplies the tool surface that live discovery would provide.
func newRuntimeStdioCmd(flags *commonFlags) *cobra.Command {
	var snapshotPath string
	cmd := &cobra.Command{
		Use:   "stdio -- <command> [args...]",
		Short: "Scan a stdio server only inside the sandbox",
		Long: "Run a stdio server only inside the sandbox. Set runtime.enabled: true in the config.\n\n" +
			"The command must be an absolute path to a statically linked ELF executable. " +
			"Pass --snapshot with a trusted or recorded capability capture. It supplies the surface to every selected analyzer; without it runtime has no tools to fuzz and the scan cannot be SAFE.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := resolveWithRuntime(flags)
			if err != nil {
				return failUsage(err)
			}
			target := model.Target{Kind: model.TargetStdio, Command: args[0], Args: args[1:]}
			s := scanner.New(analyzer.Default, app.NewSandboxOnlyPreparer(r.cfg, snapshotPath), newLogger())
			return runAndSetExit(cmd.Context(), s, target, r)
		},
	}
	cmd.Flags().StringVar(&snapshotPath, "snapshot", "",
		"trusted capability snapshot supplied to analyzers and used to choose tools")
	return cmd
}
