package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/revinand/mcp-scanner/internal/policy"
)

// exitCode is set by RunE and read by main after Execute returns
var exitCode = policy.ExitOK

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "mcp-scanner",
		Short:         "Security scanner for Model Context Protocol servers",
		Version:       scanVersion,
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	flags := &commonFlags{}
	flags.register(root.PersistentFlags())

	// Static and source targets have no session from which to fetch bodies
	staticCmd := newStaticCmd(flags)
	sourceCmd := newSourceCmd(flags)
	staticCmd.PreRunE = rejectFetchFlags("static", flags)
	sourceCmd.PreRunE = rejectFetchFlags("source", flags)

	root.AddCommand(
		newRemoteCmd(flags),
		newStdioCmd(flags),
		staticCmd,
		sourceCmd,
		newPackageCmd(flags),
		newRuntimeCmd(flags),
		newKnownConfigsCmd(flags),
		newSnapshotCmd(flags),
		newCompareCmd(),
		newConfigCmd(),
		newAnalyzersCmd(),
	)
	return root
}

// rejectUnusedGlobalFlags rejects persistent flags a command cannot use. Cobra parses every root
// flag for every subcommand, so accepting and silently ignoring one would misstate the operation.
func rejectUnusedGlobalFlags(honoured ...string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		var ignored []string
		// Changed lives on each shared *pflag.Flag. VisitAll is required because Visit on the root
		// set sees no changed entries after Cobra parses the values through the child command.
		cmd.Root().PersistentFlags().VisitAll(func(fl *pflag.Flag) {
			if fl.Changed && !slices.Contains(honoured, fl.Name) {
				ignored = append(ignored, "--"+fl.Name)
			}
		})
		if len(ignored) == 0 {
			return nil
		}
		sort.Strings(ignored)
		return failUsage(fmt.Errorf("%s does not use %s", cmd.CommandPath(), strings.Join(ignored, ", ")))
	}
}

// rejectFetchFlags rejects fetch flags for targets without a live session
func rejectFetchFlags(targetKind string, f *commonFlags) func(*cobra.Command, []string) error {
	return func(*cobra.Command, []string) error {
		switch {
		case f.readResources:
			return failUsage(fmt.Errorf("--read-resources has nothing to fetch from on a %s target", targetKind))
		case f.getPrompts:
			return failUsage(fmt.Errorf("--get-prompts has nothing to fetch from on a %s target", targetKind))
		}
		return nil
	}
}
