package main

import (
	"github.com/spf13/cobra"

	"github.com/revinand/mcp-scanner/pkg/model"
)

func newStaticCmd(flags *commonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "static <snapshot.json>",
		Short: "Scan an MCP snapshot without connecting to a server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := resolve(flags)
			if err != nil {
				return failUsage(err)
			}
			target := model.Target{Kind: model.TargetStatic, Path: args[0]}
			return runAndSetExit(cmd.Context(), newScannerFor(r), target, r)
		},
	}
}

func newSourceCmd(flags *commonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "source <path>",
		Short: "Scan a directory of source code",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := resolve(flags)
			if err != nil {
				return failUsage(err)
			}
			r.sopts.Root = args[0]
			target := model.Target{Kind: model.TargetSource, Path: args[0]}
			return runAndSetExit(cmd.Context(), newScannerFor(r), target, r)
		},
	}
}
