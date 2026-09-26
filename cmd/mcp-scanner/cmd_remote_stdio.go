package main

import (
	"github.com/revinand/mcp-scanner/internal/app"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/revinand/mcp-scanner/internal/mcp/client"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/pkg/scanner"
)

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

func newScannerFor(r resolved) *scanner.Scanner {
	return scanner.New(analyzer.Default, app.NewPreparer(r.cfg), newLogger())
}

func newRemoteCmd(flags *commonFlags) *cobra.Command {
	var transport string
	cmd := &cobra.Command{
		Use:   "remote <url>",
		Short: "Scan an MCP server over HTTP",
		Long: "Scan an MCP server over Streamable HTTP or SSE.\n\n" +
			"Connections are direct and ignore HTTP_PROXY, HTTPS_PROXY, and NO_PROXY. " +
			"See docs/threat-model.md.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := resolve(flags)
			if err != nil {
				return failUsage(err)
			}
			// Validate before a bad transport becomes a connection failure
			if err := client.ValidateTransport(transport); err != nil {
				return failUsage(err)
			}
			target := model.Target{Kind: model.TargetRemote, URL: args[0], Transport: transport}
			return runAndSetExit(cmd.Context(), newScannerFor(r), target, r)
		},
	}
	cmd.Flags().StringVar(&transport, "transport", "auto", "auto|streamable|sse")
	return cmd
}

func newStdioCmd(flags *commonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stdio -- <command> [args...]",
		Short: "Scan an MCP server launched as a child process",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := resolve(flags)
			if err != nil {
				return failUsage(err)
			}
			target := model.Target{Kind: model.TargetStdio, Command: args[0], Args: args[1:]}
			return runAndSetExit(cmd.Context(), newScannerFor(r), target, r)
		},
	}
	return cmd
}
