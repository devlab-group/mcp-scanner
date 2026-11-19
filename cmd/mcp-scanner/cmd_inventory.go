package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/devlab-group/mcp-scanner/internal/dossier"
)

// newInventoryCmd prints what the static pipeline knows about a source tree - languages,
// manifests and the MCP SDK version, declared server identity, and each capability with its
// handler code and reachable behavior - as JSON, for review beyond the scan itself. It runs no
// analyzer and reports no findings.
func newInventoryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inventory <path>",
		Short: "Print a JSON inventory of an MCP server's source tree, without scanning it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := dossier.Build(cmd.Context(), args[0], scanVersion)
			if err != nil {
				return fmt.Errorf("inventory: %w", err)
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(d)
		},
	}
}
