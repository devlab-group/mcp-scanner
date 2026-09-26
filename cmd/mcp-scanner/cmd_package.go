package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/revinand/mcp-scanner/internal/policy"
	"github.com/revinand/mcp-scanner/internal/supplychain"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// parsePackageArg accepts positional and ecosystem:name@version forms.
// The last "@" separates versions from scoped npm package names.
func parsePackageArg(args []string) (ecosystem, name, version string, err error) {
	if len(args) >= 2 {
		ecosystem, name = args[0], args[1]
		if len(args) == 3 {
			version = args[2]
		}
		return ecosystem, name, version, nil
	}

	spec := args[0]
	colon := strings.Index(spec, ":")
	if colon <= 0 {
		return "", "", "", fmt.Errorf("package spec %q must be ecosystem:name or ecosystem:name@version", spec)
	}
	ecosystem, rest := spec[:colon], spec[colon+1:]
	if at := strings.LastIndex(rest, "@"); at > 0 {
		name, version = rest[:at], rest[at+1:]
	} else {
		name = rest
	}
	if name == "" {
		return "", "", "", fmt.Errorf("package spec %q must be ecosystem:name or ecosystem:name@version", spec)
	}
	return ecosystem, name, version, nil
}

// newPackageCmd owns the extraction directory, including early failures. Its deferred cleanup
// is the backstop for errors that occur before the preparer takes responsibility for the tree.
func newPackageCmd(flags *commonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "package (<npm|pypi> <name> [version] | <npm|pypi>:<name>[@version])",
		Short: "Download a published package and scan it",
		Args:  cobra.RangeArgs(1, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := resolve(flags)
			if err != nil {
				return failUsage(err)
			}
			ecosystem, pkgName, version, err := parsePackageArg(args)
			if err != nil {
				return failUsage(err)
			}

			dest, err := os.MkdirTemp("", supplychain.ExtractionDirPrefix)
			if err != nil {
				exitCode = policy.ExitInternal
				return fmt.Errorf("create extraction directory: %w", err)
			}
			// Prepare may also remove dest; RemoveAll is safe after that
			defer os.RemoveAll(dest)

			r.sopts.Root = dest
			target := model.Target{Kind: model.TargetPackage, Ecosystem: ecosystem, Package: pkgName, Version: version, Path: dest}
			return runAndSetExit(cmd.Context(), newScannerFor(r), target, r)
		},
	}
}
