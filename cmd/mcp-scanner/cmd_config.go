package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/policy"
)

// redactedTokenValue hides literal secrets while preserving case names
const redactedTokenValue = "<redacted>"

// newConfigCmd validates and prints resolved YAML. It redacts literal test
// tokens from a copy without changing the configuration used by scans.
func newConfigCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Load, validate and print the resolved scanner configuration",
		Long: "Load, validate, and print the resolved scanner configuration.\n\n" +
			"Literal analyzer test tokens are printed as " + redactedTokenValue + ". " +
			"Prefer analyzer_options.<analyzer>.tokens_env so credentials do not live in the file.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(path)
			if err != nil {
				exitCode = policy.ExitUsage
				return err
			}
			printable := cfg
			printable.AnalyzerOptions = redactTokens(cfg.AnalyzerOptions)
			out, err := yaml.Marshal(printable)
			if err != nil {
				exitCode = policy.ExitInternal
				return err
			}
			fmt.Fprint(os.Stdout, string(out))
			exitCode = policy.ExitOK
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "config", "", "path to a scanner config file (empty: print the built-in defaults)")
	return cmd
}

// redactTokens copies options and masks values under each tokens key
func redactTokens(opts map[string]map[string]any) map[string]map[string]any {
	if opts == nil {
		return nil
	}
	out := make(map[string]map[string]any, len(opts))
	for analyzer, m := range opts {
		cp := make(map[string]any, len(m))
		for k, v := range m {
			if k == "tokens" {
				v = redactTokenCases(v)
			}
			cp[k] = v
		}
		out[analyzer] = cp
	}
	return out
}

// redactTokenCases masks supported token-map values and leaves other shapes unchanged
func redactTokenCases(v any) any {
	switch m := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			if s, ok := val.(string); ok && s != "" {
				out[k] = redactedTokenValue
			} else {
				out[k] = val
			}
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(m))
		for k, val := range m {
			if val != "" {
				out[k] = redactedTokenValue
			} else {
				out[k] = val
			}
		}
		return out
	default:
		return v
	}
}
