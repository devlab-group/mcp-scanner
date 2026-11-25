package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/devlab-group/mcp-scanner/internal/attestation"
	"github.com/devlab-group/mcp-scanner/internal/policy"
)

// newAttestationCmd answers a question the scanner itself cannot: given a signed record somebody
// else produced about these bytes, may I install them? It is a verifier, not a scanner - it runs
// no analyzers and produces no findings.
func newAttestationCmd() *cobra.Command {
	var (
		bundlePath   string
		keyPath      string
		expectedSHA  string
		asJSON       bool
		failOnReview bool
	)

	cmd := &cobra.Command{
		Use:   "verify-attestation",
		Short: "Verify a signed scan record against the artifact you are about to install",
		Long: `Verify a DSSE envelope whose payload is an in-toto Statement v1, and turn it into
allow / review / block.

The record must bind to the artifact digest you pass in --artifact-sha256. A verdict that is not
bound to those bytes says nothing about them, so a bundle with no subject digest is reported as
inconclusive rather than clean, and an expired record blocks even when its signature is valid.

Exit codes follow the rest of the CLI: 0 allow, 2 block, 3 inconclusive (could not answer),
1 usage, 4 internal.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if bundlePath == "" {
				return failUsage(fmt.Errorf("--bundle is required"))
			}
			if keyPath == "" {
				return failUsage(fmt.Errorf("--key is required"))
			}
			if expectedSHA == "" {
				return failUsage(fmt.Errorf("--artifact-sha256 is required: an unbound verdict says nothing about the bytes you install"))
			}

			bundle, err := os.ReadFile(bundlePath)
			if err != nil {
				exitCode = policy.ExitUsage
				return fmt.Errorf("read bundle: %w", err)
			}
			key, err := os.ReadFile(keyPath)
			if err != nil {
				exitCode = policy.ExitUsage
				return fmt.Errorf("read public key: %w", err)
			}

			res := attestation.Verify(bundle, key, expectedSHA, time.Now())

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(res); err != nil {
					exitCode = policy.ExitInternal
					return err
				}
			} else {
				fmt.Fprintf(os.Stdout, "%s", res.Decision)
				if res.Subject != "" {
					fmt.Fprintf(os.Stdout, "  %s", res.Subject)
				}
				fmt.Fprintln(os.Stdout)
				for _, reason := range res.Reasons {
					fmt.Fprintf(os.Stdout, "  - %s\n", reason)
				}
			}

			switch res.Decision {
			case attestation.DecisionAllow:
				exitCode = policy.ExitOK
			case attestation.DecisionReview:
				if failOnReview {
					exitCode = policy.ExitPolicyFail
				} else {
					exitCode = policy.ExitOK
				}
			case attestation.DecisionBlock:
				exitCode = policy.ExitPolicyFail
			default:
				exitCode = policy.ExitIncomplete
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&bundlePath, "bundle", "", "path to the DSSE bundle JSON")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to the public key (in-toto ed25519 JSON, JWK, or PEM)")
	cmd.Flags().StringVar(&expectedSHA, "artifact-sha256", "", "sha256 of the artifact you are about to install")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the verdict as JSON")
	cmd.Flags().BoolVar(&failOnReview, "fail-on-review", false, "treat a pass-with-findings record as a policy failure")
	return cmd
}
