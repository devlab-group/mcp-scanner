package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/revinand/mcp-scanner/internal/policy"
	reportjson "github.com/revinand/mcp-scanner/internal/report/json"
	"github.com/revinand/mcp-scanner/internal/report/sarif"
	"github.com/revinand/mcp-scanner/internal/report/summary"
	"github.com/revinand/mcp-scanner/internal/report/table"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/pkg/scanner"
)

// writeReport uses the validated format. Human formats also explain the policy decision
func writeReport(w io.Writer, res *model.ScanResult, format string, decision *policy.Decision) error {
	switch format {
	case "json":
		return reportjson.Write(w, res)
	case "sarif":
		return sarif.Write(w, res)
	case "table":
		return table.Write(w, res, decision)
	default:
		return summary.Write(w, res, decision)
	}
}

// openOutput returns stdout or a report file and a safe closer. Mode 0600 applies when the file
// is created; truncating an existing file preserves that file's current permissions.
func openOutput(path string) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	// Reports expose weaknesses, so new files start with owner-only permissions
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file %s: %w", path, err)
	}
	return f, f.Close, nil
}

// runScanAndReport applies policy, writes the report, and returns the process code
func runScanAndReport(ctx context.Context, sc *scanner.Scanner, target model.Target, r resolved) (int, error) {
	res, err := sc.Scan(ctx, target, r.sopts)
	if err != nil {
		// Invalid input is a usage error, not a security verdict
		return policy.ExitUsage, fmt.Errorf("scan: %w", err)
	}

	decision := r.pol.Apply(res)

	w, closeFn, err := openOutput(r.output)
	if err != nil {
		return policy.ExitInternal, err
	}
	writeErr := writeReport(w, res, r.format, &decision)
	closeErr := closeFn()
	if writeErr != nil {
		return policy.ExitInternal, fmt.Errorf("write report: %w", writeErr)
	}
	if closeErr != nil {
		return policy.ExitInternal, fmt.Errorf("close output: %w", closeErr)
	}

	return decision.ExitCode, nil
}

// failUsage gives invalid input a consistent exit code
func failUsage(err error) error {
	exitCode = policy.ExitUsage
	return err
}

// runAndSetExit records scan and policy outcomes without presenting them as Cobra errors. Only
// failure to run is returned; UNSAFE is a valid scan result with its own exit code.
func runAndSetExit(ctx context.Context, sc *scanner.Scanner, target model.Target, r resolved) error {
	code, err := runScanAndReport(ctx, sc, target, r)
	if err != nil {
		exitCode = code
		return err
	}
	exitCode = code
	return nil
}
