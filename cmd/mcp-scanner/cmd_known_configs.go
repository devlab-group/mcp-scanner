package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/devlab-group/mcp-scanner/internal/app"
	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/internal/report"
	reportjson "github.com/devlab-group/mcp-scanner/internal/report/json"
	"github.com/devlab-group/mcp-scanner/internal/report/sarif"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/pkg/scanner"
)

// discoveredServer is an MCP server found in a client config
type discoveredServer struct {
	Source string
	Name   string
	Target model.Target
}

type rawServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	Type    string            `json:"type"`
	Headers map[string]string `json:"headers"`
}

// toTarget preserves remote headers without serializing them. URL presence
// selects the kind; Type only selects a compatible remote transport.
func (s rawServer) toTarget(name string) model.Target {
	if s.URL != "" {
		return model.Target{Kind: model.TargetRemote, Name: name, URL: s.URL, Headers: s.Headers, Transport: remoteConfigTransport(s.Type)}
	}
	return model.Target{Kind: model.TargetStdio, Name: name, Command: s.Command, Args: s.Args, Env: s.Env}
}

// remoteConfigTransport maps supported client spellings to scanner transports.
// Unknown values use automatic detection.
func remoteConfigTransport(t string) string {
	switch t {
	case "http", "streamable-http":
		return "streamable"
	case "sse":
		return "sse"
	default:
		return ""
	}
}

// candidateConfigPaths returns existing config paths for supported clients
func candidateConfigPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var paths []string
	add := func(p string) {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
		}
	}

	switch runtime.GOOS {
	case "darwin":
		add(filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"))
		add(filepath.Join(home, "Library", "Application Support", "Code", "User", "settings.json"))
	case "windows":
		appData := os.Getenv("APPDATA")
		add(filepath.Join(appData, "Claude", "claude_desktop_config.json"))
		add(filepath.Join(appData, "Code", "User", "settings.json"))
	default:
		add(filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"))
		add(filepath.Join(home, ".config", "Code", "User", "settings.json"))
	}
	add(filepath.Join(home, ".cursor", "mcp.json"))
	return paths
}

// parseClientConfig accepts Claude, Cursor, and VS Code config shapes.
// It distinguishes invalid JSON from a valid file with no MCP section.
func parseClientConfig(data []byte) (map[string]rawServer, error) {
	var probe any
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, unreadableConfigError{fmt.Errorf("file is not valid JSON: %w", err)}
	}
	var direct struct {
		MCPServers map[string]rawServer `json:"mcpServers"`
	}
	directErr := json.Unmarshal(data, &direct)
	if directErr == nil && len(direct.MCPServers) > 0 {
		return direct.MCPServers, nil
	}
	var nested struct {
		MCP struct {
			Servers map[string]rawServer `json:"servers"`
		} `json:"mcp"`
	}
	nestedErr := json.Unmarshal(data, &nested)
	if nestedErr == nil && len(nested.MCP.Servers) > 0 {
		return nested.MCP.Servers, nil
	}
	// A present but malformed MCP section is an error, not an empty config
	if directErr != nil || nestedErr != nil {
		return nil, unreadableConfigError{
			fmt.Errorf("mcpServers or mcp.servers entry does not parse: %w", errors.Join(directErr, nestedErr)),
		}
	}
	// Valid files without an MCP section are common and are not skipped errors
	return nil, nil
}

// stripJSONComments converts JSONC to strict JSON without changing offsets.
// It preserves comment-like text inside strings and follows JSON escaping.
func stripJSONComments(data []byte) []byte {
	out := append([]byte(nil), data...)
	var inString, escaped bool
	pendingComma := -1 // index of the last top-level comma, until proven not trailing
	n := len(data)
	for i := 0; i < n; i++ {
		c := data[i]
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			pendingComma = -1
		case c == '/' && i+1 < n && data[i+1] == '/':
			j := i
			for j < n && data[j] != '\n' {
				out[j] = ' '
				j++
			}
			i = j - 1
		case c == '/' && i+1 < n && data[i+1] == '*':
			j := i
			for j < n-1 && !(data[j] == '*' && data[j+1] == '/') {
				if data[j] != '\n' {
					out[j] = ' '
				}
				j++
			}
			if j >= n-1 {
				// Let the JSON parser report an unterminated block comment
				for ; j < n; j++ {
					if data[j] != '\n' {
						out[j] = ' '
					}
				}
				i = j - 1
				continue
			}
			out[j], out[j+1] = ' ', ' '
			i = j + 1
		case c == ',':
			pendingComma = i
		case c == '}' || c == ']':
			if pendingComma >= 0 {
				out[pendingComma] = ' '
			}
			pendingComma = -1
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			// Whitespace does not determine whether a comma is trailing
		default:
			pendingComma = -1
		}
	}
	return out
}

// unreadableConfigError distinguishes invalid files from configs with no servers
type unreadableConfigError struct{ err error }

func (e unreadableConfigError) Error() string { return e.err.Error() }
func (e unreadableConfigError) Unwrap() error { return e.err }

func discoverConfiguredServers() ([]discoveredServer, []string, bool) {
	var out []discoveredServer
	var skipped []string
	unreadable := false
	for _, path := range candidateConfigPaths() {
		// Client configs are untrusted, so cap each read
		data, err := app.ReadCapped(path, app.MaxStaticSnapshotBytes)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", path, err))
			unreadable = true
			continue
		}
		// VS Code settings use JSONC; the other supported clients use strict JSON
		if filepath.Base(path) == "settings.json" {
			data = stripJSONComments(data)
		}
		servers, err := parseClientConfig(data)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", path, err))
			if _, ok := errors.AsType[unreadableConfigError](err); ok {
				unreadable = true
			}
			continue
		}
		// A valid file with no servers needs no warning
		for name, s := range servers {
			out = append(out, discoveredServer{Source: path, Name: name, Target: s.toTarget(name)})
		}
	}
	return out, skipped, unreadable
}

// printDiscovered sanitizes config-controlled values before displaying them. An installed
// server may be able to edit these files, so their contents must not forge terminal output.
func printDiscovered(out io.Writer, servers []discoveredServer, skipped []string) {
	if len(servers) == 0 {
		fmt.Fprintln(out, "no MCP servers found in any known client config")
	}
	for _, s := range servers {
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\n",
			report.Sanitize(s.Name), s.Target.Kind, report.Sanitize(s.Target.Describe()), report.Sanitize(s.Source))
	}
	for _, w := range skipped {
		fmt.Fprintf(out, "skipped: %s\n", report.Sanitize(w))
	}
}

// newKnownConfigsCmd lists configured servers. Running stdio targets requires
// both --run and --include-stdio.
func newKnownConfigsCmd(flags *commonFlags) *cobra.Command {
	var run, includeStdio bool
	cmd := &cobra.Command{
		Use:   "known-configs",
		Short: "List MCP servers configured in Claude Desktop, VS Code, and Cursor",
		RunE: func(cmd *cobra.Command, args []string) error {
			servers, skipped, unreadable := discoverConfiguredServers()

			if !run {
				printDiscovered(cmd.OutOrStdout(), servers, skipped)
				// Unreadable config makes the listing incomplete
				if unreadable {
					exitCode = policy.ExitIncomplete
				} else {
					exitCode = policy.ExitOK
				}
				return nil
			}
			return runDiscoveredServers(cmd, flags, servers, skipped, unreadable, includeStdio)
		},
	}
	cmd.Flags().BoolVar(&run, "run", false, "also scan discovered remote servers (stdio servers still need --include-stdio)")
	cmd.Flags().BoolVar(&includeStdio, "include-stdio", false, "with --run, also launch and scan discovered stdio servers")
	return cmd
}

func runDiscoveredServers(cmd *cobra.Command, flags *commonFlags, servers []discoveredServer, skipped []string, unreadable bool, includeStdio bool) error {
	r, err := resolve(flags)
	if err != nil {
		return failUsage(err)
	}
	sc := newScannerFor(r)
	// Keep progress off stdout when stdout contains machine-readable output
	info := cmd.OutOrStdout()
	if r.format == "json" || r.format == "sarif" {
		info = cmd.ErrOrStderr()
	}
	printDiscovered(info, servers, skipped)
	code, err := scanDiscoveredServers(cmd.Context(), info, sc, r, servers, unreadable, includeStdio)
	exitCode = code
	return err
}

// scanDiscoveredServers scans eligible targets and writes one combined report.
// The output opens once so later targets cannot truncate earlier results.
func scanDiscoveredServers(ctx context.Context, out io.Writer, sc *scanner.Scanner, r resolved, servers []discoveredServer, unreadable bool, includeStdio bool) (int, error) {
	var w io.Writer
	var closeOutput func() error
	var jsonResults, sarifResults []*model.ScanResult
	worst := policy.ExitOK
	var writeErr error
	ran := false
	stdioSkipped := false

	for _, s := range servers {
		if s.Target.Kind == model.TargetStdio && !includeStdio {
			fmt.Fprintf(out, "--- skipping stdio server %s (pass --include-stdio to scan it) ---\n", report.Sanitize(s.Name))
			stdioSkipped = true
			continue
		}
		if !ran {
			var err error
			w, closeOutput, err = openOutput(r.output)
			if err != nil {
				return policy.ExitInternal, err
			}
			ran = true
		}
		fmt.Fprintf(out, "--- %s (%s) ---\n", report.Sanitize(s.Name), report.Sanitize(s.Source))

		res, scanErr := sc.Scan(ctx, s.Target, r.sopts)
		if scanErr != nil {
			// Sanitize all output on this config-controlled path
			fmt.Fprintf(out, "error: %s\n", report.Sanitize(scanErr.Error()))
			if policy.ExitUsage > worst {
				worst = policy.ExitUsage
			}
			continue
		}
		decision := r.pol.Apply(res)
		if decision.ExitCode > worst {
			worst = decision.ExitCode
		}

		switch r.format {
		case "json":
			jsonResults = append(jsonResults, res)
		case "sarif":
			sarifResults = append(sarifResults, res)
		default:
			if writeErr == nil {
				writeErr = writeReport(w, res, r.format, &decision)
			}
		}
	}
	if !ran {
		if stdioSkipped || unreadable {
			// Skipped targets or unreadable configs make an empty run incomplete
			return policy.ExitIncomplete, nil
		}
		return policy.ExitOK, nil
	}

	if writeErr == nil {
		switch r.format {
		case "json":
			writeErr = reportjson.WriteMany(w, jsonResults)
		case "sarif":
			writeErr = sarif.WriteMany(w, sarifResults)
		}
	}

	closeErr := closeOutput()
	if writeErr != nil {
		return policy.ExitInternal, fmt.Errorf("write report: %w", writeErr)
	}
	if closeErr != nil {
		return policy.ExitInternal, fmt.Errorf("close output: %w", closeErr)
	}
	if (stdioSkipped || unreadable) && policy.ExitIncomplete > worst {
		worst = policy.ExitIncomplete
	}
	return worst, nil
}
