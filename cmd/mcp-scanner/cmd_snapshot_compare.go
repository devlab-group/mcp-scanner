package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/devlab-group/mcp-scanner/internal/app"
	"github.com/devlab-group/mcp-scanner/internal/mcp/client"
	"github.com/devlab-group/mcp-scanner/internal/mcp/snapshot"
	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/internal/report"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// snapshotGlobalFlags are the connection flags used during capture
var snapshotGlobalFlags = []string{
	"config", "timeout", "allow-private-networks",
	"active-probes", "allow-tool-call", "read-resources", "get-prompts",
}

func newSnapshotCmd(flags *commonFlags) *cobra.Command {
	root := &cobra.Command{
		Use:   "snapshot",
		Short: "Capture an MCP server's declared surface as JSON",
	}
	root.AddCommand(newSnapshotRemoteCmd(flags), newSnapshotStdioCmd(flags))
	return root
}

func newSnapshotRemoteCmd(flags *commonFlags) *cobra.Command {
	var output, transport string
	cmd := &cobra.Command{
		Use:     "remote <url>",
		Args:    cobra.ExactArgs(1),
		PreRunE: rejectUnusedGlobalFlags(snapshotGlobalFlags...),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := client.ValidateTransport(transport); err != nil {
				return failUsage(err)
			}
			return captureSnapshot(cmd.Context(), flags, model.Target{Kind: model.TargetRemote, URL: args[0], Transport: transport}, output)
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "write the snapshot here instead of stdout")
	cmd.Flags().StringVar(&transport, "transport", "auto", "auto|streamable|sse")
	return cmd
}

func newSnapshotStdioCmd(flags *commonFlags) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:     "stdio -- <command> [args...]",
		Args:    cobra.MinimumNArgs(1),
		PreRunE: rejectUnusedGlobalFlags(snapshotGlobalFlags...),
		RunE: func(cmd *cobra.Command, args []string) error {
			return captureSnapshot(cmd.Context(), flags, model.Target{Kind: model.TargetStdio, Command: args[0], Args: args[1:]}, output)
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "write the snapshot here instead of stdout")
	return cmd
}

// captureSnapshot uses the same connection settings as a scan. Timeouts, private-network policy,
// transport selection, and content-fetch switches must not change meaning for a capture.
func captureSnapshot(ctx context.Context, flags *commonFlags, target model.Target, output string) error {
	r, err := resolve(flags)
	if err != nil {
		return failUsage(err)
	}
	prep := client.NewPreparer(app.ClientOptions(r.cfg))
	ac, cleanup, err := prep.Prepare(ctx, target)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		exitCode = policy.ExitIncomplete
		return err
	}
	if ac == nil || ac.Snapshot == nil {
		exitCode = policy.ExitIncomplete
		return fmt.Errorf("no snapshot was captured for %s", target.Describe())
	}

	unknownGaps := unknownTruncations(ac.Snapshot)
	for _, w := range unknownGaps {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	w, closeFn, err := openOutput(output)
	if err != nil {
		exitCode = policy.ExitInternal
		return err
	}
	writeErr := snapshot.Write(w, ac.Snapshot)
	closeErr := closeFn()
	if writeErr != nil {
		exitCode = policy.ExitInternal
		return writeErr
	}
	if closeErr != nil {
		exitCode = policy.ExitInternal
		return closeErr
	}
	if len(unknownGaps) > 0 {
		exitCode = policy.ExitIncomplete
		return nil
	}
	exitCode = policy.ExitOK
	return nil
}

// unknownTruncations selects capture gaps whose missing item count is unknown. capture uses it
// to choose exit 3; known, counted shortfalls still produce a usable snapshot and exit 0
func unknownTruncations(snap *model.Snapshot) []string {
	var out []string
	for _, t := range snap.Truncated {
		if t.Unknown {
			out = append(out, fmt.Sprintf("%s: %s (an unknown number of items were not read)", t.Method, t.Reason))
		}
	}
	return out
}

func newCompareCmd() *cobra.Command {
	var failOnChange bool
	cmd := &cobra.Command{
		Use:     "compare <snapshot-a.json> <snapshot-b.json>",
		Short:   "Diff two captured snapshots (tools, prompts, resources, instructions)",
		Args:    cobra.ExactArgs(2),
		PreRunE: rejectUnusedGlobalFlags(),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadSnapshotFile(args[0])
			if err != nil {
				return failUsage(err)
			}
			b, err := loadSnapshotFile(args[1])
			if err != nil {
				return failUsage(err)
			}
			d := diffSnapshots(a, b)
			printDiff(os.Stdout, d)

			if d.empty() {
				exitCode = policy.ExitOK
				return nil
			}
			if failOnChange {
				exitCode = policy.ExitPolicyFail
			} else {
				exitCode = policy.ExitOK
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&failOnChange, "fail-on-change", false, "exit 2 if the snapshots differ at all")
	return cmd
}

// loadSnapshotFile applies the static-target size cap and accepts scanner or MCP wire formats.
// The specialized loader preserves fields whose names differ between those formats.
func loadSnapshotFile(path string) (*model.Snapshot, error) {
	data, err := app.ReadCapped(path, app.MaxStaticSnapshotBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	snap, err := client.LoadSnapshotBytes(data, path)
	if err != nil {
		return nil, fmt.Errorf("parse %s as a snapshot: %w", path, err)
	}
	return snap, nil
}

// snapshotDiff compares capabilities, instructions, and server identity
type snapshotDiff struct {
	ToolsAdded, ToolsRemoved, ToolsChanged             []string
	PromptsAdded, PromptsRemoved, PromptsChanged       []string
	ResourcesAdded, ResourcesRemoved, ResourcesChanged []string
	InstructionsChanged                                bool

	// ServerIdentityChanged covers declared name, version, or title
	ServerIdentityChanged bool

	// Anomalies covers duplicate names and schemas that cannot be encoded
	Anomalies []string
}

func (d snapshotDiff) empty() bool {
	return len(d.ToolsAdded)+len(d.ToolsRemoved)+len(d.ToolsChanged)+
		len(d.PromptsAdded)+len(d.PromptsRemoved)+len(d.PromptsChanged)+
		len(d.ResourcesAdded)+len(d.ResourcesRemoved)+len(d.ResourcesChanged)+
		len(d.Anomalies) == 0 && !d.InstructionsChanged && !d.ServerIdentityChanged
}

func diffSnapshots(a, b *model.Snapshot) snapshotDiff {
	var d snapshotDiff
	d.ServerIdentityChanged = a.ServerName != b.ServerName || a.ServerVersion != b.ServerVersion || a.ServerTitle != b.ServerTitle

	aTools, anom := toolFingerprints(a.Tools)
	d.Anomalies = append(d.Anomalies, anom...)
	bTools, anom := toolFingerprints(b.Tools)
	d.Anomalies = append(d.Anomalies, anom...)
	d.ToolsAdded, d.ToolsRemoved, d.ToolsChanged = diffNamed(aTools, bTools)

	aPrompts, anom := promptFingerprints(a.Prompts)
	d.Anomalies = append(d.Anomalies, anom...)
	bPrompts, anom := promptFingerprints(b.Prompts)
	d.Anomalies = append(d.Anomalies, anom...)
	d.PromptsAdded, d.PromptsRemoved, d.PromptsChanged = diffNamed(aPrompts, bPrompts)

	aRes, anom := resourceFingerprints(a.Resources)
	d.Anomalies = append(d.Anomalies, anom...)
	bRes, anom := resourceFingerprints(b.Resources)
	d.Anomalies = append(d.Anomalies, anom...)
	d.ResourcesAdded, d.ResourcesRemoved, d.ResourcesChanged = diffNamed(aRes, bRes)

	d.InstructionsChanged = a.Instructions != b.Instructions
	return d
}

// fingerprints retains every declaration for a repeated name. This prevents a
// later duplicate from hiding an earlier change and records the protocol anomaly.
func fingerprints[T any](kind string, items []T, name func(T) string, fp func(T) (string, error)) (map[string]string, []string) {
	out := map[string]string{}
	seen := map[string]int{}
	var anomalies []string
	for _, it := range items {
		n := name(it)
		f, err := fp(it)
		if err != nil {
			anomalies = append(anomalies, fmt.Sprintf("%s %q: %v", kind, report.Sanitize(n), err))
		}
		seen[n]++
		if seen[n] == 2 {
			anomalies = append(anomalies, fmt.Sprintf("%s %q is declared more than once", kind, report.Sanitize(n)))
		}
		if prev, ok := out[n]; ok {
			out[n] = prev + "\x00" + f
			continue
		}
		out[n] = f
	}
	return out, anomalies
}

func toolFingerprints(ts []model.ToolInfo) (map[string]string, []string) {
	return fingerprints("tool", ts,
		func(t model.ToolInfo) string { return t.Name },
		func(t model.ToolInfo) (string, error) {
			schema, err := json.Marshal(t.InputSchema)
			if err != nil {
				// The error goes into the fingerprint as well as into the
				// anomaly list: a schema nothing can encode must not compare
				// equal to one that encoded fine
				return t.Description + "\x00unreadable-schema:" + err.Error(), fmt.Errorf("input schema could not be read: %w", err)
			}
			return t.Description + "\x00" + string(schema), nil
		})
}

func promptFingerprints(ps []model.PromptInfo) (map[string]string, []string) {
	return fingerprints("prompt", ps,
		func(p model.PromptInfo) string { return p.Name },
		func(p model.PromptInfo) (string, error) { return p.Description + "\x00" + p.Text, nil })
}

func resourceFingerprints(rs []model.ResourceInfo) (map[string]string, []string) {
	return fingerprints("resource", rs,
		func(r model.ResourceInfo) string {
			if r.Name == "" {
				return r.URI
			}
			return r.Name
		},
		func(r model.ResourceInfo) (string, error) { return r.Description + "\x00" + r.MIMEType, nil })
}

func diffNamed(a, b map[string]string) (added, removed, changed []string) {
	for name, fp := range b {
		old, ok := a[name]
		if !ok {
			added = append(added, name)
		} else if old != fp {
			changed = append(changed, name)
		}
	}
	for name := range a {
		if _, ok := b[name]; !ok {
			removed = append(removed, name)
		}
	}
	return
}

// printDiff sanitizes server-controlled names before writing changes. Snapshot names may come
// from a hostile server and must not inject control sequences into terminal output.
func printDiff(w *os.File, d snapshotDiff) {
	printList := func(label string, names []string) {
		for _, n := range names {
			fmt.Fprintf(w, "  %s: %s\n", label, report.Sanitize(n))
		}
	}
	if d.empty() {
		fmt.Fprintln(w, "no differences")
		return
	}
	printList("tool added", d.ToolsAdded)
	printList("tool removed", d.ToolsRemoved)
	printList("tool changed", d.ToolsChanged)
	printList("prompt added", d.PromptsAdded)
	printList("prompt removed", d.PromptsRemoved)
	printList("prompt changed", d.PromptsChanged)
	printList("resource added", d.ResourcesAdded)
	printList("resource removed", d.ResourcesRemoved)
	printList("resource changed", d.ResourcesChanged)
	if d.InstructionsChanged {
		fmt.Fprintln(w, "  instructions changed")
	}
	if d.ServerIdentityChanged {
		fmt.Fprintln(w, "  server identity changed")
	}
	// Already sanitized where each entry was built, since the name is only
	// part of the sentence here
	for _, a := range d.Anomalies {
		fmt.Fprintf(w, "  %s\n", a)
	}
}
