package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
)

// knownAnalyzerNames lists public analyzers, including optional build-tagged ones.
// Deliberately unregistered integrations are not part of this vocabulary.
var knownAnalyzerNames = []string{
	"protocol", "auth", "yara", "promptdefense", "readiness", "source",
	"taint", "behavioral", "runtime", "supplychain", "llm",
}

// wrapWidth keeps detailed output readable without a terminal-width dependency
const wrapWidth = 96

func newAnalyzersCmd() *cobra.Command {
	var details bool
	cmd := &cobra.Command{
		Use:   "analyzers",
		Short: "List known analyzers, including ones not available in this build",
		RunE: func(cmd *cobra.Command, args []string) error {
			printAnalyzers(cmd.OutOrStdout(), details)
			return nil
		},
	}
	cmd.Flags().BoolVar(&details, "details", false, "show detections and limitations instead of the summary table")
	return cmd
}

func printAnalyzers(w io.Writer, details bool) {
	registered := map[string]analyzer.Analyzer{}
	for _, a := range analyzer.Default.All() {
		registered[a.Name()] = a
	}
	if details {
		printAnalyzerDetails(w, registered)
		return
	}
	printAnalyzerTable(w, registered)
}

// analyzerNames appends unlisted registrations after the documented order
func analyzerNames() []string {
	seen := map[string]bool{}
	names := make([]string, 0, len(knownAnalyzerNames))
	for _, n := range knownAnalyzerNames {
		seen[n] = true
		names = append(names, n)
	}
	for _, n := range analyzer.Default.Names() {
		if !seen[n] {
			names = append(names, n)
		}
	}
	return names
}

func printAnalyzerTable(w io.Writer, registered map[string]analyzer.Analyzer) {
	names := analyzerNames()
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tIN BUILD\tPROBES\tNEEDS\tEVIDENCE\tBLIND SPOTS")

	available := 0
	for _, name := range names {
		a, ok := registered[name]
		if !ok {
			fmt.Fprintf(tw, "%s\tno\t-\t-\t-\t-\n", name)
			continue
		}
		available++
		d, ok := a.(analyzer.Describer)
		if !ok {
			// Missing metadata means unknown, not none
			fmt.Fprintf(tw, "%s\tyes\t?\t?\t?\t?\n", name)
			continue
		}
		desc := d.Describe()
		fmt.Fprintf(tw, "%s\tyes\t%s\t%s\t%s\t%d\n",
			name, yesNo(desc.Active), analyzerNeeds(desc), analyzerEvidence(desc), len(desc.Limitations))
	}
	tw.Flush()

	fmt.Fprintf(w, "\n%d of %d analyzers are in this build. PROBES means the analyzer sends the\n", available, len(names))
	fmt.Fprintln(w, "target something it can observe. BLIND SPOTS counts the limits an analyzer")
	fmt.Fprintln(w, "declares about itself; --details prints them.")
}

func printAnalyzerDetails(w io.Writer, registered map[string]analyzer.Analyzer) {
	for i, name := range analyzerNames() {
		if i > 0 {
			fmt.Fprintln(w)
		}
		a, ok := registered[name]
		if !ok {
			fmt.Fprintf(w, "%s\n  not compiled into this build\n", name)
			continue
		}
		d, ok := a.(analyzer.Describer)
		if !ok {
			fmt.Fprintf(w, "%s\n  in this build, with no self-description\n", name)
			continue
		}
		desc := d.Describe()

		tags := []string{"passive"}
		if desc.Active {
			tags[0] = "sends active probes"
		}
		if n := analyzerNeeds(desc); n != "-" {
			tags = append(tags, "needs "+strings.ReplaceAll(n, ",", ", "))
		}
		fmt.Fprintf(w, "%s - %s\n", name, strings.Join(tags, ", "))
		fmt.Fprint(w, wrapIndent(desc.Purpose, "  ", "  "))

		if len(desc.Threats) > 0 {
			fmt.Fprintln(w, "\n  Detects:")
			writeBullets(w, desc.Threats, "    ")
		}
		if len(desc.Evidence) > 0 {
			fmt.Fprintf(w, "\n  Evidence: %s\n", strings.ReplaceAll(analyzerEvidence(desc), ",", ", "))
		}
		if len(desc.Limitations) > 0 {
			fmt.Fprintln(w, "\n  Blind spots:")
			writeBullets(w, desc.Limitations, "    ")
		}
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func analyzerNeeds(d analyzer.Description) string {
	var needs []string
	if d.RequiresNetwork {
		needs = append(needs, "network")
	}
	if d.RequiresDocker {
		needs = append(needs, "docker")
	}
	if d.RequiresCredentials {
		needs = append(needs, "credentials")
	}
	if len(needs) == 0 {
		return "-"
	}
	return strings.Join(needs, ",")
}

func analyzerEvidence(d analyzer.Description) string {
	if len(d.Evidence) == 0 {
		return "-"
	}
	levels := make([]string, len(d.Evidence))
	for i, e := range d.Evidence {
		levels[i] = string(e)
	}
	return strings.Join(levels, ",")
}

func writeBullets(w io.Writer, items []string, indent string) {
	for _, it := range items {
		fmt.Fprint(w, wrapIndent(it, indent+"- ", indent+"  "))
	}
}

// wrapIndent wraps prose and aligns continuation lines without splitting words
func wrapIndent(s, first, rest string) string {
	var b strings.Builder
	prefix, line := first, ""
	flush := func() {
		if line == "" {
			return
		}
		b.WriteString(prefix)
		b.WriteString(line)
		b.WriteByte('\n')
		prefix, line = rest, ""
	}
	for word := range strings.FieldsSeq(s) {
		switch {
		case line == "":
			line = word
		case utf8.RuneCountInString(prefix+line+word)+1 <= wrapWidth:
			line += " " + word
		default:
			flush()
			line = word
		}
	}
	flush()
	return b.String()
}
