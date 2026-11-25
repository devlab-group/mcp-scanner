package dossier

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/analyzers/behavioral"
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
)

var (
	hintText = regexp.MustCompile(`\b(readOnlyHint|destructiveHint|idempotentHint|openWorldHint|ReadOnlyHint|DestructiveHint|IdempotentHint|OpenWorldHint)["']?\s*(?:=|:)\s*(true|false|True|False)\b`)
	hintCall = regexp.MustCompile(`\bWith(ReadOnly|Destructive|Idempotent|OpenWorld)HintAnnotation\(\s*(true|false)\s*\)`)
)

// annotations are the hints a registration spells: the arguments of the registration call, or of
// the decorators between the previous capability of the file and this one
func annotations(g *graph.Graph, c graph.Capability) map[string]bool {
	prev := 0
	for _, o := range g.Capabilities {
		if o.File == c.File && o.Line < c.Line && o.Line > prev {
			prev = o.Line
		}
	}
	out := map[string]bool{}
	for _, call := range g.Calls {
		if call.File != c.File || !(call.Line == c.Line && !call.IsDecorator || call.IsDecorator && call.Line > prev && call.Line <= c.Line) {
			continue
		}
		for _, a := range call.Args {
			if a.HandlerID != "" {
				continue // the handler's own body
			}
			for _, m := range hintText.FindAllStringSubmatch(a.Text+" "+a.Keyword, -1) {
				out[hintName(m[1])] = strings.EqualFold(m[2], "true")
			}
			for _, m := range hintCall.FindAllStringSubmatch(a.Text, -1) {
				out[hintName(m[1]+"Hint")] = m[2] == "true"
			}
		}
		for _, m := range hintText.FindAllStringSubmatch(decoratorText(call), -1) {
			out[hintName(m[1])] = strings.EqualFold(m[2], "true")
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func decoratorText(call graph.Call) string {
	if !call.IsDecorator {
		return ""
	}
	var parts []string
	for _, a := range call.Args {
		parts = append(parts, a.Keyword+"="+a.Text)
	}
	return strings.Join(parts, " ")
}

func hintName(s string) string {
	return strings.ToLower(s[:1]) + s[1:]
}

// annotationConflicts says where a tool's readOnlyHint or destructiveHint disagrees with what the
// calls it reaches are named. It reads names, so a write through a library or a file the code
// builds only in memory does not show, and the list is a lead, not a verdict.
func annotationConflicts(ann map[string]bool, e behavioral.Effects) []string {
	var out []string
	if ann["readOnlyHint"] {
		for _, w := range e.WritesFiles {
			out = append(out, "readOnlyHint is true, and the code writes files: "+w)
		}
		for _, w := range e.RunsPrograms {
			out = append(out, "readOnlyHint is true, and the code runs a program: "+w)
		}
	}
	if ann["destructiveHint"] == false && hasKey(ann, "destructiveHint") {
		for _, w := range e.WritesFiles {
			if strings.Contains(w, "unlink") || strings.Contains(w, "rm") || strings.Contains(w, "remove") || strings.Contains(w, "Remove") {
				out = append(out, "destructiveHint is false, and the code deletes: "+w)
			}
		}
	}
	return first(out, 10)
}

func hasKey(m map[string]bool, k string) bool { _, ok := m[k]; return ok }

// Combination is a server-level lead: it can read private data, takes text from outside and can
// send data on. Each list names the capabilities that do it.
type Combination struct {
	Private  []string `json:"reads_private,omitempty"`
	External []string `json:"takes_external_text,omitempty"`
	Outbound []string `json:"can_send_out,omitempty"`
	All      bool     `json:"all_three"`
}

// combination reads the three parts from every capability's behavior and effects
func combination(caps []Capability) *Combination {
	c := &Combination{}
	for _, cp := range caps {
		b, e := cp.Behavior, cp.Effects
		if b != nil && (b.Filesystem || b.Credentials || len(b.SensitivePaths) > 0) {
			c.Private = append(c.Private, cp.Name)
		}
		if e != nil && contains(e.ReadsText, "network") {
			c.External = append(c.External, cp.Name)
		}
		if e != nil && len(e.SendsData) > 0 || b != nil && b.Egress != nil && len(b.Egress.CallerAddressed) > 0 {
			c.Outbound = append(c.Outbound, cp.Name)
		}
	}
	if len(c.Private)+len(c.External)+len(c.Outbound) == 0 {
		return nil
	}
	c.All = len(c.Private) > 0 && len(c.External) > 0 && len(c.Outbound) > 0
	for _, l := range []*[]string{&c.Private, &c.External, &c.Outbound} {
		sort.Strings(*l)
		*l = first(*l, 30)
	}
	return c
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// notTraced are the reasons a capability's path does not end in code the scanner read: it hands
// work to a backend of its own on this machine, which the scanner does not follow
func notTraced(b *behavioral.HandlerBehavior) []string {
	if b == nil {
		return nil
	}
	var out []string
	for _, h := range b.Egress.LoopbackHosts() {
		out = append(out, fmt.Sprintf("hands work to its own backend on %s, which was not traced", h))
	}
	return out
}
