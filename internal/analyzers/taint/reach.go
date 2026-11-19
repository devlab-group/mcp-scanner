package taint

import (
	"fmt"
	"slices"
	"sort"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Source classes: who controls the value a traced path starts from. The MCP threat model's
// attacker is the client side - a model steered by prompt injection fills tool arguments - so
// only mcp_input is attacker input by construction.
const (
	sourceMCPInput        = "mcp_input"        // tool, prompt or resource handler argument
	sourceExternalContent = "external_content" // HTTP response body or file contents
	sourceEnvironment     = "environment"      // environment variable, set by the operator
)

// Reachability of the function a path starts in, from any MCP handler
const (
	reachYes      = "yes"      // through resolved calls
	reachPossible = "possible" // only if an unresolved call is taken to mean any function of that name
	reachNo       = "no"       // not even then
	reachUnknown  = "unknown"  // no handler resolved in this tree, so nothing can be ruled out
)

const maxReachableFrom = 3

func sourceClass(detail string) string {
	switch detail {
	case "tool handler argument", "prompt argument", "resource handler argument":
		return sourceMCPInput
	case "environment variable":
		return sourceEnvironment
	default:
		return sourceExternalContent
	}
}

// reachIndex answers, for any symbol, which MCP handlers reach it
type reachIndex struct {
	g        *graph.Graph
	byFile   map[string][]*graph.Symbol
	resolved map[graph.SymbolID][]string
	possible map[graph.SymbolID][]string
	handlers int
}

func newReachIndex(g *graph.Graph) *reachIndex {
	r := &reachIndex{g: g, byFile: map[string][]*graph.Symbol{}, resolved: map[graph.SymbolID][]string{}, possible: map[graph.SymbolID][]string{}}
	for _, s := range g.Symbols {
		r.byFile[s.File] = append(r.byFile[s.File], s)
	}
	seeds := map[graph.SymbolID][]string{}
	for _, c := range g.Capabilities {
		if c.Handler == "" {
			continue
		}
		name := c.Name
		if !c.NameResolved || name == "" {
			if s := g.Symbols[c.Handler]; s != nil {
				name = fmt.Sprintf("%s:%d", s.File, s.Line)
			}
		}
		seeds[c.Handler] = addLabel(seeds[c.Handler], string(c.Kind)+" "+name)
		r.handlers++
	}
	if r.handlers == 0 {
		return r
	}
	byName := map[string][]graph.SymbolID{}
	for id, s := range g.Symbols {
		byName[s.Name] = append(byName[s.Name], id)
	}
	r.resolved = propagate(g, seeds, nil)
	r.possible = propagate(g, seeds, byName)
	return r
}

// propagate spreads handler labels along call edges. With byName set, an unresolved call also
// reaches every symbol whose name is the call's last segment - a deliberate over-approximation,
// so "not reachable" is only claimed when no reading of the call graph reaches the symbol.
func propagate(g *graph.Graph, seeds map[graph.SymbolID][]string, byName map[string][]graph.SymbolID) map[graph.SymbolID][]string {
	labels := map[graph.SymbolID][]string{}
	var queue []graph.SymbolID
	for id, ls := range seeds {
		labels[id] = append([]string(nil), ls...)
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, call := range g.CallsFrom(cur) {
			var targets []graph.SymbolID
			if call.Resolved {
				targets = []graph.SymbolID{call.Callee}
			} else if byName != nil {
				targets = byName[parser.LastSegment(call.CalleeText)]
			}
			for _, t := range targets {
				before := len(labels[t])
				for _, l := range labels[cur] {
					labels[t] = addLabel(labels[t], l)
				}
				// Re-visit a symbol only when it gained a label; each can gain at most
				// maxReachableFrom, which bounds the walk
				if len(labels[t]) > before {
					queue = append(queue, t)
				}
			}
		}
	}
	return labels
}

func addLabel(ls []string, l string) []string {
	if len(ls) >= maxReachableFrom || slices.Contains(ls, l) {
		return ls
	}
	return append(ls, l)
}

// enclosing returns the innermost symbol whose body covers file:line
func (r *reachIndex) enclosing(file string, line int) *graph.Symbol {
	var best *graph.Symbol
	for _, s := range r.byFile[file] {
		if s.Line > line || (s.EndLine != 0 && s.EndLine < line) {
			continue
		}
		if best == nil || s.Line > best.Line || (s.Line == best.Line && s.EndLine < best.EndLine) {
			best = s
		}
	}
	return best
}

func (r *reachIndex) of(file string, line int) (string, []string) {
	if r.handlers == 0 {
		return reachUnknown, nil
	}
	s := r.enclosing(file, line)
	if s == nil {
		// Module-level code runs when its file is loaded, which the call graph does not model
		return reachPossible, nil
	}
	if ls := r.resolved[s.ID]; len(ls) > 0 {
		return reachYes, sorted(ls)
	}
	if ls := r.possible[s.ID]; len(ls) > 0 {
		return reachPossible, sorted(ls)
	}
	return reachNo, nil
}

func sorted(ls []string) []string {
	out := append([]string(nil), ls...)
	sort.Strings(out)
	return out
}

// classify sets source class, reachability, severity and triage on taint findings.
//
// Severity says how bad the sink is if the finding is real; triage says how sure the scanner is
// that it is real. The catalogue severity holds for MCP input, the attacker by construction. It
// also stays for content from a URL or a file, which may be attacker-written - a fetched page, a
// cloned repository - or the server's own data: the path alone cannot tell which, so those keep
// their severity and go to needs_review when it is high. Severity is lowered only where the MCP
// threat model's attacker does not control the source: an environment variable the operator
// sets, or code no MCP handler can reach (tests, build scripts, an unrelated CLI).
func classify(g *graph.Graph, fs []model.Finding) []model.Finding {
	if len(fs) == 0 {
		return fs
	}
	r := newReachIndex(g)
	guards := guardIndex{root: g.Root, files: map[string][]string{}}
	for i := range fs {
		f := &fs[i]
		if len(f.Evidence) == 0 || len(f.Evidence[0].Path) == 0 {
			continue
		}
		src := f.Evidence[0].Path[0]
		f.SourceClass = sourceClass(src.Detail)
		f.Reachability, f.ReachableFrom = r.of(src.File, src.Line)
		original := f.Severity

		switch {
		case f.SourceClass == sourceMCPInput:
			// Seeded from a handler, so reachable by construction
			f.Reachability = reachYes
			if f.Triage == model.TriageNeedsReview {
				// The walker already sent it to review, with its own reason
				break
			}
			if step, ok := validatorStep(f.Evidence[0].Path); ok && original.AtLeast(model.SeverityHigh) {
				f.Triage, f.TriageReason = model.TriageNeedsReview,
					fmt.Sprintf("the argument passes through %s, the project's own validation function; whether it really rejects the dangerous input decides between a real issue and noise, and the scanner does not verify it", step)
				break
			}
			_, unresolved := unresolvedStep(f.Evidence[0].Path)
			if !unresolved && asCapability(g, f) {
				break
			}
			if guard, line, ok := guardIfHigh(guards, original, f.Evidence[0].Path); ok {
				f.Triage, f.TriageReason = model.TriageNeedsReview,
					fmt.Sprintf("before the sink the handler checks the value (%s, line %d) and stops when the check fails; whether that check blocks every dangerous value decides between a real issue and noise, and the scanner does not verify it", guard, line)
				break
			}
			if step, ok := unresolvedStep(f.Evidence[0].Path); ok && original.AtLeast(model.SeverityHigh) {
				f.Triage, f.TriageReason = model.TriageNeedsReview,
					fmt.Sprintf("the path assumes the result of %s, a call the scanner could not follow, carries the tool argument on; whether it does decides between a real issue and noise", step)
			}
		case f.Reachability == reachNo:
			f.Severity = model.SeverityInfo
			f.Triage, f.TriageReason = model.TriageContext,
				fmt.Sprintf("the path starts in code no MCP handler reaches (%s in %s); severity lowered from %s", src.Detail, src.File, original)
		case f.SourceClass == sourceEnvironment:
			f.Severity = capSeverity(f.Severity, model.SeverityLow)
			f.Triage, f.TriageReason = model.TriageContext,
				fmt.Sprintf("the value comes from an environment variable the operator sets, not from MCP input; severity lowered from %s", original)
		case f.Reachability == reachUnknown:
			if original.AtLeast(model.SeverityHigh) {
				f.Triage, f.TriageReason = model.TriageNeedsReview,
					"no MCP handler was resolved in this tree, so whether this path is reachable from MCP input is unknown"
			}
		default: // external content, reachable or possibly reachable
			if original.AtLeast(model.SeverityHigh) {
				f.Triage, f.TriageReason = model.TriageNeedsReview,
					fmt.Sprintf("%s reaches a %s sink; whether an attacker can write that content - a fetched page, a cloned repository - or it is the server's own configuration decides between a real issue and noise", src.Detail, f.Category)
			}
		}
	}
	return fs
}

// validatorStep returns the project validator a path passed through, if any
func validatorStep(path []model.FlowStep) (string, bool) {
	for _, st := range path {
		if st.Detail == validatorDetail {
			return st.Symbol, true
		}
	}
	return "", false
}

// unresolvedStep returns the first step of a path that passed taint through the result of a call
// the analyzer could not follow - a library call, an API response, a parser - which it assumes
// carries its tainted argument on
func unresolvedStep(path []model.FlowStep) (string, bool) {
	for _, st := range path {
		if st.Kind == "unknown" {
			return st.Symbol, true
		}
	}
	return "", false
}

func capSeverity(s, max model.Severity) model.Severity {
	if s.Rank() > max.Rank() {
		return max
	}
	return s
}
