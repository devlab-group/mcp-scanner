package taint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/analyzers/behavioral"
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A dangerous capability is a tool whose stated purpose is what the sink does: a run_query tool
// whose argument reaches cursor.execute, a read_file tool whose path reaches open(). That is not
// an injection - nothing is smuggled past the tool - but it is real risk: an agent steered by
// prompt injection can use the tool to do exactly that. It is reported apart from injections,
// with severity set by the restrictions the scanner can see.
const (
	capProcess = "process_execution"
	capCode    = "code_execution"
	capFile    = "file_access"
	capNetwork = "network_request"
	capSQL     = "sql_execution"
)

var capabilityPhrase = map[string]string{
	capProcess: "runs a command built from the caller's argument",
	capCode:    "executes code the caller supplies",
	capFile:    "reads or writes a file path the caller supplies",
	capNetwork: "sends a request to an address the caller supplies",
	capSQL:     "executes a query the caller supplies",
}

var (
	commandWords = regexp.MustCompile(`(?i)\b(command|commands|cmd|shell|bash|zsh|powershell|terminal|exec|executes? (a |the |any )?(command|script|program)|runs? (a |the |any )?(command|script|program|shell))\b`)
	sqlWords     = regexp.MustCompile(`(?i)\b(sql|query|queries|database|databases|table|tables|select|kql|cypher|graphql)\b`)
	codeWords    = regexp.MustCompile(`(?i)\b(code|script|scripts|repl|evaluate|evaluates|eval|python|javascript|notebook|interpreter)\b`)
	// A description that promises a boundary the tool would have to enforce
	promisesScope = regexp.MustCompile(`(?i)\b(under|within|inside|only|allowed|allowlist(ed)?|whitelist(ed)?|sandbox(ed)?|restricted|scoped|configured (root|director(y|ies)|hosts?|domains?)|workspace|project (root|director(y|ies)))\b`)
	// Calls that ask the user before acting: MCP elicitation and the common confirm helpers
	confirmCall = regexp.MustCompile(`(?i)^(elicit|elicitinput|elicitation|requestconfirmation|askconfirmation|confirm|requestapproval|askuser)$`)
)

// capabilityOf maps a sink category to the capability a tool would have to declare for the sink
// to be its purpose, and reports whether the tool's name or description declares it
func capabilityOf(category, name, description string) (string, bool) {
	text := strings.ReplaceAll(strings.ReplaceAll(name, "_", " "), "-", " ") + ". " + description
	fs, net, proc := behavioral.Declared(text)
	switch category {
	case "command_injection", "argument_injection":
		// Only a tool that says it runs commands: "archive" or "build" declare running something,
		// not running whatever the caller passes, and an option smuggled into their argv is an
		// injection
		_ = proc
		return capProcess, commandWords.MatchString(text)
	case "eval":
		return capCode, codeWords.MatchString(text)
	case "path_traversal":
		return capFile, fs
	case "ssrf", "raw_socket":
		return capNetwork, net
	case "sql_injection":
		return capSQL, sqlWords.MatchString(text)
	}
	return "", false
}

// handlerCapability finds the capability whose handler a path's source step belongs to
func handlerCapability(g *graph.Graph, file string, line int) *graph.Capability {
	for i := range g.Capabilities {
		c := &g.Capabilities[i]
		if c.Handler == "" {
			continue
		}
		if s := g.Symbols[c.Handler]; s != nil && s.File == file && s.Line == line {
			return c
		}
	}
	return nil
}

// asksForConfirmation reports whether a handler can reach a call that asks the user first
func asksForConfirmation(g *graph.Graph, handler graph.SymbolID) bool {
	reached, _ := g.Reachable(handler)
	reached[handler] = true
	for id := range reached {
		for _, call := range g.CallsFrom(id) {
			if confirmCall.MatchString(parser.LastSegment(call.CalleeText)) {
				return true
			}
		}
	}
	return false
}

// asCapability turns an MCP-input finding into a dangerous-capability finding when the tool
// declares what the sink does. When the description also promises a boundary, it leaves the
// finding an injection but sends it to review. It returns false and leaves f alone otherwise.
func asCapability(g *graph.Graph, f *model.Finding) bool {
	path := f.Evidence[0].Path
	for _, st := range path {
		// The caller's value was spliced into a larger query or command: that is an injection
		// even in a tool whose purpose is to run queries
		if st.Detail == compositionDetail {
			return false
		}
	}
	src := path[0]
	c := handlerCapability(g, src.File, src.Line)
	if c == nil || !c.DescriptionResolved && !c.NameResolved {
		return false
	}
	capName, declared := capabilityOf(f.Category, c.Name, c.Description)
	if !declared {
		return false
	}
	if w := promisesScope.FindString(c.Description); w != "" {
		// "Delete a file under the workspace" with nothing in the code that keeps the path there
		// is a broken promise - a vulnerability - not a tool doing what it says. But the word
		// alone does not tell a promise from prose ("only locals persist" in a code tool), so the
		// finding stays an injection and goes to review rather than to potential.
		f.Triage = model.TriageNeedsReview
		f.TriageReason = fmt.Sprintf("the tool's name or description says it %s, and the description also uses %q; if that word promises a boundary, nothing the scanner found on the path enforces it and this is a vulnerability, otherwise the argument reaching the sink is the tool's purpose. Words alone do not decide which", capabilityPhrase[capName], w)
		return true
	}
	sink := f.Evidence[0].Path[len(f.Evidence[0].Path)-1]
	restriction := "no user confirmation was found on the handler's path"
	if asksForConfirmation(g, c.Handler) {
		f.Severity = f.Severity.OneStepDown()
		restriction = "the handler can ask the user to confirm (an elicitation call is reachable), so severity is one step lower"
	}
	limit := ""
	switch capName {
	case capFile:
		limit = "; no root-directory check stops the path (one would have cleared this finding)"
	case capNetwork:
		limit = "; host allowlists are not recognized yet, so one may exist"
	}
	toolName := c.Name
	if !c.NameResolved || toolName == "" {
		toolName = fmt.Sprintf("%s:%d", src.File, src.Line)
	}
	// The rule stays: the argument does reach the sink. The kind and the title say what it means.
	f.FindingKind = model.FindingDangerousCapability
	f.Capability = capName
	f.Title = fmt.Sprintf("%s %q %s (%s)", c.Kind, toolName, capabilityPhrase[capName], titleCallee(sink.Symbol))
	f.Triage = model.TriagePotential
	f.TriageReason = fmt.Sprintf("the tool's own name or description says it does this, so the argument reaching %s is its purpose, not an injection; an agent steered by prompt injection can still use it that way. %s%s",
		titleCallee(sink.Symbol), restriction, limit)
	return true
}
