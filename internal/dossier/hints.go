package dossier

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Hint is a place where static analysis saw something it could not decide, written so a later
// reviewer can come back to it with the right question. docs/review-hints.md describes each code.
type Hint struct {
	Code       string   `json:"code"`
	File       string   `json:"file,omitempty"`
	Line       int      `json:"line,omitempty"`
	Capability string   `json:"capability,omitempty"`
	Observed   string   `json:"observed"`
	Undecided  string   `json:"undecided"`
	Question   string   `json:"question"`
	HowToCheck string   `json:"how_to_check"`
	Strength   string   `json:"strength"`
	Related    []string `json:"related,omitempty"`
}

const (
	strengthSuspicion = "suspicion"
	strengthLead      = "lead"
)

var (
	unsupportedFiles = regexp.MustCompile(`(\d+) source file\(s\) with extension "([^"]+)" were not analyzed`)
	wildcardParam    = regexp.MustCompile(`\{[+#]?[A-Za-z0-9_.,]+\*\}|\{[+#][A-Za-z0-9_.,]+\}`)
	validatorName    = regexp.MustCompile(`(?i)^_*(validate|sanitize|sanitise|check|ensure|verify|assert|safe|clean|normalize)[a-z0-9_]*$`)
)

func hints(d *Dossier, g *graph.Graph, cov model.Coverage) []Hint {
	var out []Hint
	add := func(h Hint) { out = append(out, h) }

	// Registration and coverage
	if len(d.Capabilities) == 0 && len(d.MCPImports) > 0 {
		add(Hint{Code: "registration_not_recognized", Strength: strengthLead,
			Observed:   fmt.Sprintf("the tree imports an MCP SDK (%s) but no tool, prompt or resource registration was found", strings.Join(first(d.MCPImports, 3), ", ")),
			Undecided:  "which tools the server exposes; none of them was analyzed",
			Question:   "How does this server register its tools, and what do they do?",
			HowToCheck: "find the registration code; list tools against a running instance"})
	}
	if onlyJSONRPC := allJSONRPC(d.Capabilities); len(d.Capabilities) == 0 || onlyJSONRPC {
		if files := protocolMethodFiles(g); len(files) > 0 {
			observed := fmt.Sprintf("no registration was found, but %d source file(s) name MCP methods such as \"tools/call\": %s", len(files), strings.Join(first(files, 4), ", "))
			undecided := "the tools a server implementing JSON-RPC by hand exposes, and what they do; none of them was analyzed"
			if onlyJSONRPC {
				observed = fmt.Sprintf("the server dispatches JSON-RPC by hand: its tools/call branch was analyzed as one handler for every tool; %d source file(s) name MCP methods: %s", len(files), strings.Join(first(files, 4), ", "))
				undecided = "the names and purposes of the tools it serves, so whether an argument reaching a sink is a tool's purpose or an injection"
			}
			add(Hint{Code: "hand_rolled_protocol", Strength: strengthLead, File: files[0],
				Observed:   observed,
				Undecided:  undecided,
				Question:   "Which tools does this hand-written dispatcher serve, and what do they reach?",
				HowToCheck: "read the tools/call dispatch and follow each tool name to its code; list tools against a running instance"})
		}
	}
	for _, l := range cov.LimitsHit {
		if m := unsupportedFiles.FindStringSubmatch(l); m != nil {
			add(Hint{Code: "unsupported_language_files", Strength: strengthSuspicion,
				Observed:   fmt.Sprintf("%s file(s) with extension %s were not parsed", m[1], m[2]),
				Undecided:  "whether any MCP handler or the code it calls lives in them",
				Question:   fmt.Sprintf("Does server code live in the %s files?", m[2]),
				HowToCheck: "read those files, starting with ones that import an MCP SDK"})
		}
	}
	byReason := map[string][]graph.SkippedRegistration{}
	for _, s := range g.SkippedRegistrations {
		byReason[s.Reason] = append(byReason[s.Reason], s)
	}
	for _, reason := range sortedKeys(byReason) {
		ss := byReason[reason]
		var at []string
		for _, s := range first2(ss, 3) {
			at = append(at, fmt.Sprintf("%s at %s:%d", s.CalleeText, s.File, s.Line))
		}
		add(Hint{Code: "registration_skipped", Strength: strengthSuspicion, File: ss[0].File, Line: ss[0].Line,
			Observed:   fmt.Sprintf("%d call(s) named like a registration were not counted (%s), such as %s", len(ss), reason, strings.Join(at, "; ")),
			Undecided:  "the reason is read from the call's arguments and receiver, not from what the receiver object is",
			Question:   "Is any of these calls a real MCP registration?",
			HowToCheck: "read the receiver's type at each call; list capabilities against a running instance"})
	}
	var minified []string
	for path := range g.Files {
		if strings.Contains(path, ".min.") || strings.HasSuffix(path, ".bundle.js") {
			minified = append(minified, path)
		}
	}
	if len(minified) > 0 {
		sort.Strings(minified)
		add(Hint{Code: "minified_code", Strength: strengthSuspicion,
			Observed:   fmt.Sprintf("%d minified or bundled file(s) were parsed, such as %s", len(minified), minified[0]),
			Undecided:  "whether paths through them are real; minified code is hard to trace and to read",
			Question:   "Is the bundled code part of the server, and is any finding in it real?",
			HowToCheck: "map the bundle to its source; read findings in it against that source"})
	}

	// Registrations of one kind in one file share a cause (one loop, one helper, one test file),
	// so they are one hint with a count rather than one per registration
	type fileKey struct{ code, file string }
	grouped := map[fileKey][]Capability{}
	var groupOrder []fileKey
	perFile := func(code string, c Capability) {
		k := fileKey{code, c.File}
		if _, ok := grouped[k]; !ok {
			groupOrder = append(groupOrder, k)
		}
		grouped[k] = append(grouped[k], c)
	}
	names := map[string][]Capability{}
	anyRisky := false
	for _, c := range d.Capabilities {
		names[c.Kind+" "+c.Name] = append(names[c.Kind+" "+c.Name], c)
		where := func(h Hint) Hint { h.File, h.Line, h.Capability = c.File, c.Line, c.Name; return h }

		if !c.NameResolved || c.Form == "loop" || c.Form == "request_handler" {
			perFile("dynamic_registration", c)
		}
		if c.NameResolved && c.Handler == nil && c.Form != "request_handler" && c.Form != "loop" {
			perFile("handler_not_found", c)
		}
		if tmpl := c.URI; c.Kind == string(graph.CapabilityResource) && strings.Contains(tmpl, "{") {
			// A template parameter is caller input whatever the handler does with it; a handler seen
			// reaching files or the network makes it a lead, otherwise it stays a suspicion
			strength, observed := strengthSuspicion, fmt.Sprintf("resource template %s takes a parameter from the client", tmpl)
			if b := c.Behavior; b != nil && (b.Filesystem || b.Network) {
				strength, observed = strengthLead, fmt.Sprintf("resource template %s reaches %s", tmpl, accessKinds(b.Filesystem, b.Network))
			} else if b != nil && b.ReachesUnresolved {
				observed += "; the handler calls code the scanner could not follow"
			}
			if wildcardParam.MatchString(tmpl) {
				// {path*} and {+path} expand across '/' in RFC 6570, and several SDKs match them that way
				strength = strengthLead
				observed += "; a wildcard parameter ({x*} or {+x}) can span '/'"
			}
			add(where(Hint{Code: "resource_template_parameter", Strength: strength,
				Observed:   observed,
				Undecided:  "whether the SDK lets a template parameter carry '/', '..' or a decoded %2F",
				Question:   "Can a client reach files or hosts outside the intended set through this URI?",
				HowToCheck: "read the SDK's URI template matcher; try '..', '%2F' and '%252F' against a running instance"}))
		}
		if desc := c.Description; nonEnglish(desc) {
			add(where(Hint{Code: "non_english_description", Strength: strengthSuspicion,
				Observed:   "the description is mostly not in English",
				Undecided:  "what it promises, denies or instructs; the behavioral and prompt-defense vocabularies are English",
				Question:   "Does the description match what the handler does, and does it instruct the model?",
				HowToCheck: "read or translate it and compare with the handler's behavior"}))
		}
		b := c.Behavior
		if b == nil {
			continue
		}
		if b.Process || b.Filesystem {
			anyRisky = true
			add(where(Hint{Code: "dangerous_capability_restrictions", Strength: strengthSuspicion,
				Observed:   fmt.Sprintf("the handler can reach %s", accessKinds(b.Filesystem, false, b.Process)),
				Undecided:  "what limits it: path or command allowlists in configuration and client-side confirmation are not recognized",
				Question:   "What stops an agent steered by prompt injection from misusing this?",
				HowToCheck: "read the handler and the server configuration for an allowlist, a root directory or an approval step"}))
		}
		if b.Network {
			add(where(Hint{Code: "untrusted_content_to_model", Strength: strengthSuspicion,
				Observed:   "the handler makes network calls and may return what it fetched to the model",
				Undecided:  "whether an outsider can write that content (a page, an issue, an email)",
				Question:   "Can a third party plant instructions in what this tool returns?",
				HowToCheck: "read where the returned content comes from"}))
		}
		if b.Credentials && b.Network {
			add(where(Hint{Code: "credentials_and_network", Strength: strengthLead,
				Observed:   fmt.Sprintf("the handler reads credentials (%s) and makes network calls", strings.Join(first(append(b.EnvVars, b.SensitivePaths...), 4), ", ")),
				Undecided:  "where the credentials are sent",
				Question:   "Are the credentials sent only to the service they belong to?",
				HowToCheck: "follow each credential to the requests that carry it"}))
		}
		if hosts := hostsOf(b.URLs); len(hosts) > 0 {
			add(where(Hint{Code: "outbound_hosts", Strength: strengthSuspicion,
				Observed:   "the handler can contact " + strings.Join(first(hosts, 8), ", "),
				Undecided:  "whether every host is the vendor's own service",
				Question:   "Is any of these hosts telemetry or a third party the tool does not mention?",
				HowToCheck: "compare the hosts with the tool's description and the project's documentation"}))
		}
		if c.Handler != nil {
			if v := reachedValidators(g, c); len(v) > 0 {
				add(where(Hint{Code: "project_validator", Strength: strengthLead,
					Observed:   "the handler can reach the project's own validation functions: " + strings.Join(first(v, 5), ", "),
					Undecided:  "whether they reject every dangerous input; the scanner does not verify them",
					Question:   "Do these validators reject '..', absolute paths, symlinks, quotes and unexpected schemes?",
					HowToCheck: "read each validator; test it with those inputs"}))
			}
		}
	}
	for _, k := range groupOrder {
		cs := grouped[k]
		var ex []string
		for _, c := range cs[:min(len(cs), 4)] {
			if k.code == "handler_not_found" {
				ex = append(ex, fmt.Sprintf("%s %s at line %d%s", c.Kind, c.Name, c.Line, handlerText(c.HandlerText)))
			} else {
				ex = append(ex, fmt.Sprintf("%s in %s form at line %d", c.Kind, formName(c.Form), c.Line))
			}
		}
		h := Hint{Code: k.code, File: k.file, Line: cs[0].Line, Capability: cs[0].Name}
		if len(cs) > 1 {
			h.Capability = ""
		}
		switch k.code {
		case "dynamic_registration":
			h.Strength = strengthLead
			h.Observed = fmt.Sprintf("%d registration(s) whose name or contents are computed at run time: %s", len(cs), strings.Join(ex, "; "))
			h.Undecided = "which capabilities these register and what they do"
			h.Question = "What does this register at run time, and do those capabilities do anything dangerous?"
			h.HowToCheck = "read the data or the upstream server the list comes from; list capabilities against a running instance"
		case "handler_not_found":
			h.Strength = strengthSuspicion
			h.Observed = fmt.Sprintf("%d registration(s) whose handler was not found in the tree: %s", len(cs), strings.Join(ex, "; "))
			h.Undecided = "what these capabilities do, or whether the calls are registrations at all; nothing behind them was analyzed"
			h.Question = "Are these real registrations, and what do their handlers do?"
			h.HowToCheck = "read the call and the receiver's type; follow the handler into the code that defines it"
		}
		add(h)
	}
	if anyRisky {
		add(Hint{Code: "annotations_not_visible", Strength: strengthSuspicion,
			Observed:   "tools reach the filesystem or run processes, and this is a source scan",
			Undecided:  "the annotations (readOnlyHint, destructiveHint) and input schemas a client sees",
			Question:   "Does each tool that writes, deletes or runs commands declare itself destructive?",
			HowToCheck: "list tools against a running instance and read their annotations"})
	}
	for key, cs := range names {
		if len(cs) > 1 && cs[0].NameResolved {
			add(Hint{Code: "duplicate_capability_name", Strength: strengthSuspicion, File: cs[0].File, Line: cs[0].Line, Capability: cs[0].Name,
				Observed:   fmt.Sprintf("%d registrations of %s (%s:%d and %s:%d)", len(cs), key, cs[0].File, cs[0].Line, cs[1].File, cs[1].Line),
				Undecided:  "which one a client sees, or whether one impersonates another",
				Question:   "Which registration wins, and is that intended?",
				HowToCheck: "list capabilities against a running instance"})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func formName(f string) string {
	if f == "" {
		return "an unrecognized"
	}
	return f
}

func accessKinds(fs, net bool, proc ...bool) string {
	var k []string
	if fs {
		k = append(k, "the filesystem")
	}
	if net {
		k = append(k, "the network")
	}
	if len(proc) > 0 && proc[0] {
		k = append(k, "process execution")
	}
	return strings.Join(k, " and ")
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func hostsOf(urls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		if p, err := url.Parse(u); err == nil && p.Host != "" && !seen[p.Host] {
			seen[p.Host] = true
			out = append(out, p.Host)
		}
	}
	sort.Strings(out)
	return out
}

// nonEnglish reports whether most letters of a description are outside the Latin script
func nonEnglish(s string) bool {
	letters, other := 0, 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			letters++
			if !unicode.Is(unicode.Latin, r) {
				other++
			}
		}
	}
	return letters >= 12 && other*10 >= letters*3
}

func reachedValidators(g *graph.Graph, c Capability) []string {
	id := graph.SymbolID(c.Handler.Symbol)
	reached, _ := g.Reachable(id)
	seen := map[string]bool{}
	var out []string
	for sid := range reached {
		if s := g.Symbols[sid]; s != nil && validatorName.MatchString(s.Name) && !seen[s.Name] {
			seen[s.Name] = true
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}

func first2(s []graph.SkippedRegistration, n int) []graph.SkippedRegistration {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func handlerText(t string) string {
	if t == "" {
		return " (no handler argument)"
	}
	if len(t) > 80 {
		t = t[:80] + "..."
	}
	return fmt.Sprintf(" (handler argument %q)", t)
}

// protocolMethodFiles lists non-test source files that spell the MCP tools/call or tools/list
// method as a string - the sign of a JSON-RPC dispatcher written without an SDK
func protocolMethodFiles(g *graph.Graph) []string {
	var out []string
	for p := range g.Files {
		low := strings.ToLower(p)
		if strings.Contains(low, "test") || strings.Contains(low, "/examples/") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(g.Root, p))
		if err != nil || len(b) > 2<<20 {
			continue
		}
		if bytes.Contains(b, []byte(`"tools/call"`)) || bytes.Contains(b, []byte(`'tools/call'`)) || bytes.Contains(b, []byte(`"tools/list"`)) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// allJSONRPC reports whether every capability came from a hand-written JSON-RPC dispatcher
func allJSONRPC(cs []Capability) bool {
	if len(cs) == 0 {
		return false
	}
	for _, c := range cs {
		if c.Form != "jsonrpc" {
			return false
		}
	}
	return true
}
