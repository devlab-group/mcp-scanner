package behavioral

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/targetfs"
)

// Egress says where the network calls a handler reaches are addressed, and where the credentials
// it reads go. It reads names along the handler's calls (walkFlow), not a traced flow: an address
// is the caller's when the caller's data starts it, the server's own when a literal host, a
// constant or a setting does, and unsettled when the names do not say.
type Egress struct {
	// FixedHosts are literal hosts in the code: in a call's address, or in the constant it starts with
	FixedHosts []string `json:"fixed_hosts,omitempty"`
	// Configured are the constants and settings that start an address the code does not spell out
	Configured []string `json:"configured_addresses,omitempty"`
	// CallerAddressed are the calls whose address the caller's data starts
	CallerAddressed []string `json:"caller_addressed,omitempty"`
	// Unsettled counts the network calls whose address the names do not settle
	Unsettled int `json:"unsettled,omitempty"`
	// CredentialNames are the environment variables the handler reads that are named like a credential
	CredentialNames []string `json:"credential_names,omitempty"`
	// CredentialCalls are the network calls that carry a credential, and where each is addressed
	CredentialCalls []CredentialCall `json:"credential_calls,omitempty"`
	// CredentialInResult: the handler's own result carries a credential
	CredentialInResult bool `json:"credential_in_result,omitempty"`
}

// CredentialCall is one network call that carries a credential. To is the host, the name of the
// constant or setting that starts the address, or what the address is when neither is known.
type CredentialCall struct {
	Call string `json:"call"`
	// Address is fixed, configured, caller or unsettled
	Address string `json:"address"`
	To      string `json:"to,omitempty"`
}

const maxEgress = 50

var (
	// a constant or a setting by its name: API_BASE, self.base_url, config.host, apiEndpoint
	settingName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$|\.(?i:\w*(?:base|host|origin|server|endpoint|url|uri|api))$|(?i:base_?url|base_?uri|api_?(?:base|url|host|endpoint)|endpoint)`)
	egressHost  = regexp.MustCompile(`(?i)(?:https?|wss?)://([A-Za-z0-9.-]+(?::\d+)?)`)
	egressName  = regexp.MustCompile(`^[A-Za-z_$][\w$]*`)
)

// EgressOf reads the network calls handler reaches and the credentials they carry; nil when
// there are none. envVars are the environment variables the handler reads.
func EgressOf(g *graph.Graph, handler graph.SymbolID, envVars []string) *Egress {
	reached, _ := g.Reachable(handler)
	reached[handler] = true
	fl := walkFlow(g, handler, reached)
	e := &Egress{CredentialInResult: fl.returnsCred}
	if len(fl.net) == 0 && !fl.returnsCred {
		return nil
	}
	fixed, conf, caller := map[string]bool{}, map[string]bool{}, map[string]bool{}
	calls := map[string]CredentialCall{}
	for _, nc := range fl.net {
		if !requestCall(nc.call) {
			continue
		}
		addr := addressOf(nc)
		kind := addrStart(addr, fl.effectiveCaller(nc.sym))
		where := fmt.Sprintf("%s:%d %s", nc.call.File, nc.call.Line, strings.TrimSpace(nc.call.CalleeText))
		address, to := "unsettled", ""
		switch kind {
		case "caller":
			address = "caller"
			caller[where] = true
		case "own":
			if h := fixedHost(g, nc.call.File, addr); h != "" {
				address, to = "fixed", h
				fixed[h] = true
			} else if name := configuredName(addr); settingName.MatchString(name) {
				address, to = "configured", name
				conf[name] = true
			} else {
				// a local name or a loop variable: the names do not say where it comes from
				e.Unsettled++
			}
		default:
			e.Unsettled++
		}
		var args []string
		for _, a := range nc.call.Args {
			args = append(args, a.Text)
		}
		if carriesCredential(strings.Join(args, ", "), fl.cred[nc.sym]) {
			calls[where] = CredentialCall{Call: where, Address: address, To: to}
		}
	}
	e.FixedHosts, e.Configured, e.CallerAddressed = sortedCapped(fixed), sortedCapped(conf), sortedCapped(caller)
	for _, v := range envVars {
		if credentialLikeName(v) {
			e.CredentialNames = append(e.CredentialNames, v)
		}
	}
	keys := make([]string, 0, len(calls))
	for k := range calls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys[:min(len(keys), maxEgress)] {
		e.CredentialCalls = append(e.CredentialCalls, calls[k])
	}
	if len(fixed)+len(conf)+len(caller)+len(calls)+len(e.CredentialNames)+e.Unsettled == 0 && !e.CredentialInResult {
		return nil
	}
	return e
}

// requestCall reports whether a call matched as network makes a request. The catalogue matches
// names by substring, so fetchDocumentation and fetched.get count as network: a project function
// is followed through the graph, and only fetch itself is one.
func requestCall(c graph.Call) bool {
	if c.Callee != "" {
		return false
	}
	if !strings.Contains(c.CalleeText, "fetch") {
		return true
	}
	last := c.CalleeText[strings.LastIndexAny(c.CalleeText, ".:")+1:]
	return last == "fetch"
}

// fixedHost is the literal host an own address starts with: in the address itself, or in the
// constant of the same file that starts it
func fixedHost(g *graph.Graph, file, addr string) string {
	if m := egressHost.FindStringSubmatch(addr); m != nil {
		return m[1]
	}
	name := configuredName(addr)
	if name == "" || strings.ContainsAny(name, ".") {
		return ""
	}
	b, err := targetfs.ReadGraphFile(g, file)
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:(?:const|let|var|final|static)\s+)*` + regexp.QuoteMeta(name) + `\s*(?::[^=\n]+)?=\s*["'` + "`" + `](?:https?|wss?)://([A-Za-z0-9.-]+(?::\d+)?)`)
	if m := re.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// configuredName is the identifier an own address starts with: API + "/x" is API, settings.url is
// settings.url, f"{BASE}/x" is BASE
func configuredName(addr string) string {
	a := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(addr), "await "))
	a = strings.TrimPrefix(strings.TrimPrefix(a, "f\""), "f'")
	a = strings.TrimLeft(a, "`\"'")
	a = strings.TrimPrefix(strings.TrimPrefix(a, "$"), "{")
	if m := leadIdent.FindString(a); m != "" {
		return m
	}
	return egressName.FindString(a)
}

func sortedCapped(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out[:min(len(out), maxEgress)]
}
