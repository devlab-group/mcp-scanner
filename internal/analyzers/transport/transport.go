// Package transport reads, from source alone, how an MCP server is served over the network: the
// address its HTTP, SSE or Streamable HTTP endpoint listens on, whether it lets web pages of any
// origin call it (CORS), and whether a request has to carry credentials. An endpoint without
// authentication is an exposure as large as what the server's tools can do, so each finding is
// weighed against what the tools reach: running programs, changing files or a database, the
// credentials the server holds. Nothing is executed and no network request is made.
package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

const name = "transport"

// Rule IDs
const (
	RuleNetworkExposed   = "transport.network_exposed"
	RuleBrowserReachable = "transport.browser_reachable"
)

func init() { analyzer.Register(&Analyzer{}) }

// Analyzer implements analyzer.Analyzer for source and package targets
type Analyzer struct{}

var (
	_ analyzer.Analyzer   = (*Analyzer)(nil)
	_ analyzer.Applicable = (*Analyzer)(nil)
	_ analyzer.Describer  = (*Analyzer)(nil)
)

func (*Analyzer) Name() string { return name }

func (*Analyzer) AppliesTo(kind model.TargetKind) bool {
	return kind == model.TargetSource || kind == model.TargetPackage
}

func (*Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name:    name,
		Purpose: "Reads how an MCP server is served over HTTP, SSE or Streamable HTTP - the listen address, CORS headers and any authentication on the route - and weighs an unauthenticated endpoint against what the server's tools can do.",
		Threats: []string{
			"an MCP endpoint that listens on every network interface (0.0.0.0, a Go \":port\", Node's listen(port)) with no authentication, so any device on the same network can call tools that run programs, change files or act with the user's credentials",
			"an MCP endpoint that allows every web origin (CORS *), so any page the user opens can call the tools on localhost and read the results",
			"an authentication check that is only installed when an API key variable is set, leaving the default configuration open",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceStatic},
		Active:   false,
		Limitations: []string{
			"recognises the MCP SDK transports (TypeScript StreamableHTTPServerTransport/SSEServerTransport, Python FastMCP run/sse_app/http_app with uvicorn, Go mcp-go and go-sdk HTTP servers) and hand-written JSON-RPC over HTTP that dispatches tools/call; other frameworks and transports are not read",
			"the listen address is read when it is a literal, a same-file constant, or an environment variable with a literal default; a value computed elsewhere leaves the endpoint unplaced and unreported",
			"authentication is recognised by reads of the Authorization or an API-key request header and by known SDK and framework middlewares, in the server file, its directory and the local modules it imports; a check by any other means is not seen, and one check there counts for all of the server's routes",
			"what the tools can do is the sink catalogue's view of everything their handlers statically reach inside the server's package; a capability the catalogue does not know (a cloud SDK call, desktop automation, a Docker client in Go) only counts through the credentials the server reads, and cleanup of the server's own temporary files or a public read-only service can still be weighed too high",
			"DNS rebinding (a localhost endpoint that checks neither Host nor Origin) is not reported yet",
		},
	}
}

// analysis is one run's shared state
type analysis struct {
	g       *graph.Graph
	r       *reader
	sources map[string]string
	facts   map[string]*facts
	byFile  map[string][]*graph.Symbol
}

func (a *analysis) source(path string) string {
	if s, ok := a.sources[path]; ok {
		return s
	}
	gf := a.g.Files[path]
	s := ""
	if gf != nil {
		if b, err := a.r.read(path, gf); err == nil {
			s = string(b)
		}
	}
	a.sources[path] = s
	return s
}

// scan collects facts file by file
type scan struct{}

func (*Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	started := time.Now().UTC()
	var acRoot string
	if ac != nil {
		acRoot = ac.Root
	}
	root, err := source.ResolveRoot(target.Path, acRoot)
	if err != nil {
		return model.Errorf(name, "config", "%v", err)
	}
	if root == "" {
		return model.Errorf(name, "config", "no source path to scan")
	}
	g, cov, walkCoverageMissing, err := source.LoadGraph(ctx, ac, root)
	if err != nil {
		return model.Errorf(name, "internal", "building source graph: %v", err)
	}

	a := &analysis{g: g, r: newReader(g), sources: map[string]string{}, facts: map[string]*facts{}}
	defer a.r.close()
	var warnings []string
	unreadable, timedOut := a.collect(ctx)
	if unreadable > 0 {
		warnings = append(warnings, fmt.Sprintf("%d file(s) could not be read again for the transport check", unreadable))
	}
	if timedOut > 0 {
		warnings = append(warnings, fmt.Sprintf("%d file(s) did not parse within the time limit for the transport check", timedOut))
	}

	findings := a.findings()
	model.SortFindings(findings)

	cov.CapabilitiesDiscovered = len(g.Capabilities)
	cov.CapabilitiesAnalyzed, cov.CapabilitiesSkipped = 0, 0
	for _, c := range g.Capabilities {
		if c.Handler == "" {
			cov.AddSkipReason("capability handler is not statically known")
			cov.CapabilitiesSkipped++
			continue
		}
		cov.CapabilitiesAnalyzed++
	}

	status := model.AnalyzerCompleted
	if ctx.Err() != nil {
		status = model.AnalyzerPartial
	}
	if walkCoverageMissing {
		status = model.AnalyzerPartial
		warnings = append(warnings, "the published source graph carried no walk coverage; file-level coverage cannot be reported for this scan")
	}
	var arts *analyzer.Artifacts
	if ac != nil {
		arts = ac.Artifacts
	}
	cov = source.FoldWalkCoverage(arts, cov)

	res := model.AnalyzerResult{
		Analyzer:  name,
		Status:    status,
		Required:  true,
		Coverage:  cov,
		Findings:  findings,
		Warnings:  warnings,
		StartedAt: started,
	}
	res.FinishedAt = time.Now().UTC()
	res.Duration = res.FinishedAt.Sub(started)
	return res
}

// collect re-parses every file that mentions a transport, a listen call, CORS or authentication
func (a *analysis) collect(ctx context.Context) (unreadable, timedOut int) {
	paths := make([]string, 0, len(a.g.Files))
	for p := range a.g.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	s := &scan{}
	for _, p := range paths {
		if ctx.Err() != nil {
			return
		}
		gf := a.g.Files[p]
		switch language.ID(gf.Language) {
		case language.JavaScript, language.TypeScript, language.Python, language.Go:
		default:
			continue
		}
		src := a.source(p)
		if src == "" || !worthParsing([]byte(src)) {
			continue
		}
		f, tree, err := a.r.parse(ctx, p, gf, []byte(src))
		if err != nil {
			if errors.Is(err, parser.ErrParseTimeout) {
				timedOut++
			} else {
				unreadable++
			}
			continue
		}
		if f == nil {
			continue
		}
		fx := &facts{}
		s.visit(f, fx)
		tree.Close()
		// a dictionary or headers object fixes CORS only when the file also sends the header list
		for i := range fx.cors {
			if fx.allowHeaders {
				fx.cors[i].Preflight = true
			}
		}
		a.facts[p] = fx
	}
	return
}

// testPath matches files that by their path are tests, as the taint analyzer's rule does
var testPath = regexp.MustCompile(`(^|/)(tests?|__tests__|spec|specs)/|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(go|py)$|(^|/)test_[^/]*\.py$`)

// examplePath matches example and demo code shipped beside a server
var examplePath = regexp.MustCompile(`(^|/)(examples?|demos?|samples?)/`)

// manifests mark the root of one package, the scope of one server in a monorepo
var manifests = []string{"package.json", "pyproject.toml", "setup.py", "setup.cfg", "go.mod", "requirements.txt"}

// scopeOf is the directory of the package that holds file: the nearest directory above it with a
// package manifest, or the scan root
func (a *analysis) scopeOf(file string) string {
	dir := path.Dir(file)
	for dir != "." && dir != "/" && dir != "" {
		for _, m := range manifests {
			if a.r.exists(path.Join(dir, m)) {
				return dir
			}
		}
		dir = path.Dir(dir)
	}
	return ""
}

func (r *reader) exists(p string) bool {
	var err error
	if r.root != nil {
		_, err = r.root.Stat(p)
	} else {
		_, err = os.Stat(p)
	}
	return err == nil
}

// endpointGroup is one served MCP endpoint and everything read about it
type endpointGroup struct {
	scope    string
	file     string
	endpoint site
	listens  []listenSite
	cors     []corsSite
	auth     []authSite
	jsonrpc  bool
	dispatch string
	built    bool
}

// groups assembles one group per file that serves MCP over HTTP
func (a *analysis) groups() []endpointGroup {
	var paths []string
	for p := range a.facts {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var out []endpointGroup
	for _, p := range paths {
		fx := a.facts[p]
		if testPath.MatchString(p) {
			continue
		}
		ep, dispatch, ok := a.endpointOf(p, fx)
		if !ok {
			continue
		}
		grp := endpointGroup{scope: a.scopeOf(p), file: p, endpoint: ep, jsonrpc: dispatch != "", dispatch: dispatch}
		grp.listens = append(grp.listens, fx.listens...)
		if len(fx.pyRunsWithoutHost) > 0 {
			if fx.pyHostSetting != nil {
				grp.listens = append(grp.listens, *fx.pyHostSetting)
			} else {
				for _, r := range fx.pyRunsWithoutHost {
					grp.listens = append(grp.listens, listenSite{site{File: r.File, Line: r.Line, Detail: r.Detail + " with no host: FastMCP listens on 127.0.0.1 by default"}, bindLocal})
				}
			}
		}
		if len(grp.listens) == 0 {
			// the app is created here and listened on elsewhere: the listen calls of server files
			// in the same directory
			for _, q := range paths {
				if q != p && path.Dir(q) == path.Dir(p) && len(a.facts[q].servers) > 0 {
					grp.listens = append(grp.listens, a.facts[q].listens...)
				}
			}
		}
		grp.cors = append(grp.cors, fx.cors...)
		grp.built = buildOutput.MatchString(p)
		// authentication counts where it can guard this endpoint: the server file, its directory,
		// and the local modules it imports (two levels), not another server of the same repository
		for _, q := range a.guardFiles(p, dispatch) {
			if fq, ok := a.facts[q]; ok && !testPath.MatchString(q) {
				grp.auth = append(grp.auth, fq.auth...)
			}
		}
		out = append(out, grp)
	}
	// a compiled copy (dist/, build/) of a server whose source is also here is the same endpoint
	sources := map[string]bool{}
	for _, g := range out {
		if !g.built {
			sources[g.scope] = true
		}
	}
	kept := out[:0]
	for _, g := range out {
		if !g.built || !sources[g.scope] {
			kept = append(kept, g)
		}
	}
	return kept
}

// buildOutput matches compiled output directories
var buildOutput = regexp.MustCompile(`(^|/)(dist|build|out)/`)

// endpointOf is the site that shows a file serves MCP over HTTP: an SDK transport, or a server
// that dispatches tools/call itself
func (a *analysis) endpointOf(p string, fx *facts) (site, string, bool) {
	if len(fx.endpoints) > 0 {
		return fx.endpoints[0], "", true
	}
	if fx.jsonrpc && len(fx.servers) > 0 {
		s := fx.servers[0]
		s.Detail = "an HTTP server in a file that dispatches MCP tools/call requests itself (" + s.Detail + ")"
		return s, p, true
	}
	if len(fx.servers) > 0 && (len(fx.listens) > 0 || len(fx.cors) > 0) {
		if mod := a.dispatchModule(p); mod != "" {
			s := fx.servers[0]
			s.Detail = "an HTTP server that hands requests to " + mod + ", which dispatches MCP tools/call itself (" + s.Detail + ")"
			return s, mod, true
		}
	}
	return site{}, "", false
}

// guardFiles are the files whose authentication checks can guard the endpoint in p
func (a *analysis) guardFiles(p, dispatch string) []string {
	out := map[string]bool{p: true}
	if dispatch != "" {
		out[dispatch] = true
	}
	for q := range a.g.Files {
		if path.Dir(q) == path.Dir(p) {
			out[q] = true
		}
	}
	frontier := []string{p}
	if dispatch != "" {
		frontier = append(frontier, dispatch)
	}
	for level := 0; level < 2; level++ {
		var next []string
		for _, f := range frontier {
			for _, q := range a.localImports(f) {
				if !out[q] {
					out[q] = true
					next = append(next, q)
				}
			}
		}
		frontier = next
	}
	list := make([]string, 0, len(out))
	for q := range out {
		list = append(list, q)
	}
	sort.Strings(list)
	return list
}

// localImports resolves a file's imports of other files in the tree: relative JavaScript and
// TypeScript imports, and Python imports of modules that exist in the tree
func (a *analysis) localImports(p string) []string {
	gf := a.g.Files[p]
	if gf == nil {
		return nil
	}
	dir := path.Dir(p)
	var out []string
	for _, imp := range gf.Imports {
		var cands []string
		switch language.ID(gf.Language) {
		case language.JavaScript, language.TypeScript:
			if !strings.HasPrefix(imp.Path, "./") && !strings.HasPrefix(imp.Path, "../") {
				continue
			}
			base := path.Join(dir, imp.Path)
			stem := strings.TrimSuffix(strings.TrimSuffix(base, ".js"), ".mjs")
			cands = []string{base, base + ".js", base + ".mjs", base + ".cjs", base + ".ts", stem + ".ts", stem + ".tsx", base + "/index.js", base + "/index.ts"}
		case language.Python:
			mod := imp.Path
			up := dir
			for strings.HasPrefix(mod, ".") {
				mod = mod[1:]
				if strings.HasPrefix(mod, ".") {
					up = path.Dir(up)
				}
			}
			rel := strings.ReplaceAll(mod, ".", "/")
			cands = []string{path.Join(up, rel+".py"), path.Join(up, rel, "__init__.py"), rel + ".py", path.Join(rel, "__init__.py")}
		default:
			continue
		}
		for _, c := range cands {
			if _, ok := a.g.Files[c]; ok {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// dispatchModule is a local module the file imports that dispatches MCP JSON-RPC itself
func (a *analysis) dispatchModule(p string) string {
	gf := a.g.Files[p]
	if gf == nil {
		return ""
	}
	dir := path.Dir(p)
	for _, imp := range gf.Imports {
		if !strings.HasPrefix(imp.Path, "./") && !strings.HasPrefix(imp.Path, "../") {
			continue
		}
		base := path.Join(dir, imp.Path)
		for _, cand := range []string{base, base + ".js", base + ".mjs", base + ".cjs", base + ".ts", strings.TrimSuffix(base, ".js") + ".ts", base + "/index.js", base + "/index.ts"} {
			if fx, ok := a.facts[cand]; ok && fx.jsonrpc {
				return cand
			}
		}
	}
	return ""
}

// launched reports whether the package's manifest starts the endpoint file (a bin entry or a
// start script naming it), which makes code under examples/ the shipped server, not an example
func (a *analysis) launched(scope, file string) bool {
	stem := strings.TrimSuffix(path.Base(file), path.Ext(file))
	if stem == "index" || stem == "main" || stem == "server" || len(stem) < 3 {
		return false
	}
	for _, m := range []string{"package.json", "pyproject.toml", "setup.py", "Dockerfile"} {
		if strings.Contains(a.rawFile(path.Join(scope, m)), stem) {
			return true
		}
	}
	return false
}

// rawFile reads a small non-source file inside the scan root, "" when it is absent
func (a *analysis) rawFile(p string) string {
	fh, err := a.r.open(p)
	if err != nil {
		return ""
	}
	defer fh.Close()
	b, _ := io.ReadAll(io.LimitReader(fh, 256<<10))
	return string(b)
}

func (a *analysis) findings() []model.Finding {
	var out []model.Finding
	seen := map[string]bool{}
	for _, grp := range a.groups() {
		var extra []string
		if grp.jsonrpc {
			extra = uniqStrings([]string{grp.file, grp.dispatch})
		}
		pw := a.capabilityPower(grp.scope, extra)
		var unconditional, conditional []authSite
		for _, s := range grp.auth {
			if s.Conditional {
				conditional = append(conditional, s)
			} else {
				unconditional = append(unconditional, s)
			}
		}
		if len(unconditional) > 0 {
			continue
		}
		if l, ok := worstListen(grp.listens); ok && l.Bind == bindAll {
			key := RuleNetworkExposed + "|" + l.File + fmt.Sprint(l.Line)
			if !seen[key] {
				seen[key] = true
				out = append(out, a.exposedFinding(grp, l, pw, conditional))
			}
		}
		for _, c := range grp.cors {
			key := RuleBrowserReachable + "|" + c.File + fmt.Sprint(c.Line)
			if !seen[key] {
				seen[key] = true
				out = append(out, a.browserFinding(grp, c, pw, conditional))
				break
			}
		}
	}
	return out
}

func uniqStrings(xs []string) []string {
	var out []string
	for _, x := range xs {
		if x != "" && !containsString(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func worstListen(ls []listenSite) (listenSite, bool) {
	if len(ls) == 0 {
		return listenSite{}, false
	}
	best := ls[0]
	for _, l := range ls[1:] {
		if l.Bind > best.Bind {
			best = l
		}
	}
	return best, true
}

// weigh turns what the tools can do into severity, confidence and triage
func weigh(pw power, conditional []authSite, file string, launched bool) (model.Severity, float64, model.Triage, string) {
	sev, conf, triage := model.SeverityLow, 0.5, model.TriageContext
	reason := "the tools found reach nothing beyond what a caller could do without this server; the exposure is listed for context"
	switch pw.level {
	case reachStrong:
		sev, conf, triage = model.SeverityHigh, 0.8, model.TriagePotential
		reason = "reachable without authentication, and the tools act on the host or with the user's credentials"
	case reachCred:
		sev, conf, triage = model.SeverityMedium, 0.7, model.TriagePotential
		reason = "reachable without authentication, and the tools act with a credential the server holds: a caller uses the owner's account at that service"
	case reachRead:
		sev, conf, triage = model.SeverityMedium, 0.6, model.TriageNeedsReview
		reason = "the tools only read local data or write their own files; whether that data is sensitive decides how much the exposure matters"
	}
	if len(conditional) > 0 && pw.level > reachNone {
		sev, triage = model.SeverityMedium, model.TriageNeedsReview
		reason = fmt.Sprintf("an authentication check exists but is only installed under a condition (%s, %s:%d); whether users run the server without it depends on its documentation and deployment", conditional[0].Detail, conditional[0].File, conditional[0].Line)
	}
	if examplePath.MatchString(file) && !launched && triage == model.TriagePotential {
		triage = model.TriageNeedsReview
		reason = "the endpoint is in example code (" + file + "); whether users run it as shipped decides between a real exposure and documentation"
	}
	return sev, conf, triage, reason
}

func (a *analysis) exposedFinding(grp endpointGroup, l listenSite, pw power, conditional []authSite) model.Finding {
	sev, conf, triage, reason := weigh(pw, conditional, l.File, a.launched(grp.scope, grp.file))
	what := toolSummary(pw)
	desc := fmt.Sprintf("The MCP endpoint (%s, %s:%d) listens on every network interface: %s (%s:%d). No authentication check was found in the server's package, so any device that can reach this port - on the same Wi-Fi, office or container network - can call the tools. %s",
		grp.endpoint.Detail, grp.endpoint.File, grp.endpoint.Line, l.Detail, l.File, l.Line, what)
	ev := []model.Evidence{
		{Level: model.EvidenceStatic, Kind: "network_endpoint", Description: grp.endpoint.Detail, File: grp.endpoint.File, Line: grp.endpoint.Line},
		{Level: model.EvidenceStatic, Kind: "listen_address", Description: l.Detail, File: l.File, Line: l.Line},
	}
	ev = append(ev, powerEvidence(pw)...)
	return model.Finding{
		RuleID:        RuleNetworkExposed,
		Analyzer:      name,
		Category:      "network_exposure",
		Title:         "MCP endpoint listens on all network interfaces without authentication",
		Severity:      sev,
		Confidence:    conf,
		EvidenceLevel: model.EvidenceStatic,
		File:          l.File,
		Line:          l.Line,
		Description:   desc,
		Remediation:   "Listen on 127.0.0.1 by default and make other addresses an explicit option; require a token (for example a random bearer token generated at start-up) on every request to the MCP route.",
		Evidence:      ev,
		Triage:        triage,
		TriageReason:  reason,
	}
}

func (a *analysis) browserFinding(grp endpointGroup, c corsSite, pw power, conditional []authSite) model.Finding {
	sev, conf, triage, reason := weigh(pw, conditional, c.File, a.launched(grp.scope, grp.file))
	if !c.Preflight && !grp.jsonrpc && triage == model.TriagePotential {
		// a bare Access-Control-Allow-Origin: * without an answer to preflights lets a page send
		// only simple requests, which an SDK transport rejects for their content type
		sev, triage = model.SeverityMedium, model.TriageNeedsReview
		reason = "every origin is allowed, but preflight requests are not answered here, so whether a page can send the JSON request the transport requires depends on code the scanner did not place"
	}
	what := toolSummary(pw)
	desc := fmt.Sprintf("The MCP endpoint (%s, %s:%d) allows web pages of every origin: %s (%s:%d). No authentication check was found in the server's package, so any page the user opens while the server runs can send requests to it - on localhost too - and read the results. %s",
		grp.endpoint.Detail, grp.endpoint.File, grp.endpoint.Line, c.Detail, c.File, c.Line, what)
	ev := []model.Evidence{
		{Level: model.EvidenceStatic, Kind: "network_endpoint", Description: grp.endpoint.Detail, File: grp.endpoint.File, Line: grp.endpoint.Line},
		{Level: model.EvidenceStatic, Kind: "cors_policy", Description: c.Detail, File: c.File, Line: c.Line},
	}
	ev = append(ev, powerEvidence(pw)...)
	return model.Finding{
		RuleID:        RuleBrowserReachable,
		Analyzer:      name,
		Category:      "cross_origin_access",
		Title:         "Any web page can call the MCP endpoint: CORS allows every origin and there is no authentication",
		Severity:      sev,
		Confidence:    conf,
		EvidenceLevel: model.EvidenceStatic,
		File:          c.File,
		Line:          c.Line,
		Description:   desc,
		Remediation:   "Remove the wildcard CORS policy (allow only the origins of your own UI, if any), accept only Content-Type: application/json, and require a token on every request; for a local server also check the Host and Origin headers.",
		Evidence:      ev,
		Triage:        triage,
		TriageReason:  reason,
	}
}

func toolSummary(pw power) string {
	switch pw.level {
	case reachStrong, reachCred:
		return "What a caller gets: " + strings.Join(pw.reasons, "; ") + "."
	case reachRead:
		return "What a caller gets: " + strings.Join(pw.reasons, "; ") + "."
	}
	if pw.tools == 0 {
		return "No tool handler was found to weigh what a caller could do."
	}
	return fmt.Sprintf("The %d tool handler(s) found reach no program, file change or credential.", pw.tools)
}

func powerEvidence(pw power) []model.Evidence {
	var out []model.Evidence
	for _, r := range pw.reasons {
		out = append(out, model.Evidence{Level: model.EvidenceStatic, Kind: "tool_reach", Description: r})
	}
	return out
}
