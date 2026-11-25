package transport

import (
	"regexp"
	"strings"
	"unicode"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// authHeaders are request headers a server reads to authenticate the caller
var authHeaders = map[string]bool{
	"authorization": true, "x-api-key": true, "api-key": true, "x-auth-token": true, "x-access-token": true,
	"apikey": true, "x-api-token": true,
}

// authHeaderName matches header names that carry a caller credential under a project's own name:
// x-mcp-api-key, x-myservice-token, x-auth
var authHeaderName = regexp.MustCompile(`(?i)^x-[a-z0-9-]*(api-?key|token|auth)[a-z0-9-]*$`)

func authHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return authHeaders[n] || authHeaderName.MatchString(n)
}

// jsAuthCallees are authentication middlewares and verifiers by their last name segment
var jsAuthCallees = map[string]bool{
	"requireBearerAuth": true, "bearerAuth": true, "basicAuth": true, "jwtVerify": true, "expressjwt": true,
	"expressJwt": true, "clerkMiddleware": true, "requireAuth": true, "verifyAccessToken": true,
}

// pyAuthNames are authentication providers and middlewares by their last name segment
var pyAuthNames = map[string]bool{
	"BearerAuthProvider": true, "JWTVerifier": true, "StaticTokenVerifier": true, "RemoteAuthProvider": true,
	"OAuthProxy": true, "HTTPBearer": true, "APIKeyHeader": true, "AuthenticationMiddleware": true,
	"BearerAuthBackend": true, "RequireAuthMiddleware": true, "BearerTokenAuth": true, "OAuthProvider": true,
}

// pyNetworkTransports are the FastMCP transport names that serve over HTTP
var pyNetworkTransports = map[string]bool{"sse": true, "streamable-http": true, "streamable_http": true, "http": true}

func (s *scan) visit(f *file, fx *facts) {
	switch f.lang {
	case language.JavaScript, language.TypeScript:
		walkNodes(f.root, func(n *sitter.Node) { s.js(f, fx, n) })
	case language.Python:
		walkNodes(f.root, func(n *sitter.Node) { s.py(f, fx, n) })
	case language.Go:
		walkNodes(f.root, func(n *sitter.Node) { s.goNode(f, fx, n) })
	}
}

// ---- JavaScript and TypeScript

func (s *scan) js(f *file, fx *facts, n *sitter.Node) {
	switch n.Kind() {
	case "new_expression":
		ctor := parser.LastSegment(f.text(n.ChildByFieldName("constructor")))
		switch ctor {
		case "StreamableHTTPServerTransport", "SSEServerTransport", "WebStandardStreamableHTTPServerTransport":
			fx.endpoints = append(fx.endpoints, f.site(n, "new "+ctor))
			if ctor != "SSEServerTransport" && jsStateful(f, n) {
				fx.statefulHTTP = true
			}
		case "Hono", "Koa", "Elysia":
			fx.servers = append(fx.servers, f.site(n, "new "+ctor))
		}
	case "call_expression":
		s.jsCall(f, fx, n)
	case "member_expression":
		obj := n.ChildByFieldName("object")
		if obj != nil && strings.HasSuffix(strings.ToLower(f.text(obj)), "headers") && strings.EqualFold(f.text(n.ChildByFieldName("property")), "origin") && (inCondition(n) || f.rejectsNear(n)) && !inCORSHeaderSet(f, n) {
			fx.originChecks = append(fx.originChecks, f.site(n, "tests the request's Origin header"))
		}
		if obj != nil && strings.HasSuffix(strings.ToLower(f.text(obj)), "headers") && authHeader(f.text(n.ChildByFieldName("property"))) && !assignedTo(n) {
			f.headerAuth(fx, n, f.text(n.ChildByFieldName("property")))
		}
	case "subscript_expression":
		obj := n.ChildByFieldName("object")
		if obj != nil && strings.HasSuffix(strings.ToLower(f.text(obj)), "headers") && !assignedTo(n) {
			if v, ok := f.lit(n.ChildByFieldName("index")); ok && authHeader(v) {
				f.headerAuth(fx, n, v)
			}
		}
	case "pair":
		s.headerPair(f, fx, n)
	case "string":
		s.markerString(f, fx, n)
	}
}

// assignedTo reports whether n is the target of an assignment (headers.authorization = ...),
// which sets a header rather than reading one
func assignedTo(n *sitter.Node) bool {
	p := n.Parent()
	if p == nil || p.Kind() != "assignment_expression" && p.Kind() != "augmented_assignment_expression" {
		return false
	}
	l := p.ChildByFieldName("left")
	return l != nil && l.StartByte() == n.StartByte() && l.EndByte() == n.EndByte()
}

func (s *scan) markerString(f *file, fx *facts, n *sitter.Node) {
	v, ok := f.lit(n)
	if !ok {
		return
	}
	switch strings.ToLower(v) {
	case "tools/call":
		fx.jsonrpc = true
	case "access-control-allow-headers":
		fx.allowHeaders = true
	case "mcp-session-id":
		fx.sessionHeaderNamed = true
	}
}

// headerPair reads "Access-Control-Allow-Origin": "*" in a headers object or dictionary
func (s *scan) headerPair(f *file, fx *facts, n *sitter.Node) {
	k, v := n.ChildByFieldName("key"), n.ChildByFieldName("value")
	if k == nil || v == nil {
		return
	}
	key, ok := f.lit(k)
	if !ok {
		key = f.text(k)
	}
	if !strings.EqualFold(key, "access-control-allow-origin") {
		return
	}
	if val, ok := f.lit(v); ok && val == "*" {
		fx.cors = append(fx.cors, corsSite{site: f.site(n, "sends Access-Control-Allow-Origin: *")})
	} else if reflectsOrigin(f.text(v)) {
		fx.cors = append(fx.cors, corsSite{site: f.site(n, "echoes the request's Origin in Access-Control-Allow-Origin")})
	}
}

// reflectsOrigin reports whether an expression is the request's own Origin header, which allows
// every origin
func reflectsOrigin(expr string) bool {
	e := strings.ToLower(strings.ReplaceAll(expr, " ", ""))
	return strings.Contains(e, "headers.origin") || strings.Contains(e, `headers["origin"]`) || strings.Contains(e, `headers['origin']`) ||
		strings.Contains(e, `.get("origin")`) || strings.Contains(e, `.get('origin')`) || strings.Contains(e, `header("origin")`)
}

func (s *scan) jsCall(f *file, fx *facts, n *sitter.Node) {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return
	}
	callee := strings.TrimSpace(f.text(fn))
	last := parser.LastSegment(callee)
	args := namedArgs(n.ChildByFieldName("arguments"))
	switch {
	case last == "listen" && fn.Kind() == "member_expression":
		s.jsListen(f, fx, n, args)
	case callee == "express" || last == "createServer" || callee == "fastify" || callee == "Fastify" || callee == "koa" ||
		last == "createMcpExpressApp" || last == "createMcpHonoApp":
		fx.servers = append(fx.servers, f.site(n, callee+"()"))
		if last == "createMcpExpressApp" || last == "createMcpHonoApp" {
			fx.endpoints = append(fx.endpoints, f.site(n, callee+"()"))
		}
	case callee == "serve" && f.imports("@hono/node-server"):
		fx.servers = append(fx.servers, f.site(n, "serve()"))
		var host *sitter.Node
		if len(args) > 0 && args[0].Kind() == "object" {
			host = f.objectField(args[0], "hostname", "host")
		}
		b := classifyHost(f.evalJS(host, 0), bindAll)
		fx.listens = append(fx.listens, listenSite{f.site(n, "serve() "+hostDetail(f, host, "no hostname")), b})
	case callee == "cors":
		s.jsCors(f, fx, n, args)
	case (last == "setHeader" || last == "header" || last == "set" || last == "append") && len(args) >= 2:
		name, ok := f.lit(args[0])
		if !ok {
			return
		}
		if strings.EqualFold(name, "access-control-allow-origin") {
			if v, ok := f.lit(args[1]); ok && v == "*" {
				fx.cors = append(fx.cors, corsSite{site: f.site(n, "sends Access-Control-Allow-Origin: *")})
			} else if reflectsOrigin(f.text(args[1])) {
				fx.cors = append(fx.cors, corsSite{site: f.site(n, "echoes the request's Origin in Access-Control-Allow-Origin")})
			}
		}
	case jsAuthCallees[last] || callee == "passport.authenticate" || callee == "jwt.verify":
		fx.auth = append(fx.auth, authSite{f.site(n, callee+"()"), f.conditional(n)})
	case (last == "get" || last == "header" || last == "getHeader") && len(args) >= 1:
		if v, ok := f.lit(args[0]); ok && authHeader(v) {
			recv := strings.ToLower(strings.TrimSuffix(callee, last))
			if strings.Contains(recv, "header") || strings.Contains(recv, "req") {
				f.headerAuth(fx, n, v)
			}
		}
	}
}

// jsListen reads server.listen(port, host, cb) and server.listen({port, host})
func (s *scan) jsListen(f *file, fx *facts, n *sitter.Node, args []*sitter.Node) {
	// Node's http.Server binds every interface when no host is given; fastify binds localhost
	absent := bindAll
	if f.imports("fastify") {
		absent = bindLocal
	}
	if len(args) == 0 {
		fx.listens = append(fx.listens, listenSite{f.site(n, "listen() with no address"), absent})
		return
	}
	first := args[0]
	var host *sitter.Node
	switch first.Kind() {
	case "object":
		host = f.objectField(first, "host", "hostname")
	case "string", "template_string":
		if v, ok := f.lit(first); ok && !numeric(v) {
			fx.listens = append(fx.listens, listenSite{f.site(n, "listens on the local path "+v), bindLocal})
			return
		}
	}
	if first.Kind() != "object" && len(args) > 1 {
		h := args[1]
		if !isFunctionNode(h) && h.Kind() != "number" && !(h.Kind() == "identifier" && f.isFunctionName(f.text(h))) {
			host = h
		}
	}
	v := f.evalJS(host, 0)
	fx.listens = append(fx.listens, listenSite{f.site(n, "listen() "+hostDetail(f, host, "with no host")+envDetail(v)), classifyHost(v, absent)})
}

func (s *scan) jsCors(f *file, fx *facts, n *sitter.Node, args []*sitter.Node) {
	if len(args) == 0 {
		fx.cors = append(fx.cors, corsSite{site: f.site(n, "cors() with no options allows every origin"), Preflight: true})
		return
	}
	if args[0].Kind() != "object" {
		return
	}
	origin := f.objectField(args[0], "origin")
	if origin == nil {
		fx.cors = append(fx.cors, corsSite{site: f.site(n, "cors() without an origin option allows every origin"), Preflight: true})
		return
	}
	if v, ok := f.lit(origin); ok && v == "*" || origin.Kind() == "true" {
		fx.cors = append(fx.cors, corsSite{site: f.site(n, "cors({origin: "+f.text(origin)+"}) allows every origin"), Preflight: true})
	}
}

// objectField returns the value of the first of keys set in an object literal
func (f *file) objectField(obj *sitter.Node, keys ...string) *sitter.Node {
	for i := range obj.NamedChildCount() {
		ch := obj.NamedChild(i)
		if ch == nil {
			continue
		}
		switch ch.Kind() {
		case "pair":
			k := ch.ChildByFieldName("key")
			name, ok := f.lit(k)
			if !ok {
				name = f.text(k)
			}
			for _, want := range keys {
				if name == want {
					return ch.ChildByFieldName("value")
				}
			}
		case "shorthand_property_identifier":
			for _, want := range keys {
				if f.text(ch) == want {
					return ch
				}
			}
		}
	}
	return nil
}

// ---- Python

func (s *scan) py(f *file, fx *facts, n *sitter.Node) {
	switch n.Kind() {
	case "call":
		s.pyCall(f, fx, n)
	case "assignment":
		if l := strings.ReplaceAll(f.text(n.ChildByFieldName("left")), " ", ""); strings.HasSuffix(l, ".settings.host") {
			v := f.evalPy(n.ChildByFieldName("right"), 0)
			fx.pyHostSetting = &listenSite{f.site(n, l+" = "+strings.TrimSpace(f.text(n.ChildByFieldName("right")))+envDetail(v)), classifyHost(v, bindLocal)}
		}
	case "pair":
		s.headerPair(f, fx, n)
	case "subscript":
		if strings.HasSuffix(strings.ToLower(f.text(n.ChildByFieldName("value"))), "headers") {
			if v, ok := f.lit(n.ChildByFieldName("subscript")); ok && authHeader(v) {
				f.headerAuth(fx, n, v)
			}
		}
	case "string":
		s.markerString(f, fx, n)
	}
}

func (s *scan) pyCall(f *file, fx *facts, n *sitter.Node) {
	callee := strings.TrimSpace(f.text(n.ChildByFieldName("function")))
	last := parser.LastSegment(callee)
	pos, kw := f.pyArgs(n)
	switch {
	case callee == "uvicorn.run" || callee == "uvicorn.Config" || (callee == "run" || callee == "Config") && f.imports("uvicorn"):
		host := kw["host"]
		if host == nil && len(pos) > 1 {
			host = pos[1]
		}
		v := f.evalPy(host, 0)
		fx.servers = append(fx.servers, f.site(n, callee+"()"))
		fx.listens = append(fx.listens, listenSite{f.site(n, callee+"() "+hostDetail(f, host, "with no host")+envDetail(v)), classifyPyHost(v, host)})
	case last == "run" || last == "run_async":
		t := kw["transport"]
		if t == nil && len(pos) > 0 {
			t = pos[0]
		}
		if t == nil {
			return
		}
		name, ok := f.lit(t)
		if !ok || !pyNetworkTransports[name] {
			return
		}
		fx.endpoints = append(fx.endpoints, f.site(n, callee+"(transport="+name+")"))
		s.pyHost(f, fx, n, callee, kw["host"])
	case last == "sse_app" || last == "streamable_http_app" || last == "http_app":
		fx.endpoints = append(fx.endpoints, f.site(n, callee+"()"))
		if last != "sse_app" && !f.pyStateless(n, kw) {
			fx.statefulHTTP = true
		}
	case last == "run_sse_async" || last == "run_streamable_http_async" || last == "run_http_async":
		fx.endpoints = append(fx.endpoints, f.site(n, callee+"()"))
		s.pyHost(f, fx, n, callee, kw["host"])
	case last == "FastMCP":
		fx.servers = append(fx.servers, f.site(n, "FastMCP()"))
		if h := kw["host"]; h != nil {
			v := f.evalPy(h, 0)
			fx.pyHostSetting = &listenSite{f.site(n, "FastMCP(host="+strings.TrimSpace(f.text(h))+")"+envDetail(v)), classifyPyHost(v, h)}
		}
		for _, k := range []string{"auth", "token_verifier", "auth_server_provider"} {
			v := kw[k]
			if v == nil || v.Kind() == "none" {
				continue
			}
			cond := f.conditional(n) || v.Kind() == "conditional_expression"
			fx.auth = append(fx.auth, authSite{f.site(v, "FastMCP("+k+"=...)"), cond})
		}
	case last == "CORSMiddleware" || (last == "Middleware" || last == "add_middleware") && len(pos) > 0 && parser.LastSegment(f.text(pos[0])) == "CORSMiddleware":
		origins, regex := kw["allow_origins"], kw["allow_origin_regex"]
		broadRegex := false
		if rv, ok := f.lit(regex); ok {
			// a pattern for the user's own machine (localhost, 127.0.0.1) is not every origin
			broadRegex = !strings.Contains(rv, "localhost") && !strings.Contains(rv, "127")
		}
		if origins != nil && (strings.Contains(f.text(origins), `"*"`) || strings.Contains(f.text(origins), `'*'`)) || broadRegex {
			hdrs := strings.ToLower(f.text(kw["allow_headers"]))
			fx.cors = append(fx.cors, corsSite{site: f.site(n, "CORSMiddleware allows every origin"), Preflight: strings.Contains(hdrs, "*") || strings.Contains(hdrs, "content-type")})
		}
	case last == "get" && len(pos) >= 1 && strings.Contains(strings.ToLower(strings.TrimSuffix(callee, ".get")), "headers"):
		v, ok := f.lit(pos[0])
		if !ok {
			v, ok = pyBytes(f.text(pos[0]))
		}
		if ok && authHeader(v) {
			f.headerAuth(fx, n, v)
		}
		if ok && strings.EqualFold(v, "origin") && (inCondition(n) || f.rejectsNear(n)) {
			fx.originChecks = append(fx.originChecks, f.site(n, "tests the request's Origin header"))
		}
	case pyAuthNames[last]:
		fx.auth = append(fx.auth, authSite{f.site(n, callee+"()"), f.conditional(n)})
	}
}

// pyHost records the listen host of a FastMCP run/serve call: its own host= keyword, or the
// FastMCP settings when it has none
func (s *scan) pyHost(f *file, fx *facts, n *sitter.Node, callee string, host *sitter.Node) {
	if host == nil {
		fx.pyRunsWithoutHost = append(fx.pyRunsWithoutHost, f.site(n, callee+"()"))
		return
	}
	v := f.evalPy(host, 0)
	fx.listens = append(fx.listens, listenSite{f.site(n, callee+"(host="+strings.TrimSpace(f.text(host))+")"+envDetail(v)), classifyPyHost(v, host)})
}

// classifyPyHost classifies a Python host argument: no argument at all leaves the API's default
// (localhost for uvicorn and FastMCP); an explicit None or unset variable is not something the
// scanner can place
func classifyPyHost(v hostVal, node *sitter.Node) bind {
	if node == nil {
		return bindLocal
	}
	if v.state == valAbsent {
		return bindUnknown
	}
	return classifyHost(v, bindLocal)
}

// ---- Go

func (s *scan) goNode(f *file, fx *facts, n *sitter.Node) {
	switch n.Kind() {
	case "call_expression":
		s.goCall(f, fx, n)
	case "keyed_element":
		s.goKeyed(f, fx, n)
	case "interpreted_string_literal", "raw_string_literal":
		s.markerString(f, fx, n)
	}
}

func (s *scan) goCall(f *file, fx *facts, n *sitter.Node) {
	callee := strings.TrimSpace(f.text(n.ChildByFieldName("function")))
	last := parser.LastSegment(callee)
	args := namedArgs(n.ChildByFieldName("arguments"))
	switch {
	case last == "NewSSEServer" || last == "NewStreamableHTTPServer" || last == "NewStreamableHTTPHandler" || last == "NewSSEHandler":
		fx.endpoints = append(fx.endpoints, f.site(n, callee+"()"))
	case last == "Start" && len(args) == 1 && strings.Contains(callee, "."):
		v := f.evalGo(args[0], 0)
		fx.listens = append(fx.listens, listenSite{f.site(n, callee+"("+strings.TrimSpace(f.text(args[0]))+")"+envDetail(v)), classifyGoAddr(v)})
	case (callee == "http.ListenAndServe" || callee == "http.ListenAndServeTLS") && len(args) >= 1:
		v := f.evalGo(args[0], 0)
		fx.servers = append(fx.servers, f.site(n, callee+"()"))
		fx.listens = append(fx.listens, listenSite{f.site(n, callee+"("+strings.TrimSpace(f.text(args[0]))+")"+envDetail(v)), classifyGoAddr(v)})
	case callee == "net.Listen" && len(args) == 2:
		v := f.evalGo(args[1], 0)
		fx.listens = append(fx.listens, listenSite{f.site(n, callee+"(..., "+strings.TrimSpace(f.text(args[1]))+")"+envDetail(v)), classifyGoAddr(v)})
	case (last == "Set" || last == "Add") && len(args) == 2:
		if name, ok := f.lit(args[0]); ok && strings.EqualFold(name, "access-control-allow-origin") {
			if v, ok := f.lit(args[1]); ok && v == "*" {
				fx.cors = append(fx.cors, corsSite{site: f.site(n, "sends Access-Control-Allow-Origin: *")})
			} else if reflectsOrigin(f.text(args[1])) {
				fx.cors = append(fx.cors, corsSite{site: f.site(n, "echoes the request's Origin in Access-Control-Allow-Origin")})
			}
		}
	case callee == "cors.AllowAll":
		fx.cors = append(fx.cors, corsSite{site: f.site(n, "cors.AllowAll()"), Preflight: true})
	case last == "Get" && len(args) == 1 && strings.Contains(callee, "Header"):
		if v, ok := f.lit(args[0]); ok && authHeader(v) {
			f.headerAuth(fx, n, v)
		} else if ok && strings.EqualFold(v, "origin") && inCondition(n) {
			fx.originChecks = append(fx.originChecks, f.site(n, "tests the request's Origin header"))
		}
	case strings.Contains(last, "RequireBearerToken") || last == "BearerAuth" || last == "JWTAuth" || last == "BasicAuth" && strings.Contains(callee, "."):
		fx.auth = append(fx.auth, authSite{f.site(n, callee+"()"), f.conditional(n)})
	}
}

// goKeyed reads http.Server{Addr: ...} and cors.Options{AllowedOrigins: []string{"*"}}
func (s *scan) goKeyed(f *file, fx *facts, n *sitter.Node) {
	parts := namedArgs(n)
	if len(parts) < 2 {
		return
	}
	key, val := unwrapElement(parts[0]), unwrapElement(parts[len(parts)-1])
	switch f.text(key) {
	case "Addr":
		if typ := compositeType(f, n); strings.HasSuffix(typ, "http.Server") {
			v := f.evalGo(val, 0)
			fx.servers = append(fx.servers, f.site(n, typ+"{Addr}"))
			fx.listens = append(fx.listens, listenSite{f.site(n, typ+"{Addr: "+strings.TrimSpace(f.text(val))+"}"+envDetail(v)), classifyGoAddr(v)})
		}
	case "AllowedOrigins":
		if strings.Contains(f.text(val), `"*"`) {
			fx.cors = append(fx.cors, corsSite{site: f.site(n, "AllowedOrigins includes *"), Preflight: true})
		}
	}
}

func unwrapElement(n *sitter.Node) *sitter.Node {
	if n != nil && n.Kind() == "literal_element" {
		if inner := firstNamed(n); inner != nil {
			return inner
		}
	}
	return n
}

// compositeType is the type of the composite literal a keyed element belongs to
func compositeType(f *file, n *sitter.Node) string {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "composite_literal" {
			return strings.TrimSpace(f.text(p.ChildByFieldName("type")))
		}
	}
	return ""
}

// ---- details

func numeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func hostDetail(f *file, host *sitter.Node, none string) string {
	if host == nil {
		return none
	}
	return "on " + strings.TrimSpace(f.text(host))
}

func envDetail(v hostVal) string {
	switch {
	case v.env != "" && v.state == valLiteral:
		return " (" + v.env + " unset: " + quoteHost(v.value) + ")"
	case v.env != "" && v.state == valAbsent:
		return " (" + v.env + " unset: no value)"
	}
	return ""
}

func quoteHost(v string) string {
	if v == "" {
		return `""`
	}
	return v
}

// inCondition reports whether n sits in the condition of an if (or a ternary), directly or
// through a comparison or a call such as allowed.includes(origin)
func inCondition(n *sitter.Node) bool {
	for p, child := n.Parent(), n; p != nil; p, child = p.Parent(), p {
		switch p.Kind() {
		case "if_statement", "ternary_expression", "conditional_expression":
			c := p.ChildByFieldName("condition")
			return c != nil && c.StartByte() <= child.StartByte() && child.EndByte() <= c.EndByte()
		case "statement_block", "block", "function_definition", "arrow_function", "function_declaration", "method_definition", "func_literal":
			return false
		}
	}
	return false
}

// jsStateful reports whether a Streamable HTTP transport is created with session ids: its
// sessionIdGenerator option is anything but undefined
func jsStateful(f *file, n *sitter.Node) bool {
	args := namedArgs(n.ChildByFieldName("arguments"))
	if len(args) == 0 || args[0].Kind() != "object" {
		return false
	}
	g := f.objectField(args[0], "sessionIdGenerator")
	return g != nil && strings.TrimSpace(f.text(g)) != "undefined"
}

// pyStateless reports whether a FastMCP HTTP app runs without sessions: stateless_http=True on
// the call or the FastMCP constructor of the file
func (f *file) pyStateless(n *sitter.Node, kw map[string]*sitter.Node) bool {
	if v := kw["stateless_http"]; v != nil {
		return f.text(v) == "True"
	}
	return strings.Contains(string(f.src), "stateless_http=True")
}

// pyBytes decodes a Python bytes literal b"..." or b'...'
func pyBytes(text string) (string, bool) {
	t := strings.TrimSpace(text)
	if len(t) >= 3 && (t[0] == 'b' || t[0] == 'B') && (t[1] == '"' || t[1] == '\'') && t[len(t)-1] == t[1] {
		return t[2 : len(t)-1], true
	}
	return "", false
}

// rejection marks a refused request: a 401/403 status, its name, or an auth error message
var rejection = regexp.MustCompile(`(?i)\b40[13]\b|unauthori[sz]ed|forbidden|compare_digest|timingSafeEqual|ConstantTimeCompare|Status(Unauthorized|Forbidden)|invalid (api[ _-]?)?(key|token|credentials)|missing (api[ _-]?)?(key|token|credentials)|wrong (api[ _-]?)?(key|token)`)

// headerAuth records a read of a credential header as authentication only when the request is
// refused nearby without it: a header that only picks whose token to use (the caller's, else the
// server's own) authenticates nobody
func (f *file) headerAuth(fx *facts, n *sitter.Node, header string) {
	if !f.rejectsNear(n) {
		return
	}
	fx.auth = append(fx.auth, authSite{f.site(n, "reads the "+header+" request header and refuses the request without it"), f.conditional(n)})
}

// rejectsNear reports whether the code around n refuses a request (rejection): the function that
// holds n when it is a middleware-sized one, else the lines around n
func (f *file) rejectsNear(n *sitter.Node) bool {
	funcs := functionKinds[f.lang]
	for p := n.Parent(); p != nil; p = p.Parent() {
		if funcs[p.Kind()] {
			if p.EndPosition().Row-p.StartPosition().Row <= 80 {
				return rejection.MatchString(f.text(p))
			}
			break
		}
	}
	from := int(n.StartPosition().Row) - 3
	to := int(n.StartPosition().Row) + 12
	lines := strings.Split(string(f.src), "\n")
	if from < 0 {
		from = 0
	}
	if to > len(lines) {
		to = len(lines)
	}
	return rejection.MatchString(strings.Join(lines[from:to], "\n"))
}

// inCORSHeaderSet reports whether n is the value of an Access-Control-Allow-Origin header being
// set: echoing the Origin back is the opposite of checking it
func inCORSHeaderSet(f *file, n *sitter.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "call_expression", "pair":
			return strings.Contains(strings.ToLower(f.text(p)), "access-control-allow-origin")
		case "statement_block", "program":
			return false
		}
	}
	return false
}
