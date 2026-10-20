package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tauth "github.com/devlab-group/mcp-scanner/testdata/auth"

	"github.com/devlab-group/mcp-scanner/internal/httpx"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// newTestAnalyzer permits loopback only in this test client. Production keeps the private-network
// guard, while metadata tests still exercise the real guarded transport against httptest servers.
func newTestAnalyzer() *Analyzer {
	a := New()
	a.httpClient = httpx.Policy{AllowPrivateNetworks: true}.Client(5 * time.Second)
	return a
}

const (
	testAudience = "mcp-test-resource"
	testIssuer   = "https://mock-as.invalid"
	testScope    = "tools:call"
)

func validClaims(subject string) tauth.Claims {
	return tauth.Claims{
		Subject: subject, Audience: testAudience, Issuer: testIssuer,
		Scope: testScope, ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
}

// fullTokenSet mints every operator-supplied test token the matrix can use,
// each wrong in exactly the one way its name says
func fullTokenSet() map[string]any {
	return map[string]any{
		"valid":              tauth.SignJWT(validClaims("userA")),
		"expired_token":      tauth.SignJWT(tauth.Claims{Subject: "userA", Audience: testAudience, Issuer: testIssuer, Scope: testScope, ExpiresAt: time.Now().Add(-time.Hour).Unix()}),
		"wrong_audience":     tauth.SignJWT(tauth.Claims{Subject: "userA", Audience: "other-resource", Issuer: testIssuer, Scope: testScope, ExpiresAt: time.Now().Add(time.Hour).Unix()}),
		"wrong_issuer":       tauth.SignJWT(tauth.Claims{Subject: "userA", Audience: testAudience, Issuer: "https://evil-as.invalid", Scope: testScope, ExpiresAt: time.Now().Add(time.Hour).Unix()}),
		"insufficient_scope": tauth.SignJWT(tauth.Claims{Subject: "userA", Audience: testAudience, Issuer: testIssuer, Scope: "tools:read", ExpiresAt: time.Now().Add(time.Hour).Unix()}),
		"excessive_scope":    tauth.SignJWT(tauth.Claims{Subject: "userA", Audience: testAudience, Issuer: testIssuer, Scope: "tools:call admin:all", ExpiresAt: time.Now().Add(time.Hour).Unix()}),
		"user_b":             tauth.SignJWT(validClaims("userB")),
	}
}

// testContext builds an AnalysisContext with tokens (if any) nested under
// options.auth.tokens, matching what readTokens actually looks up
func testContext(dialer analyzer.Dialer, probes analyzer.ProbeLevel, tokens map[string]any, allowedTools []string) *analyzer.AnalysisContext {
	opts := map[string]any{}
	if len(tokens) > 0 {
		opts["tokens"] = tokens
	}
	return &analyzer.AnalysisContext{
		Dialer:           dialer,
		Probes:           probes,
		AllowedToolCalls: allowedTools,
		Snapshot:         &model.Snapshot{Transport: model.TransportInfo{TLS: true}}, // isolate from the plaintext_transport check
		Options:          map[string]map[string]any{"auth": opts},
	}
}

func TestAnalyzeSkipsNonRemoteTargets(t *testing.T) {
	a := New()
	for _, kind := range []model.TargetKind{model.TargetStdio, model.TargetStatic} {
		res := a.Analyze(context.Background(), model.Target{Kind: kind}, testContext(nil, analyzer.ProbeSafe, nil, nil))
		if res.Status != model.AnalyzerSkipped {
			t.Fatalf("kind %s: expected SKIPPED, got %s", kind, res.Status)
		}
		if len(res.Warnings) == 0 {
			t.Fatalf("kind %s: expected a skip reason", kind)
		}
	}
}

func TestAnalyzeSkipsWhenProbesTooLow(t *testing.T) {
	srv := tauth.New(tauth.Secure())
	defer srv.Close()
	a := New()
	target := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	ac := testContext(tauth.HTTPDialer{}, analyzer.ProbeNone, nil, nil)
	res := a.Analyze(context.Background(), target, ac)
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("expected SKIPPED at ProbeNone, got %s (findings=%v)", res.Status, res.Findings)
	}
}

func TestAnalyzeSkipsWhenNoDialer(t *testing.T) {
	a := New()
	// A literal loopback address with nothing listening: fails locally,
	// no DNS lookup, no chance of touching the real network
	target := model.Target{Kind: model.TargetRemote, URL: "http://127.0.0.1:1"}
	ac := testContext(nil, analyzer.ProbeSafe, nil, nil)
	res := a.Analyze(context.Background(), target, ac)
	// Passive discovery still ran (it needs no dialer), so this is a
	// partial result, not a total skip
	if res.Status != model.AnalyzerPartial {
		t.Fatalf("expected PARTIAL with no dialer, got %s", res.Status)
	}
	found := false
	for _, r := range res.Coverage.SkipReasons {
		if r == "no dialer available: cannot open additional sessions for the credential matrix" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a clear no-dialer skip reason, got %v", res.Coverage.SkipReasons)
	}
}

func TestAnalyzeCompletesWithMinimalConfig(t *testing.T) {
	srv := tauth.New(tauth.Secure())
	defer srv.Close()
	a := newTestAnalyzer()
	target := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	ac := testContext(tauth.HTTPDialer{}, analyzer.ProbeSafe, nil, nil)

	res := a.Analyze(context.Background(), target, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("expected COMPLETED, got %s", res.Status)
	}
	if res.Coverage.CapabilitiesAnalyzed == 0 {
		t.Fatalf("expected at least one analyzed check")
	}
	if res.Coverage.CapabilitiesSkipped == 0 {
		t.Fatalf("expected skipped checks without configured tokens")
	}
	if len(res.Coverage.SkipReasons) == 0 {
		t.Fatalf("skips must always carry a reason")
	}
	if gaps := res.Coverage.Gaps(); len(gaps) != 0 {
		t.Fatalf("coverage must add up, got gaps: %v", gaps)
	}
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding %+v: %v", f, err)
		}
	}
}

func TestAnalyzeCompletesWithMinimalConfigStillFindsVulnerabilities(t *testing.T) {
	srv := tauth.New(tauth.Policy{AcceptAnyToken: true, SessionIDStyle: "random"})
	defer srv.Close()
	a := newTestAnalyzer()
	target := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	ac := testContext(tauth.HTTPDialer{}, analyzer.ProbeSafe, nil, nil)

	res := a.Analyze(context.Background(), target, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("expected COMPLETED, got %s", res.Status)
	}
	if len(res.Findings) == 0 {
		t.Fatal("a server that requires no real auth must still be flagged with no test tokens configured")
	}
}

func TestAnalyzeFullMatrixVulnerable(t *testing.T) {
	srv := tauth.New(tauth.Policy{
		AcceptAnyToken:          true,
		SessionIDStyle:          "sequential",
		AllowClientSessionID:    true,
		BindSessionToUser:       false,
		HonorSessionTermination: false,
		RejectMalformedSession:  false,
	})
	defer srv.Close()

	a := newTestAnalyzer()
	target := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	// Reuse the tokens that were sent; minting again may produce different values
	tokens := fullTokenSet()
	ac := testContext(tauth.HTTPDialer{}, analyzer.ProbeToolCalls, tokens, []string{"whoami"})
	ac.Options["auth"]["identity_tool"] = "whoami"

	res := a.Analyze(context.Background(), target, ac)
	if res.Status != model.AnalyzerCompleted && res.Status != model.AnalyzerPartial {
		t.Fatalf("unexpected status %s", res.Status)
	}
	for _, gap := range res.Coverage.Gaps() {
		t.Fatalf("coverage does not add up: %s", gap)
	}

	want := []string{
		"auth.no_auth_required",
		"auth.expired_token_accepted",
		"auth.audience_not_validated",
		"auth.issuer_not_validated",
		"auth.scope_not_enforced",
		"auth.reused_session_accepted",
		"auth.malformed_session_id_accepted",
		"auth.guessable_session_id",
		"auth.session_fixation",
	}
	got := map[string]model.Finding{}
	for _, f := range res.Findings {
		got[f.RuleID] = f
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding %+v: %v", f, err)
		}
		if len(f.Evidence) == 0 {
			t.Fatalf("finding %s has no evidence", f.RuleID)
		}
	}
	for _, ruleID := range want {
		if _, ok := got[ruleID]; !ok {
			t.Errorf("expected finding %s, coverage: analyzed=%d skipped=%d reasons=%v",
				ruleID, res.Coverage.CapabilitiesAnalyzed, res.Coverage.CapabilitiesSkipped, res.Coverage.SkipReasons)
		}
	}

	for _, restated := range []string{"auth.invalid_token_accepted", "auth.session_not_bound_to_user"} {
		if _, ok := got[restated]; ok {
			t.Errorf("a target that accepted no credential at all was also reported as %s", restated)
		}
	}

	// Authorization must never appear in the clear in evidence
	for _, f := range res.Findings {
		for _, ev := range f.Evidence {
			req, _ := ev.Data["request"].(map[string]any)
			if req == nil {
				continue
			}
			authz, _ := req["authorization"].(string)
			for _, tok := range tokens {
				if s, ok := tok.(string); ok && authz == "Bearer "+s {
					t.Fatalf("finding %s leaked a full token in evidence: %q", f.RuleID, authz)
				}
			}
		}
	}

	// An accepted session id is a credential, so evidence must redact it like a token
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "attacker-chosen-session-id-0000000000000000") {
		t.Fatal("a full session id reached the serialized result")
	}
}

func TestAnalyzeFullMatrixFixed(t *testing.T) {
	srv := tauth.New(tauth.Secure())
	defer srv.Close()

	a := newTestAnalyzer()
	target := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	ac := testContext(tauth.HTTPDialer{}, analyzer.ProbeToolCalls, fullTokenSet(), []string{"whoami"})
	ac.Options["auth"]["identity_tool"] = "whoami"

	res := a.Analyze(context.Background(), target, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("expected COMPLETED against a fully fixed server, got %s (skip reasons: %v)", res.Status, res.Coverage.SkipReasons)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected zero findings against a fully fixed server, got %+v", res.Findings)
	}
	if gaps := res.Coverage.Gaps(); len(gaps) != 0 {
		t.Fatalf("coverage does not add up: %v", gaps)
	}
}

func TestPlaintextTransportFinding(t *testing.T) {
	srv := tauth.New(tauth.Secure())
	defer srv.Close()
	a := newTestAnalyzer()
	target := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	ac := &analyzer.AnalysisContext{
		Dialer: tauth.HTTPDialer{}, Probes: analyzer.ProbeSafe,
		Snapshot: &model.Snapshot{Transport: model.TransportInfo{TLS: false}},
	}
	res := a.Analyze(context.Background(), target, ac)
	found := false
	for _, f := range res.Findings {
		if f.RuleID == "auth.plaintext_transport" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected auth.plaintext_transport when Snapshot reports no TLS, got %+v", res.Findings)
	}
}

func TestNewRefusesLoopbackByDefault(t *testing.T) {
	srv := tauth.New(tauth.Secure())
	defer srv.Close()

	a := New()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, wellKnownURL(srv.URL), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if _, err := a.metadataClient(&analyzer.AnalysisContext{}).Do(req); err == nil {
		t.Fatalf("expected the production client to refuse a loopback destination")
	}
}

func TestMetadataClientHonoursAllowPrivateNetworks(t *testing.T) {
	srv := tauth.New(tauth.Secure())
	defer srv.Close()

	a := New()
	meta, err := a.fetchProtectedResourceMetadata(context.Background(),
		a.metadataClient(&analyzer.AnalysisContext{AllowPrivateNetworks: true}),
		wellKnownURL(srv.URL))
	if err != nil {
		t.Fatalf("fetching loopback metadata with the flag set: %v", err)
	}
	if len(meta) == 0 {
		t.Fatal("metadata came back empty, so the fetch did not reach the loopback server")
	}
}

// Permit the first loopback request so the test isolates the cross-origin redirect refusal.
// The redirected server must never receive the follow-up request.
func TestFetchMetadataRefusesCrossOriginRedirect(t *testing.T) {
	var sinkHit atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sinkHit.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"resource":              "internal-only",
			"authorization_servers": []string{"http://169.254.169.254/"},
		})
	}))
	defer sink.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			http.Redirect(w, r, sink.URL+"/.well-known/oauth-protected-resource", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer target.Close()

	a := newTestAnalyzer()
	st := &state{ac: &analyzer.AnalysisContext{}, target: model.Target{Kind: model.TargetRemote, URL: target.URL}}
	findings := a.passive(context.Background(), st)

	if sinkHit.Load() != 0 {
		t.Fatalf("the cross-origin redirect was followed - the SSRF guard regressed")
	}
	if st.metadataFound {
		t.Fatalf("metadata must not be considered found when the fetch was blocked by a refused redirect")
	}
	if st.resourceURL != "" || len(st.authServers) != 0 {
		t.Fatalf("no data from the redirect target should have been absorbed into state, got resource=%q authServers=%v", st.resourceURL, st.authServers)
	}
	for _, f := range findings {
		if f.RuleID == "auth.resource_identifier_mismatch" || f.RuleID == "auth.authorization_server_cross_origin" {
			t.Fatalf("must not report a finding built from data that was never actually fetched: %+v", f)
		}
	}
	if len(st.warnings) == 0 {
		t.Fatalf("expected a warning noting the fetch did not return usable metadata")
	}
	if strings.Contains(st.warnings[0], "127.0.0.1") || strings.Contains(st.warnings[0], "refused") || strings.Contains(st.warnings[0], "redirect") {
		t.Fatalf("warning must not leak connection detail that could distinguish this outcome from any other fetch failure: %q", st.warnings[0])
	}
}

// TestResourceIdentifierMismatchFinding is the required vulnerable/fixed
// pair for the resource-identifier-mismatch finding
func TestResourceIdentifierMismatchFinding(t *testing.T) {
	cases := []struct {
		name        string
		policy      tauth.Policy
		wantFinding bool
	}{
		{"vulnerable: resource names a different origin", tauth.Policy{MetadataResource: "https://internal-only.invalid/other-resource"}, true},
		{"fixed: resource names the target itself", tauth.Policy{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tauth.New(tc.policy)
			defer srv.Close()
			a := newTestAnalyzer()
			st := &state{ac: &analyzer.AnalysisContext{}, target: model.Target{Kind: model.TargetRemote, URL: srv.URL}}
			findings := a.passive(context.Background(), st)

			got := findingByRule(findings, "auth.resource_identifier_mismatch")
			if (got != nil) != tc.wantFinding {
				t.Fatalf("resource_identifier_mismatch present=%v, want %v (findings=%+v)", got != nil, tc.wantFinding, findings)
			}
			if got != nil {
				if err := got.Validate(); err != nil {
					t.Fatalf("invalid finding: %v", err)
				}
				if got.EvidenceLevel != model.EvidenceProtocol {
					t.Fatalf("expected PROTOCOL evidence, got %s", got.EvidenceLevel)
				}
			}
		})
	}
}

// TestAuthorizationServerCrossOriginFinding is the required vulnerable/fixed
// pair for the authorization-server-cross-origin finding
func TestAuthorizationServerCrossOriginFinding(t *testing.T) {
	cases := []struct {
		name        string
		policy      tauth.Policy
		wantFinding bool
	}{
		{"vulnerable: authorization server on a different origin", tauth.Policy{MetadataAuthServers: []string{"https://untrusted-as.invalid"}}, true},
		{"fixed: authorization server on the resource's own origin", tauth.Policy{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tauth.New(tc.policy)
			defer srv.Close()
			a := newTestAnalyzer()
			st := &state{ac: &analyzer.AnalysisContext{}, target: model.Target{Kind: model.TargetRemote, URL: srv.URL}}
			findings := a.passive(context.Background(), st)

			got := findingByRule(findings, "auth.authorization_server_cross_origin")
			if (got != nil) != tc.wantFinding {
				t.Fatalf("authorization_server_cross_origin present=%v, want %v (findings=%+v)", got != nil, tc.wantFinding, findings)
			}
			if got != nil {
				if err := got.Validate(); err != nil {
					t.Fatalf("invalid finding: %v", err)
				}
			}
		})
	}
}

func findingByRule(findings []model.Finding, ruleID string) *model.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func TestPredictableSessionIDHeuristic(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"session-1", "session-2", true},
		{"short", "shorter", true},
		{"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "f6e5d4c3b2a1908070605040302010ff", false},
	}
	for _, c := range cases {
		if got := predictable(c.a, c.b); got != c.want {
			t.Errorf("predictable(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestTokenPassthroughDetection(t *testing.T) {
	token := "sk-canary-passthrough-test-token"
	ac := &analyzer.AnalysisContext{
		Dialer:           echoDialer{},
		Probes:           analyzer.ProbeToolCalls,
		AllowedToolCalls: []string{"echo"},
		Options: map[string]map[string]any{
			"auth": {"tokens": map[string]any{"valid": token}, "identity_tool": "echo"},
		},
	}
	st := &state{ac: ac, target: model.Target{Kind: model.TargetRemote, URL: "https://example.invalid"}, tokens: readTokens(ac)}
	ran, f, reason := New().checkTokenPassthrough(context.Background(), st)
	if !ran {
		t.Fatalf("expected the check to run, skip reason: %s", reason)
	}
	if f == nil {
		t.Fatalf("expected a token_passthrough finding")
	}
	if f.RuleID != "auth.token_passthrough" {
		t.Fatalf("unexpected rule id %s", f.RuleID)
	}
}

type echoDialer struct{}

func (echoDialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	return echoSession{authz: target.Headers["Authorization"]}, nil
}

type echoSession struct{ authz string }

func (echoSession) Snapshot() *model.Snapshot { return nil }
func (s echoSession) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	return nil, nil
}
func (s echoSession) CallTool(ctx context.Context, name string, args map[string]any) (*analyzer.ToolCallResult, error) {
	return &analyzer.ToolCallResult{Text: []string{s.authz}}, nil
}
func (echoSession) ReadResource(ctx context.Context, uri string) (*analyzer.ResourceContent, error) {
	return nil, nil
}
func (echoSession) SessionID() string { return "" }
func (echoSession) Close() error      { return nil }

// countingBody measures client reads without counting bytes buffered by a test server
type countingBody struct {
	r io.Reader
	n int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += int64(n)
	return n, err
}

func (*countingBody) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchMetadataIsSizeBounded(t *testing.T) {
	// Keep the body finite while making any read past the bound observable
	body := &countingBody{r: io.MultiReader(
		strings.NewReader(`{"resource":"`),
		strings.NewReader(strings.Repeat("a", 8*maxMetadataBytes)),
	)}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       body,
			Request:    r,
		}, nil
	})}

	out, err := New().fetchProtectedResourceMetadata(context.Background(), client, "https://mcp.example/.well-known/oauth-protected-resource")
	if err == nil {
		t.Fatalf("an oversized metadata body decoded without error: %v", out)
	}
	if body.n > maxMetadataBytes {
		t.Fatalf("read %d bytes of the body, want the decode to stop at the %d byte bound", body.n, maxMetadataBytes)
	}
}

// Passive evidence may retain useful URL structure but never URL, query, or metadata credentials.
// Check the serialized result because that is the form users archive and share.
func TestPassiveFindingsCarryNoCredential(t *testing.T) {
	const password = "hunter2"
	const queryToken = "s3cr3t-query-token"
	const metaSecret = "metadata-token-9999"

	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"resource":              "https://bob:" + metaSecret + "@elsewhere.example/mcp",
			"authorization_servers": []string{"https://issuer.example/?client_secret=" + metaSecret},
		})
	}))
	defer meta.Close()

	host := strings.TrimPrefix(meta.URL, "http://")
	credentialed := "http://alice:" + password + "@" + host + "/mcp?api_key=" + queryToken

	a := newTestAnalyzer()
	st := &state{
		ac:     &analyzer.AnalysisContext{AllowPrivateNetworks: true},
		target: model.Target{Kind: model.TargetRemote, URL: credentialed},
	}
	findings := a.passive(context.Background(), st)
	if len(findings) == 0 {
		t.Fatal("no findings: the leak path this guards was never exercised")
	}

	serialized, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{password, queryToken, metaSecret} {
		if bytes.Contains(serialized, []byte(secret)) {
			t.Errorf("%q reached finding evidence:\n%s", secret, serialized)
		}
	}
}

func TestSessionNotBoundToUserOnAServerThatDoesAuthenticate(t *testing.T) {
	srv := tauth.New(tauth.Policy{
		CheckAudience: true, Audience: testAudience,
		CheckIssuer: true, Issuer: testIssuer,
		CheckExpiry:       true,
		BindSessionToUser: false,
	})
	defer srv.Close()

	ac := testContext(tauth.HTTPDialer{}, analyzer.ProbeToolCalls, fullTokenSet(), []string{"whoami"})
	ac.Options["auth"]["identity_tool"] = "whoami"

	res := newTestAnalyzer().Analyze(context.Background(),
		model.Target{Kind: model.TargetRemote, URL: srv.URL}, ac)

	var found *model.Finding
	for i := range res.Findings {
		if res.Findings[i].RuleID == "auth.session_not_bound_to_user" {
			found = &res.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("a server that honours one user's session for another user's token was not reported: findings=%v skips=%v",
			ruleIDs(res.Findings), res.Coverage.SkipReasons)
	}
	// A server that refuses an unauthenticated request is not open, so the
	// gate that suppresses this on an open target must not fire here
	for _, r := range res.Coverage.SkipReasons {
		if strings.Contains(r, "session_user_b") {
			t.Errorf("the cross-user case was skipped on a target that does authenticate: %s", r)
		}
	}
	// identity_tool is configured and allowed, so the finding should carry
	// the identity that came back rather than staying at the protocol level
	if found.EvidenceLevel != model.EvidenceConfirmed {
		t.Errorf("evidence level = %s, want CONFIRMED: identity_tool was configured for exactly this upgrade (warnings: %v)",
			found.EvidenceLevel, res.Warnings)
	}
}

// Accepting the narrow-scope token while refusing the broad one is scope checked backwards,
// its own finding next to the narrow token being accepted
func TestScopeCheckedBackwardsIsReported(t *testing.T) {
	p := tauth.Secure()
	p.RequiredScope = "tools:read"
	srv := tauth.New(p)
	defer srv.Close()

	res := newTestAnalyzer().Analyze(context.Background(), model.Target{Kind: model.TargetRemote, URL: srv.URL},
		testContext(tauth.HTTPDialer{}, analyzer.ProbeSafe, fullTokenSet(), nil))
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.RuleID] = true
	}
	if !got["auth.scope_enforcement_inverted"] || !got["auth.scope_not_enforced"] {
		t.Fatalf("want both scope findings, got %v (skips %v)", got, res.Coverage.SkipReasons)
	}
}
