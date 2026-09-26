package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/internal/mcp/client"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	tauth "github.com/revinand/mcp-scanner/testdata/auth"
)

func TestProposeSessionIDAgainstTheRealConnectionLayer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const chosen = "attacker-chosen-session-id-0001"

	t.Run("a server that adopts the client's id hands it back", func(t *testing.T) {
		srv := tauth.New(tauth.Policy{AcceptAnyToken: true, AllowClientSessionID: true})
		defer srv.Close()

		sess := dialProposing(ctx, t, srv.URL, chosen)
		defer sess.Close()
		if sess.SessionID() != chosen {
			t.Fatalf("session id = %q, want the proposed %q - the probe never reached the handshake", sess.SessionID(), chosen)
		}
	})

	t.Run("a server that mints its own does not", func(t *testing.T) {
		srv := tauth.New(tauth.Policy{AcceptAnyToken: true})
		defer srv.Close()

		sess := dialProposing(ctx, t, srv.URL, chosen)
		defer sess.Close()
		if sess.SessionID() == chosen {
			t.Fatal("a server that mints its own id appeared to adopt the client's")
		}
		if sess.SessionID() == "" {
			t.Fatal("no session id at all, so the probe proves nothing either way")
		}
	})
}

func dialProposing(ctx context.Context, t *testing.T, url, id string) analyzer.Session {
	t.Helper()
	d, ok := client.NewDialer(client.Options{Timeout: 5 * time.Second, AllowPrivateNetworks: true}).(analyzer.SessionDialer)
	if !ok {
		t.Fatal("the production dialer does not implement SessionDialer, so the session checks cannot run against it")
	}
	target := model.Target{Kind: model.TargetRemote, URL: url,
		Headers: map[string]string{"Authorization": "Bearer good"}}
	sess, err := d.DialWithOptions(ctx, target, analyzer.DialOptions{ProposeSessionID: id})
	if err != nil {
		t.Fatalf("proposing a session id: %v", err)
	}
	return sess
}

func TestSessionFixationFiresThroughTheProductionDialer(t *testing.T) {
	srv := tauth.New(tauth.Policy{AcceptAnyToken: true, AllowClientSessionID: true})
	defer srv.Close()

	d := client.NewDialer(client.Options{Timeout: 5 * time.Second, AllowPrivateNetworks: true})
	ac := testContext(d, analyzer.ProbeSafe, map[string]any{"valid": "good", "user_b": "other"}, nil)
	target := model.Target{Kind: model.TargetRemote, URL: srv.URL}

	res := newTestAnalyzer().Analyze(context.Background(), target, ac)

	var found bool
	for _, f := range res.Findings {
		if f.RuleID == "auth.session_fixation" {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Errorf("session_fixation severity = %s, want HIGH", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("a server that adopts a client-chosen session id produced no session_fixation finding; findings=%v skips=%v",
			ruleIDs(res.Findings), res.Coverage.SkipReasons)
	}
}

// And the other direction: a server that mints its own id must not be
// reported, or the check would be worthless in the opposite way
func TestSessionFixationIsQuietOnAServerThatMintsItsOwnID(t *testing.T) {
	srv := tauth.New(tauth.Policy{AcceptAnyToken: true})
	defer srv.Close()

	d := client.NewDialer(client.Options{Timeout: 5 * time.Second, AllowPrivateNetworks: true})
	ac := testContext(d, analyzer.ProbeSafe, map[string]any{"valid": "good"}, nil)
	target := model.Target{Kind: model.TargetRemote, URL: srv.URL}

	res := newTestAnalyzer().Analyze(context.Background(), target, ac)
	for _, f := range res.Findings {
		if f.RuleID == "auth.session_fixation" {
			t.Fatalf("session_fixation fired on a server that mints its own id: %+v", f)
		}
	}
}

func ruleIDs(fs []model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func TestAnOpenServerIsNotAlsoReportedForAcceptingGarbage(t *testing.T) {
	srv := tauth.New(tauth.Policy{AcceptAnyToken: true})
	defer srv.Close()

	d := client.NewDialer(client.Options{Timeout: 5 * time.Second, AllowPrivateNetworks: true})
	res := newTestAnalyzer().Analyze(context.Background(),
		model.Target{Kind: model.TargetRemote, URL: srv.URL},
		testContext(d, analyzer.ProbeSafe, nil, nil))

	var open, garbage *model.Finding
	for i := range res.Findings {
		switch res.Findings[i].RuleID {
		case "auth.no_auth_required":
			open = &res.Findings[i]
		case "auth.invalid_token_accepted":
			garbage = &res.Findings[i]
		}
	}
	if open == nil {
		t.Fatalf("the open server was not reported at all: %v", ruleIDs(res.Findings))
	}

	if garbage != nil {
		t.Errorf("also reported at %s for accepting a garbage token, on a target that validates nothing", garbage.Severity)
	}
	for _, f := range res.Findings {
		if f.Severity == model.SeverityCritical {
			t.Errorf("an intentionally open server produced a CRITICAL finding, which fails the default gate: %s", f.RuleID)
		}
	}
}

// A server that refuses a missing token is not open, so the garbage-token case must still run
// against it, and one that then takes any bearer value is the CRITICAL case
func TestAServerThatRefusesNoTokenButTakesGarbageIsStillCritical(t *testing.T) {
	srv := tauth.New(tauth.Policy{AcceptAnyBearer: true})
	defer srv.Close()

	d := client.NewDialer(client.Options{Timeout: 5 * time.Second, AllowPrivateNetworks: true})
	res := newTestAnalyzer().Analyze(context.Background(),
		model.Target{Kind: model.TargetRemote, URL: srv.URL},
		testContext(d, analyzer.ProbeSafe, nil, nil))

	for _, r := range res.Coverage.SkipReasons {
		if strings.Contains(r, "invalid_token:") {
			t.Fatalf("the garbage-token case did not run on a server that does refuse an empty credential: %s", r)
		}
	}
	var got *model.Finding
	for i := range res.Findings {
		if res.Findings[i].RuleID == "auth.invalid_token_accepted" {
			got = &res.Findings[i]
		}
	}
	if got == nil {
		t.Fatalf("a server that accepts any bearer value produced no invalid_token finding: %+v", res.Findings)
	}
	if got.Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want CRITICAL", got.Severity)
	}
}

func TestTokensResolveFromTheEnvironment(t *testing.T) {
	t.Setenv("MCP_SCANNER_TEST_AUTH_VALID", "sk-live-from-the-environment")

	ac := testContext(nil, analyzer.ProbeSafe, nil, nil)
	ac.Options = map[string]map[string]any{"auth": {
		"tokens_env": map[string]any{"valid": "MCP_SCANNER_TEST_AUTH_VALID"},
	}}
	if got := readTokens(ac)["valid"]; got != "sk-live-from-the-environment" {
		t.Fatalf("tokens_env did not resolve: %q", got)
	}

	// An unset variable contributes nothing rather than an empty credential,
	// which would read as "configured" and make a case run with no token
	ac.Options = map[string]map[string]any{"auth": {
		"tokens_env": map[string]any{"valid": "MCP_SCANNER_TEST_AUTH_UNSET"},
	}}
	if _, ok := readTokens(ac)["valid"]; ok {
		t.Fatal("an unset environment variable produced a token entry")
	}

	// A literal still works and still wins, so an operator can override one
	// case without moving all of them
	ac.Options = map[string]map[string]any{"auth": {
		"tokens_env": map[string]any{"valid": "MCP_SCANNER_TEST_AUTH_VALID"},
		"tokens":     map[string]any{"valid": "literal-wins"},
	}}
	if got := readTokens(ac)["valid"]; got != "literal-wins" {
		t.Fatalf("a literal token did not override the environment form: %q", got)
	}
}

func TestAResumedSessionCanStillCallATool(t *testing.T) {
	srv := tauth.New(tauth.Policy{AcceptAnyToken: true})
	defer srv.Close()

	d := client.NewDialer(client.Options{
		Timeout: 5 * time.Second, AllowPrivateNetworks: true,
		Probes: analyzer.ProbeToolCalls, AllowedToolCalls: []string{"whoami"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target := model.Target{Kind: model.TargetRemote, URL: srv.URL,
		Headers: map[string]string{"Authorization": "Bearer good"}}

	first, err := d.Dial(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	id := first.SessionID()
	if id == "" {
		t.Fatal("the fixture issued no session id, so there is nothing to resume")
	}

	sd, ok := d.(analyzer.SessionDialer)
	if !ok {
		t.Fatal("the production dialer no longer implements SessionDialer")
	}
	resumed, err := sd.DialWithOptions(ctx, target, analyzer.DialOptions{ResumeSessionID: id})
	if err != nil {
		t.Fatalf("resuming: %v", err)
	}
	defer resumed.Close()

	res, err := resumed.CallTool(ctx, "whoami", map[string]any{})
	if err != nil {
		t.Fatalf("a resumed session could not call a tool: %v", err)
	}
	if len(res.Text) == 0 {
		t.Fatalf("the tool returned nothing: %+v", res)
	}
	t.Logf("resumed session called whoami and got %q", res.Text[0])

	// The allowlist still decides, exactly as it does for a handshaked
	// session - a different transport must not become a way around it
	if _, err := resumed.CallTool(ctx, "not-allowed", map[string]any{}); err == nil {
		t.Error("a resumed session called a tool that was not on the allowlist")
	}
}
