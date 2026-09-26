package auth

import (
	"context"
	"testing"
	"time"

	tauth "github.com/revinand/mcp-scanner/testdata/auth"

	"github.com/revinand/mcp-scanner/internal/mcp/client"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/testdata/protocol/fixtures"
)

type refusedToolCallDialer struct{ d analyzer.Dialer }

func (w refusedToolCallDialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	sess, err := w.d.Dial(ctx, target)
	if err != nil {
		return nil, err
	}
	return refusedToolCallSession{sess}, nil
}

type refusedToolCallSession struct{ analyzer.Session }

func (refusedToolCallSession) CallTool(context.Context, string, map[string]any) (*analyzer.ToolCallResult, error) {
	return nil, client.ErrToolCallNotAllowed
}

func TestCheckTokenPassthroughRefusedCallIsNotACleanCheck(t *testing.T) {
	srv := tauth.New(tauth.Secure())
	defer srv.Close()

	ac := &analyzer.AnalysisContext{
		Dialer:           refusedToolCallDialer{tauth.HTTPDialer{}},
		Probes:           analyzer.ProbeToolCalls,
		AllowedToolCalls: []string{"whoami"},
		Options: map[string]map[string]any{
			"auth": {
				"tokens":        map[string]any{"valid": tauth.SignJWT(validClaims("userA"))},
				"identity_tool": "whoami",
			},
		},
	}
	st := &state{ac: ac, target: model.Target{Kind: model.TargetRemote, URL: srv.URL}, tokens: readTokens(ac)}

	ran, f, reason := New().checkTokenPassthrough(context.Background(), st)
	if ran {
		t.Fatalf("a refused tool call must not be recorded as a completed check (reason=%q, finding=%+v)", reason, f)
	}
	if f != nil {
		t.Fatalf("expected no finding from a call that never ran, got %+v", f)
	}
	if reason == "" {
		t.Fatal("expected a skip reason explaining the refused call")
	}
	if !st.inconclusiveProbe {
		t.Fatal("a refused tool call learned nothing and must mark the probe inconclusive")
	}

	// Aggregate must not be able to turn this into a clean scan
	res := model.AnalyzerResult{
		Analyzer: name, Status: model.AnalyzerPartial, Required: true,
		Coverage: model.Coverage{CapabilitiesDiscovered: 1, CapabilitiesSkipped: 1, SkipReasons: []string{"token_passthrough: " + reason}},
	}
	sr := &model.ScanResult{Analyzers: []model.AnalyzerResult{res}}
	sr.Aggregate(model.DefaultBlockingSeverity)
	if sr.Verdict == model.VerdictSafe {
		t.Fatal("aggregation produced SAFE from a refused, unconfirmed tool call")
	}
}

func TestCheckTokenPassthroughThroughRealDialer(t *testing.T) {
	srv := fixtures.StreamableHTTPServer(fixtures.ToolsOnly())
	defer srv.Close()
	client.AllowPrivateNetworksForTesting()

	target := model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"}
	newState := func(ac *analyzer.AnalysisContext) *state {
		return &state{ac: ac, target: target, tokens: map[string]string{"valid": "test-token"}}
	}
	acOptions := map[string]map[string]any{"auth": {"identity_tool": "ping"}}

	t.Run("refused when the dialer's own Options grant no permission", func(t *testing.T) {
		ac := &analyzer.AnalysisContext{
			Dialer:           client.NewDialer(client.Options{Timeout: 5 * time.Second}), // no Probes, no AllowedToolCalls
			Probes:           analyzer.ProbeToolCalls,
			AllowedToolCalls: []string{"ping"},
			Options:          acOptions,
		}
		ran, f, reason := New().checkTokenPassthrough(context.Background(), newState(ac))
		if ran {
			t.Fatalf("expected the call to be refused, got ran=true reason=%q finding=%+v", reason, f)
		}
		if reason == "" {
			t.Fatal("expected a skip reason")
		}
	})

	t.Run("runs once the dialer's Options actually carry Probes and AllowedToolCalls", func(t *testing.T) {
		ac := &analyzer.AnalysisContext{
			Dialer: client.NewDialer(client.Options{
				Timeout: 5 * time.Second, Probes: analyzer.ProbeToolCalls, AllowedToolCalls: []string{"ping"},
			}),
			Probes:           analyzer.ProbeToolCalls,
			AllowedToolCalls: []string{"ping"},
			Options:          acOptions,
		}
		ran, _, reason := New().checkTokenPassthrough(context.Background(), newState(ac))
		if !ran {
			t.Fatalf("expected the call to run once the dialer's own Options grant permission, skip reason: %q", reason)
		}
	})
}

// hiddenSessionID models a client, such as legacy SSE, that does not expose the server session id
type hiddenSessionID struct{ analyzer.Session }

func (hiddenSessionID) SessionID() string { return "" }

type hiddenSessionIDDialer struct{ inner tauth.HTTPDialer }

func (d hiddenSessionIDDialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	return d.DialWithOptions(ctx, target, analyzer.DialOptions{})
}

func (d hiddenSessionIDDialer) DialWithOptions(ctx context.Context, target model.Target, opts analyzer.DialOptions) (analyzer.Session, error) {
	s, err := d.inner.DialWithOptions(ctx, target, opts)
	if err != nil {
		return nil, err
	}
	return hiddenSessionID{s}, nil
}

// A fixation probe with no visible session id is inconclusive, even when the server adopts it
func TestSessionFixationWithNoVisibleSessionIDIsNotHeld(t *testing.T) {
	p := tauth.Secure()
	p.AllowClientSessionID = true
	srv := tauth.New(p)
	defer srv.Close()

	ac := &analyzer.AnalysisContext{
		Dialer:  hiddenSessionIDDialer{},
		Probes:  analyzer.ProbeSafe,
		Options: map[string]map[string]any{"auth": {"tokens": map[string]any{"valid": tauth.SignJWT(validClaims("userA"))}}},
	}
	st := &state{ac: ac, target: model.Target{Kind: model.TargetRemote, URL: srv.URL}, tokens: readTokens(ac)}
	ran, f, reason := New().checkSessionFixation(context.Background(), st)
	if ran || f != nil {
		t.Fatalf("ran = %v, finding = %+v: an unobservable id was reported as a result", ran, f)
	}
	if reason == "" {
		t.Fatal("want a skip reason saying why fixation could not be tested")
	}
}

// plainDialer cannot carry a proposed or resumed session id
type plainDialer struct{ inner tauth.HTTPDialer }

func (d plainDialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	return d.inner.Dial(ctx, target)
}

// A dialer that cannot send the proposed id cannot run the fixation probe
func TestSessionProbeWithoutSessionDialerIsNotRun(t *testing.T) {
	p := tauth.Secure()
	p.AllowClientSessionID = true
	srv := tauth.New(p)
	defer srv.Close()

	ac := &analyzer.AnalysisContext{
		Dialer:  plainDialer{},
		Probes:  analyzer.ProbeSafe,
		Options: map[string]map[string]any{"auth": {"tokens": map[string]any{"valid": tauth.SignJWT(validClaims("userA"))}}},
	}
	st := &state{ac: ac, target: model.Target{Kind: model.TargetRemote, URL: srv.URL}, tokens: readTokens(ac)}
	ran, f, reason := New().checkSessionFixation(context.Background(), st)
	if ran || f != nil || reason == "" {
		t.Fatalf("ran = %v, finding = %+v, reason = %q: a probe that could not be sent was reported as run", ran, f, reason)
	}
	if !st.inconclusiveProbe {
		t.Fatal("an unsendable probe must mark the result inconclusive")
	}
}
