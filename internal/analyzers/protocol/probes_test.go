package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	mcpclient "github.com/revinand/mcp-scanner/internal/mcp/client"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/testdata/protocol/fixtures"
)

type fakeSession struct {
	callFn  func(ctx context.Context, method string, params any) (json.RawMessage, error)
	closed  bool
	closeCh chan struct{}
}

func (f *fakeSession) Snapshot() *model.Snapshot { return nil }
func (f *fakeSession) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	return f.callFn(ctx, method, params)
}
func (f *fakeSession) CallTool(context.Context, string, map[string]any) (*analyzer.ToolCallResult, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeSession) ReadResource(context.Context, string) (*analyzer.ResourceContent, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeSession) SessionID() string { return "fake" }
func (f *fakeSession) Close() error {
	f.closed = true
	if f.closeCh != nil {
		close(f.closeCh)
	}
	return nil
}

var _ analyzer.Session = (*fakeSession)(nil)

func TestEvaluateRejectionProbeCases(t *testing.T) {
	if fs := evaluateRejectionProbe("x", "x/method", nil, nil); !hasRule(fs, RuleProbeUnexpectedAnswer) {
		t.Fatal("a nil error (success) was not flagged as unexpected")
	}
	if fs := evaluateRejectionProbe("x", "x/method", nil, context.DeadlineExceeded); !hasRule(fs, RuleProbeAcceptedUnanswered) {
		t.Fatal("a deadline-exceeded error was not flagged as accepted-but-unanswered")
	}
	if fs := evaluateRejectionProbe("x", "x/method", nil, errors.New("panic: runtime error: index out of range\ngoroutine 1")); !hasRule(fs, RuleProbeLeaksInternals) {
		t.Fatal("a stack-trace-shaped error was not flagged as a leak")
	}
	if fs := evaluateRejectionProbe("x", "x/method", nil, &analyzer.ProtocolError{Code: -32601, Message: "method not found"}); len(fs) != 0 {
		t.Fatalf("a clean rejection was flagged: %v", fs)
	}
	if fs := evaluateRejectionProbe("x", "x/method", nil, &fakeStatusError{status: 202, msg: "unsupported content type \"\""}); !hasRule(fs, RuleProbeAcceptedUnanswered) {
		t.Fatalf("a 2xx status with no reply was not flagged as accepted-but-unanswered: %v", fs)
	} else if strings.Contains(fs[0].Description, "unsupported content type") || strings.Contains(fs[0].Evidence[0].Description, "unsupported content type") {
		t.Fatalf("the finding quoted the client/server-shaped error text instead of describing what was observed: %+v", fs[0])
	}
	if fs := evaluateRejectionProbe("x", "x/method", nil, &fakeStatusError{status: 403, msg: "forbidden"}); len(fs) != 0 {
		t.Fatalf("a 4xx status was not treated as a clean rejection: %v", fs)
	}
}

// fakeStatusError satisfies analyzer.StatusCoder without depending on the
// unexported error type internal/mcp/client actually wraps a status in
type fakeStatusError struct {
	status int
	msg    string
}

func (e *fakeStatusError) Error() string { return e.msg }
func (e *fakeStatusError) Status() int   { return e.status }

var _ analyzer.StatusCoder = (*fakeStatusError)(nil)

func TestLeaksInternalsPatternPrecision(t *testing.T) {
	benign := []string{
		"invalid character 0x00 looking for beginning of value",
		"field\tvalue\nsecond\tcolumn", // tab-separated, not a stack frame
	}
	for _, s := range benign {
		if leaked, pattern := leaksInternals(s); leaked {
			t.Fatalf("leaksInternals(%q) = true (matched %q), want false", s, pattern)
		}
	}

	leaking := []string{
		"segfault reading pointer 0x00007f9a3c000000",
		"java.lang.NullPointerException\n\tat com.example.Service.call(Service.java:42)",
	}
	for _, s := range leaking {
		if leaked, _ := leaksInternals(s); !leaked {
			t.Fatalf("leaksInternals(%q) = false, want true", s)
		}
	}
}

func TestRedact(t *testing.T) {
	const secret = "sk-live-SECRET"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"json header, value stripped and key kept",
			`{"headers":{"Authorization":"Bearer sk-live-SECRET123"}}`,
			`{"headers":{"Authorization":"[redacted]"}}`,
		},
		{
			"plain text header, key kept",
			"upstream rejected: Authorization: Bearer sk-live-SECRET123",
			"upstream rejected: Authorization: [redacted]",
		},
		{
			"every occurrence redacted, not just the first",
			`{"a":{"Authorization":"Bearer AAA"},"b":{"Authorization":"Bearer BBB"}}`,
			`{"a":{"Authorization":"[redacted]"},"b":{"Authorization":"[redacted]"}}`,
		},
		{
			"a credential header other than Authorization",
			`{"headers":{"X-Api-Key":"sk-live-SECRET456"}}`,
			`{"headers":{"X-Api-Key":"[redacted]"}}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := redact(c.in)
			if got != c.want {
				t.Fatalf("redact(%q) = %q, want %q", c.in, got, c.want)
			}
			if strings.Contains(got, secret) {
				t.Fatalf("redact(%q) leaked the secret: %q", c.in, got)
			}
		})
	}
}

func TestProbeUnsupportedProtocolVersionEchoIsFlagged(t *testing.T) {
	sess := &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		return json.RawMessage(`{"protocolVersion":"1999-01-01"}`), nil
	}}
	fs := probeUnsupportedProtocolVersion(context.Background(), sess)
	if !hasRule(fs, RuleProbeUnexpectedAnswer) {
		t.Fatalf("echoing the bogus version back was not flagged: %v", fs)
	}
}

func TestProbeUnsupportedProtocolVersionNegotiationIsFine(t *testing.T) {
	sess := &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		return json.RawMessage(`{"protocolVersion":"2025-06-18"}`), nil
	}}
	fs := probeUnsupportedProtocolVersion(context.Background(), sess)
	if len(fs) != 0 {
		t.Fatalf("a real negotiated version was flagged: %v", fs)
	}
}

func TestProbeInvalidToolNameUnexpectedSuccessIsFlagged(t *testing.T) {
	sess := &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		return json.RawMessage(`{"isError":false,"content":[{"type":"text","text":"ok"}]}`), nil
	}}
	fs := probeInvalidToolName(context.Background(), sess)
	if !hasRule(fs, RuleProbeUnexpectedAnswer) {
		t.Fatalf("a fabricated success for a nonexistent tool was not flagged: %v", fs)
	}

	desc := fs[0].Evidence[0].Description
	if !strings.Contains(desc, "isError") {
		t.Fatalf("evidence description is not readable JSON: %q", desc)
	}
}

func TestProbeInvalidToolNameLeakIsFlagged(t *testing.T) {
	sess := &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		return json.RawMessage(`{"isError":true,"content":[{"type":"text","text":"panic: nil pointer\n/home/dev/server.go:42"}]}`), nil
	}}
	fs := probeInvalidToolName(context.Background(), sess)
	if !hasRule(fs, RuleProbeLeaksInternals) {
		t.Fatalf("a leaked stack trace in the tool error result was not flagged: %v", fs)
	}
}

func TestProbeInvalidToolNameCleanErrorResultIsFine(t *testing.T) {
	sess := &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		return json.RawMessage(`{"isError":true,"content":[{"type":"text","text":"unknown tool"}]}`), nil
	}}
	fs := probeInvalidToolName(context.Background(), sess)
	if len(fs) != 0 {
		t.Fatalf("a clean isError result was flagged: %v", fs)
	}
}

func TestProbeCapabilityMismatchActiveFlagsUnadvertisedAnswer(t *testing.T) {
	snap := &model.Snapshot{Capabilities: map[string]any{}} // nothing advertised
	sess := &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		return json.RawMessage(`{"tools":[]}`), nil // answers anyway
	}}
	fs := probeCapabilityMismatchActive(context.Background(), snap, sess)
	if !hasRule(fs, RuleCapabilityMismatch) {
		t.Fatalf("an unadvertised capability that still answered was not flagged: %v", fs)
	}
}

func TestProbeCapabilityMismatchActiveCleanWhenConsistent(t *testing.T) {
	snap := &model.Snapshot{Capabilities: map[string]any{}}
	sess := &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		return nil, &analyzer.ProtocolError{Code: -32601, Message: "method not found"}
	}}
	fs := probeCapabilityMismatchActive(context.Background(), snap, sess)
	if len(fs) != 0 {
		t.Fatalf("a consistently-unadvertised, consistently-unanswered capability was flagged: %v", fs)
	}
}

func TestProbeMalformedRequestAcceptedButUnansweredSameOverBothTransports(t *testing.T) {
	oldTimeout := probeTimeout
	probeTimeout = 2 * time.Second
	defer func() { probeTimeout = oldTimeout }()

	runProbe := func(t *testing.T, ctx context.Context, sess analyzer.Session) []model.Finding {
		t.Helper()
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		fs := probeMalformedRequest(pctx, sess)
		if !hasRule(fs, RuleProbeAcceptedUnanswered) {
			t.Fatalf("expected the request to be flagged as accepted but unanswered, got %v", fs)
		}
		if hasRule(fs, RuleProbeConnectionDied) {
			t.Fatalf("an accepted-but-unanswered request is not a dead connection: %v", fs)
		}
		return fs
	}

	t.Run("streamable", func(t *testing.T) {
		ac, _, cleanup := prepareLiveWellBehaved(t)
		defer cleanup()
		runProbe(t, context.Background(), ac.Session)
	})

	t.Run("sse", func(t *testing.T) {

		srv := fixtures.SSEServer(fixtures.WellBehaved())
		defer srv.Close()
		target := model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "sse"}
		p := mcpclient.NewPreparer(mcpclient.Options{Timeout: 5 * time.Second})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		ac, cleanup, err := p.Prepare(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		ac.Probes = analyzer.ProbeSafe
		runProbe(t, ctx, ac.Session)
	})
}

// fakeDialer hands back a fresh fakeSession every time Dial is called, so
// runActiveProbes' reconnect path can be exercised without a live target
type fakeDialer struct {
	dialed int
	newFn  func() analyzer.Session
	failAt int // Dial fails on this call number (1-based); 0 means never
}

func (d *fakeDialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	d.dialed++
	if d.failAt != 0 && d.dialed == d.failAt {
		return nil, errors.New("dial failed")
	}
	return d.newFn(), nil
}

func TestRunActiveProbesReconnectsAfterDeadSession(t *testing.T) {
	oldTimeout := probeTimeout
	probeTimeout = 200 * time.Millisecond
	defer func() { probeTimeout = oldTimeout }()

	pingCount := 0
	makeDeadFirstSession := func() *fakeSession {
		return &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
			if method == "ping" {
				pingCount++
				if pingCount == 1 {
					return nil, errors.New("connection reset")
				}
				return json.RawMessage(`{}`), nil
			}
			return nil, &analyzer.ProtocolError{Code: -32601, Message: "method not found"}
		}}
	}

	dead := makeDeadFirstSession()
	fresh := makeDeadFirstSession()
	dialer := &fakeDialer{newFn: func() analyzer.Session { return fresh }}

	ac := &analyzer.AnalysisContext{
		Session: dead,
		Dialer:  dialer,
		Snapshot: &model.Snapshot{Capabilities: map[string]any{
			"tools": map[string]any{}, "prompts": map[string]any{}, "resources": map[string]any{},
		}},
	}
	findings, warnings, complete := runActiveProbes(context.Background(), model.Target{}, ac)
	if !complete {
		t.Fatalf("expected the run to complete after reconnecting, warnings: %v", warnings)
	}
	if !hasRule(findings, RuleProbeConnectionDied) {
		t.Fatalf("expected a connection-died finding, got %v", findings)
	}
	if dialer.dialed != 1 {
		t.Fatalf("dialer was called %d times, want 1", dialer.dialed)
	}
	if dead.closed {

		t.Fatal("runActiveProbes closed the original session, which it did not open")
	}
	if !fresh.closed {
		t.Fatal("runActiveProbes did not close the session it dialed")
	}
}

// A JSON-RPC error still proves the peer answered and the connection framing survived.
// Treating an unsupported ping as death would create a false HIGH finding and needless reconnect.
func TestRunActiveProbesTreatsAPingProtocolErrorAsAlive(t *testing.T) {
	sess := &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		return nil, &analyzer.ProtocolError{Code: -32601, Message: "method not found"}
	}}
	dialer := &fakeDialer{newFn: func() analyzer.Session { return &fakeSession{} }}
	ac := &analyzer.AnalysisContext{Session: sess, Dialer: dialer}

	findings, warnings, complete := runActiveProbes(context.Background(), model.Target{}, ac)
	if !complete {
		t.Fatalf("expected the run to complete, warnings: %v", warnings)
	}
	if hasRule(findings, RuleProbeConnectionDied) {
		t.Fatalf("a ping answered with a JSON-RPC error is a live connection, got %v", findings)
	}
	if dialer.dialed != 0 {
		t.Fatalf("no reconnect should be needed for a live session, dialed %d times", dialer.dialed)
	}
}

// A parent scan deadline and the probe's own timeout surface as the same context error.
// The scanner must not attribute its exhausted parent deadline to target behavior.
func TestRunActiveProbesDoesNotBlameTheTargetForTheScannersOwnDeadline(t *testing.T) {
	sess := &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	findings, warnings, complete := runActiveProbes(ctx, model.Target{}, &analyzer.AnalysisContext{Session: sess})
	if complete {
		t.Fatal("a run cut short by an inherited deadline is not complete coverage")
	}
	if hasRule(findings, RuleProbeConnectionDied) {
		t.Fatalf("the scanner's own deadline was reported as the target failing to answer: %v", findings)
	}
	if hasRule(findings, RuleProbeAcceptedUnanswered) {
		t.Fatalf("the scanner's own deadline was reported as the server accepting and ignoring a request: %v", findings)
	}
	if len(warnings) == 0 {
		t.Fatal("expected a warning recording that the analyzer or scan deadline cut the probes short")
	}
}
