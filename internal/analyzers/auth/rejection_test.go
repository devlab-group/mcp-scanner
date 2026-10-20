package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	tauth "github.com/devlab-group/mcp-scanner/testdata/auth"
)

type statusErr struct {
	code int
	msg  string
}

func (e *statusErr) Error() string { return e.msg }
func (e *statusErr) Status() int   { return e.code }

var _ analyzer.StatusCoder = (*statusErr)(nil)

// failDialer fails every Dial identically, with whatever error the test
// configures - a clean typed rejection, or a plain network-shaped error
type failDialer struct{ err error }

func (d failDialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	return nil, d.err
}

func (d failDialer) DialWithOptions(ctx context.Context, target model.Target, _ analyzer.DialOptions) (analyzer.Session, error) {
	return d.Dial(ctx, target)
}

// timeoutDialer models a target that never answers: Dial blocks until ctx
// ends and returns exactly what a real Dialer honoring cancellation would
type timeoutDialer struct{}

func (timeoutDialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d timeoutDialer) DialWithOptions(ctx context.Context, target model.Target, _ analyzer.DialOptions) (analyzer.Session, error) {
	return d.Dial(ctx, target)
}

type toolsListFailDialer struct{ err error }

func (d toolsListFailDialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	return toolsListFailSession{err: d.err}, nil
}

func (d toolsListFailDialer) DialWithOptions(ctx context.Context, target model.Target, _ analyzer.DialOptions) (analyzer.Session, error) {
	return d.Dial(ctx, target)
}

type toolsListFailSession struct{ err error }

func (toolsListFailSession) Snapshot() *model.Snapshot { return nil }
func (s toolsListFailSession) Call(context.Context, string, any) (json.RawMessage, error) {
	return nil, s.err
}
func (s toolsListFailSession) CallTool(context.Context, string, map[string]any) (*analyzer.ToolCallResult, error) {
	return nil, s.err
}
func (s toolsListFailSession) ReadResource(context.Context, string) (*analyzer.ResourceContent, error) {
	return nil, s.err
}
func (toolsListFailSession) SessionID() string { return "" }
func (toolsListFailSession) Close() error      { return nil }

func dialFullMatrixContext(d analyzer.Dialer) *analyzer.AnalysisContext {
	ac := testContext(d, analyzer.ProbeToolCalls, fullTokenSet(), []string{"whoami"})
	ac.Options["auth"]["identity_tool"] = "whoami"
	return ac
}

// unreachableTarget is loopback with nothing listening: local, immediate,
// no DNS lookup and no chance of touching the real network, the same target
// TestAnalyzeSkipsWhenNoDialer uses
var unreachableTarget = model.Target{Kind: model.TargetRemote, URL: "http://127.0.0.1:1"}

func assertCannotProduceSafe(t *testing.T, res model.AnalyzerResult) {
	t.Helper()
	res.Required = true
	sr := &model.ScanResult{Analyzers: []model.AnalyzerResult{res}}
	sr.Aggregate(model.DefaultBlockingSeverity)
	if sr.Verdict == model.VerdictSafe {
		t.Fatalf("aggregation produced SAFE from an inconclusive auth result: status=%s coverage=%+v", res.Status, res.Coverage)
	}
}

func TestAuthClassifiesStatusCodes(t *testing.T) {
	cases := []struct {
		status   int
		rejected bool
	}{
		{http.StatusBadRequest, true},
		{http.StatusUnauthorized, true},
		{http.StatusForbidden, true},
		{http.StatusNotFound, false},
		{http.StatusRequestTimeout, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("status_%d", tc.status), func(t *testing.T) {
			d := failDialer{err: &statusErr{code: tc.status, msg: "response"}}
			res := New().Analyze(context.Background(), unreachableTarget, dialFullMatrixContext(d))
			if tc.rejected {
				if res.Status != model.AnalyzerCompleted {
					t.Fatalf("status %d carries an auth/session decision and must still let the analyzer complete, got %s (skip reasons: %v)",
						tc.status, res.Status, res.Coverage.SkipReasons)
				}
				if len(res.Findings) != 0 {
					t.Fatalf("a clean rejection is not a vulnerability, got findings: %+v", res.Findings)
				}
				if gaps := res.Coverage.Gaps(); len(gaps) != 0 {
					t.Fatalf("coverage does not add up: %v", gaps)
				}
				return
			}
			if res.Status == model.AnalyzerCompleted {
				t.Fatalf("status %d answers a different question than the credential being probed and must not let the analyzer report COMPLETED, got %s",
					tc.status, res.Status)
			}
			assertCannotProduceSafe(t, res)
		})
	}
}

func TestAuthGenericDialFailureDoesNotComplete(t *testing.T) {
	d := failDialer{err: errors.New("connection reset by peer")}
	res := New().Analyze(context.Background(), unreachableTarget, dialFullMatrixContext(d))
	if res.Status == model.AnalyzerCompleted {
		t.Fatalf("a generic dial failure on every probe must not let the analyzer report COMPLETED, got %s", res.Status)
	}
	assertCannotProduceSafe(t, res)
}

func TestAuthTimeoutDoesNotComplete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	res := New().Analyze(ctx, unreachableTarget, dialFullMatrixContext(timeoutDialer{}))
	if res.Status == model.AnalyzerCompleted {
		t.Fatalf("a target that never answers must not let the analyzer report COMPLETED, got %s", res.Status)
	}
	assertCannotProduceSafe(t, res)
}

func TestAuthToolsListFailureDoesNotComplete(t *testing.T) {
	d := toolsListFailDialer{err: errors.New("stream reset")}
	res := New().Analyze(context.Background(), unreachableTarget, dialFullMatrixContext(d))
	if res.Status == model.AnalyzerCompleted {
		t.Fatalf("a broken tools/list channel on every probe must not let the analyzer report COMPLETED, got %s", res.Status)
	}
	assertCannotProduceSafe(t, res)
}

// notFoundUnlessValid returns 404 for invalid tokens and passes the valid token to a real server
type notFoundUnlessValid struct{ valid string }

func (d notFoundUnlessValid) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	return d.DialWithOptions(ctx, target, analyzer.DialOptions{})
}

func (d notFoundUnlessValid) DialWithOptions(ctx context.Context, target model.Target, opts analyzer.DialOptions) (analyzer.Session, error) {
	if target.Headers["Authorization"] != "Bearer "+d.valid {
		return nil, &statusErr{code: http.StatusNotFound, msg: "404 page not found"}
	}
	return tauth.HTTPDialer{}.DialWithOptions(ctx, target, opts)
}

// A 404 does not prove that a bad credential was checked, so those probes remain inconclusive
func TestNotFoundForBadCredentialsIsNotABoundaryHeld(t *testing.T) {
	srv := tauth.New(tauth.Secure())
	defer srv.Close()

	tokens := fullTokenSet()
	// Leave excessive_scope out because it has a separate inconclusive path
	delete(tokens, "excessive_scope")
	ac := testContext(notFoundUnlessValid{valid: tokens["valid"].(string)}, analyzer.ProbeSafe, tokens, nil)
	res := newTestAnalyzer().Analyze(context.Background(), model.Target{Kind: model.TargetRemote, URL: srv.URL}, ac)
	if res.Status != model.AnalyzerPartial {
		t.Fatalf("status = %s, want PARTIAL (skips %v)", res.Status, res.Coverage.SkipReasons)
	}
	assertCannotProduceSafe(t, res)
}
