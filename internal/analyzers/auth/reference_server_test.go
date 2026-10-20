package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/devlab-group/mcp-scanner/internal/mcp/client"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// referenceServer uses the real SDK server so rejection status and session behavior match the
// transport under test. A lighter fake would not exercise the 400/404 distinctions used by auth.
func referenceServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "reference", Version: "0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "whoami", Description: "Report the caller."},
		func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "anon"}}}, nil, nil
		})
	return s
}

func analyzeReference(t *testing.T, h http.Handler) model.AnalyzerResult {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	d := client.NewDialer(client.Options{Timeout: 5 * time.Second, AllowPrivateNetworks: true})
	ac := testContext(d, analyzer.ProbeSafe, map[string]any{"valid": "good", "user_b": "other"}, nil)
	return newTestAnalyzer().Analyze(context.Background(),
		model.Target{Kind: model.TargetRemote, URL: srv.URL}, ac)
}

func getReference(*http.Request) *mcp.Server { return referenceServer() }

func skipReasonFor(res model.AnalyzerResult, caseName string) (string, bool) {
	for _, r := range res.Coverage.SkipReasons {
		if strings.HasPrefix(r, caseName+":") {
			return r, true
		}
	}
	return "", false
}

func TestReferenceStatefulServerCompletes(t *testing.T) {
	res := analyzeReference(t, mcp.NewStreamableHTTPHandler(getReference, nil))
	t.Logf("status=%s findings=%v", res.Status, ruleIDs(res.Findings))
	for _, r := range res.Coverage.SkipReasons {
		t.Logf("skip: %s", r)
	}
	if res.Status != model.AnalyzerCompleted {
		t.Errorf("a spec-conformant server left the analyzer at %s, so every scan of one exits incomplete", res.Status)
	}
}

func TestReferenceStatelessServerHasNoSessionsToReport(t *testing.T) {
	res := analyzeReference(t, mcp.NewStreamableHTTPHandler(getReference, &mcp.StreamableHTTPOptions{Stateless: true}))
	t.Logf("status=%s findings=%v", res.Status, ruleIDs(res.Findings))
	for _, r := range res.Coverage.SkipReasons {
		t.Logf("skip: %s", r)
	}
	for _, f := range res.Findings {
		if f.RuleID == "auth.malformed_session_id_accepted" {
			t.Errorf("a server with no sessions was reported for accepting a malformed session id")
		}
	}
}

func TestReferenceSSEServerHasNoSessionIDToResume(t *testing.T) {
	res := analyzeReference(t, mcp.NewSSEHandler(getReference, nil))
	t.Logf("status=%s findings=%v", res.Status, ruleIDs(res.Findings))
	for _, r := range res.Coverage.SkipReasons {
		t.Logf("skip: %s", r)
	}
	if _, skipped := skipReasonFor(res, "malformed_session_id"); !skipped {
		t.Errorf("the malformed-session-id case was counted as analyzed against a transport that carries no session id")
	}
}

func TestReferenceOpenServerIsOnlyReportedAsOpen(t *testing.T) {
	res := analyzeReference(t, mcp.NewStreamableHTTPHandler(getReference, nil))
	for _, f := range res.Findings {
		if f.RuleID == "auth.session_not_bound_to_user" {
			t.Errorf("a server with no authentication at all was reported at %s for not binding a session to a user", f.Severity)
		}
	}
}
