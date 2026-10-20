package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpclient "github.com/devlab-group/mcp-scanner/internal/mcp/client"
	"github.com/devlab-group/mcp-scanner/internal/mcp/discovery"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/testdata/protocol/fixtures"
)

func init() {
	// Every fixture in these tests is an httptest.Server, which is always
	// loopback; see AllowPrivateNetworksForTesting's doc comment
	mcpclient.AllowPrivateNetworksForTesting()
}

func prepareLive(t *testing.T, server *mcp.Server) (*analyzer.AnalysisContext, model.Target, func()) {
	t.Helper()
	srv := fixtures.StreamableHTTPServer(server)
	target := model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"}

	p := mcpclient.NewPreparer(mcpclient.Options{Timeout: 5 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ac, cleanup, err := p.Prepare(ctx, target)
	if err != nil {
		cancel()
		srv.Close()
		t.Fatal(err)
	}
	ac.Probes = analyzer.ProbeSafe
	return ac, target, func() {
		cleanup()
		cancel()
		srv.Close()
	}
}

func prepareLiveWellBehaved(t *testing.T) (*analyzer.AnalysisContext, model.Target, func()) {
	return prepareLive(t, fixtures.WellBehaved())
}

func prepareLiveCapabilityMismatch(t *testing.T) (*analyzer.AnalysisContext, model.Target, func()) {
	return prepareLive(t, fixtures.CapabilityMismatch())
}

func TestAnalyzeWellBehavedProducesOnlyExpectedFindings(t *testing.T) {
	ac, target, cleanup := prepareLiveWellBehaved(t)
	defer cleanup()

	res := protocolAnalyzer{}.Analyze(context.Background(), target, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, warnings = %v", res.Status, res.Warnings)
	}

	if !hasRule(res.Findings, RuleResourceURIUnsafe) {
		t.Fatalf("expected the fixture's non-standard resource scheme to be noted, got %v", res.Findings)
	}

	if !hasRule(res.Findings, RuleProbeAcceptedUnanswered) {
		t.Fatalf("expected the malformed-request probe's unanswered 202 to be noted, got %v", res.Findings)
	}
	for _, f := range res.Findings {
		if f.RuleID != RuleResourceURIUnsafe && f.RuleID != RuleProbeAcceptedUnanswered {
			t.Fatalf("a well-behaved server produced an unrelated finding: %v", res.Findings)
		}
	}
	if res.Coverage.CapabilitiesDiscovered == 0 {
		t.Fatal("coverage reported zero capabilities discovered")
	}
	if res.Coverage.CapabilitiesAnalyzed != res.Coverage.CapabilitiesDiscovered {
		t.Fatalf("coverage = %+v, want analyzed == discovered for a clean run", res.Coverage)
	}
}

func TestAnalyzeCapabilityMismatchFixture(t *testing.T) {
	ac, target, cleanup := prepareLiveCapabilityMismatch(t)
	defer cleanup()

	res := protocolAnalyzer{}.Analyze(context.Background(), target, ac)
	if !hasRule(res.Findings, RuleCapabilityMismatch) {
		t.Fatalf("expected a capability mismatch finding, got %v", res.Findings)
	}
	// Both directions should show up: prompts advertised-but-failing
	// (passive, from the snapshot) and tools answering without being
	// advertised (active probe)
	var passive, active int
	for _, f := range res.Findings {
		if f.RuleID != RuleCapabilityMismatch {
			continue
		}
		if f.EvidenceLevel == model.EvidenceStatic {
			passive++
		}
		if f.EvidenceLevel == model.EvidenceProtocol {
			active++
		}
	}
	if passive == 0 {
		t.Error("expected the passive (advertised but failing) direction to be flagged")
	}
	if active == 0 {
		t.Error("expected the active (answered but not advertised) direction to be flagged")
	}
}

func TestAnalyzeStaticTargetSkipsProbes(t *testing.T) {
	ac := &analyzer.AnalysisContext{
		Snapshot: &model.Snapshot{ServerName: "static", ProtocolVersion: "2025-06-18"},
		Probes:   analyzer.ProbeSafe,
	}
	res := protocolAnalyzer{}.Analyze(context.Background(), model.Target{Kind: model.TargetStatic}, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s", res.Status)
	}
	found := false
	for _, w := range res.Warnings {
		if w == "active probes skipped: no live session (static target or offline scan)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a warning explaining why probes did not run, got %v", res.Warnings)
	}
}

func TestAnalyzeNoSnapshotIsSkipped(t *testing.T) {
	res := protocolAnalyzer{}.Analyze(context.Background(), model.Target{}, &analyzer.AnalysisContext{})
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("status = %s, want SKIPPED", res.Status)
	}
}

func TestAppliesTo(t *testing.T) {
	a := protocolAnalyzer{}
	for _, k := range []model.TargetKind{model.TargetRemote, model.TargetStdio, model.TargetStatic} {
		if !a.AppliesTo(k) {
			t.Errorf("AppliesTo(%s) = false, want true", k)
		}
	}
	for _, k := range []model.TargetKind{model.TargetSource, model.TargetPackage, model.TargetConfig} {
		if a.AppliesTo(k) {
			t.Errorf("AppliesTo(%s) = true, want false", k)
		}
	}
}

func TestDescribe(t *testing.T) {
	d := protocolAnalyzer{}.Describe()
	if d.Name != Name || d.Purpose == "" || !d.Active {
		t.Fatalf("got %+v", d)
	}
}

func TestRegisteredInDefaultRegistry(t *testing.T) {
	if _, ok := analyzer.Default.Get(Name); !ok {
		t.Fatal("protocol analyzer did not register itself via init()")
	}
}

func TestCapabilityCoverageNoTruncationIsComplete(t *testing.T) {
	snap := &model.Snapshot{Tools: []model.ToolInfo{{Name: "a"}, {Name: "b"}}}
	cov := capabilityCoverage(snap)
	if len(cov.Gaps()) != 0 {
		t.Fatalf("a fully-read snapshot has gaps: %v", cov.Gaps())
	}
	if cov.CapabilitiesDiscovered != 2 || cov.CapabilitiesAnalyzed != 2 {
		t.Fatalf("got %+v", cov)
	}
}

func TestCapabilityCoverageKnownShortfallBalances(t *testing.T) {
	snap := &model.Snapshot{
		Tools:     []model.ToolInfo{{Name: "a"}},
		Truncated: []model.Truncation{{Method: "tools/list", Read: 1, Missed: 5, Reason: "server said so"}},
	}
	cov := capabilityCoverage(snap)
	if len(cov.Gaps()) != 0 {
		t.Fatalf("a fully-explained, fully-counted shortfall has gaps: %v", cov.Gaps())
	}
	if cov.CapabilitiesDiscovered != 6 || cov.CapabilitiesAnalyzed != 1 || cov.CapabilitiesSkipped != 5 {
		t.Fatalf("got %+v", cov)
	}
	if len(cov.SkipReasons) == 0 {
		t.Fatal("expected a skip reason naming the known shortfall")
	}
}

func TestCapabilityCoverageUnknownShortfallDoesNotBalance(t *testing.T) {
	snap := &model.Snapshot{
		Tools:     make([]model.ToolInfo, 50),
		Truncated: []model.Truncation{{Method: "tools/list", Read: 50, Unknown: true, Reason: discovery.LimitHitReason + "50-item cap"}},
	}
	cov := capabilityCoverage(snap)
	if len(cov.Gaps()) == 0 {
		t.Fatal("an unknown-size shortfall did not produce a coverage gap")
	}
	if cov.CapabilitiesDiscovered <= cov.CapabilitiesAnalyzed+cov.CapabilitiesSkipped {
		t.Fatalf("an unknown-size shortfall balanced anyway: %+v", cov)
	}
}

func TestCapabilityCoverageRecordsLimitHit(t *testing.T) {
	snap := &model.Snapshot{
		Tools:     make([]model.ToolInfo, 10),
		Truncated: []model.Truncation{{Method: "tools/list", Read: 10, Unknown: true, Reason: discovery.LimitHitReason + "10-item cap"}},
	}
	cov := capabilityCoverage(snap)
	if len(cov.LimitsHit) != 1 {
		t.Fatalf("got %d entries in LimitsHit, want 1: %v", len(cov.LimitsHit), cov.LimitsHit)
	}
	if len(cov.Gaps()) == 0 {
		t.Fatal("a recorded limit hit did not produce a coverage gap")
	}
}

func TestCapabilityCoverageServerCausedShortfallIsNotALimitHit(t *testing.T) {
	snap := &model.Snapshot{
		Tools:     make([]model.ToolInfo, 2),
		Truncated: []model.Truncation{{Method: "tools/list", Read: 2, Unknown: true, Reason: "server returned a pagination cursor it had already returned"}},
	}
	cov := capabilityCoverage(snap)
	if len(cov.LimitsHit) != 0 {
		t.Fatalf("a server-caused shortfall was recorded as a scanner limit: %v", cov.LimitsHit)
	}
	if len(cov.Gaps()) == 0 {
		t.Fatal("a server-caused unknown shortfall did not produce a coverage gap")
	}
}

func liveSnapshot() *model.Snapshot {
	return &model.Snapshot{ServerName: "live", ProtocolVersion: "2025-06-18", Capabilities: map[string]any{
		"tools": map[string]any{}, "prompts": map[string]any{}, "resources": map[string]any{},
	}}
}

// ProbeNone must not send active requests through an open session
func TestAnalyzeSendsNoProbesBelowSafe(t *testing.T) {
	var calls []string
	sess := &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		calls = append(calls, method)
		return json.RawMessage(`{}`), nil
	}}
	ac := &analyzer.AnalysisContext{Snapshot: liveSnapshot(), Session: sess, Probes: analyzer.ProbeNone}
	res := protocolAnalyzer{}.Analyze(context.Background(), model.Target{Kind: model.TargetRemote}, ac)
	if len(calls) != 0 {
		t.Fatalf("probe level none sent %d request(s) to the live session: %v", len(calls), calls)
	}
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED for the passive checks", res.Status)
	}
}

// A probe run that cannot judge every request is partial
func TestAnalyzeIncompleteProbeRunIsPartial(t *testing.T) {
	oldTimeout := probeTimeout
	probeTimeout = 100 * time.Millisecond
	defer func() { probeTimeout = oldTimeout }()

	deadConnection := func() analyzer.Session {
		return &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
			if method == "ping" {
				return nil, errors.New("connection reset")
			}
			return nil, &analyzer.ProtocolError{Code: -32601, Message: "method not found"}
		}}
	}
	healthy := func() analyzer.Session {
		return &fakeSession{callFn: func(ctx context.Context, method string, params any) (json.RawMessage, error) {
			if method == "ping" {
				return json.RawMessage(`{}`), nil
			}
			return nil, &analyzer.ProtocolError{Code: -32601, Message: "method not found"}
		}}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name   string
		ctx    context.Context
		sess   analyzer.Session
		dialer analyzer.Dialer
	}{
		{"connection died and there is no dialer", context.Background(), deadConnection(), nil},
		{"connection died and the redial failed", context.Background(), deadConnection(), &fakeDialer{failAt: 1, newFn: healthy}},
		{"the deadline passed before the probes", cancelled, healthy(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ac := &analyzer.AnalysisContext{Snapshot: liveSnapshot(), Session: tc.sess, Dialer: tc.dialer, Probes: analyzer.ProbeSafe}
			res := protocolAnalyzer{}.Analyze(tc.ctx, model.Target{Kind: model.TargetRemote}, ac)
			if res.Status != model.AnalyzerPartial {
				t.Fatalf("status = %s, want PARTIAL (warnings %v)", res.Status, res.Warnings)
			}
		})
	}
}
