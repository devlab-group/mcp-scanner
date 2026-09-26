package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/mcp/client"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/testdata/protocol/fixtures"
)

// The session and scanner must receive the same tool-call policy
func TestConnectionAndScanAgreeOnToolCalls(t *testing.T) {
	cfg := config.Defaults()
	cfg.ActiveProbes = string(analyzer.ProbeToolCalls)
	cfg.AllowToolCalls = []string{"whoami"}

	sopts, err := ScanOptions(cfg)
	if err != nil {
		t.Fatalf("ScanOptions: %v", err)
	}
	copts := (&Preparer{cfg: cfg}).clientOptions()

	if copts.Probes != sopts.Probes {
		t.Errorf("the dialer and the scan disagree on the probe level: %q vs %q", copts.Probes, sopts.Probes)
	}
	if len(copts.AllowedToolCalls) != len(sopts.AllowedToolCalls) {
		t.Fatalf("the dialer and the scan disagree on the allowlist: %v vs %v", copts.AllowedToolCalls, sopts.AllowedToolCalls)
	}
	for i := range copts.AllowedToolCalls {
		if copts.AllowedToolCalls[i] != sopts.AllowedToolCalls[i] {
			t.Errorf("allowlist entry %d differs: %q vs %q", i, copts.AllowedToolCalls[i], sopts.AllowedToolCalls[i])
		}
	}

	// Verify the policy decision, not only the copied fields
	if !analyzer.ToolCallAllowed(copts.Probes, copts.AllowedToolCalls, "whoami") {
		t.Error("an allowlisted tool is still refused by a session built from this configuration")
	}
	if analyzer.ToolCallAllowed(copts.Probes, copts.AllowedToolCalls, "not-allowlisted") {
		t.Error("a tool nobody allowlisted was permitted")
	}
}

// Drive the configured policy through a live session and an actual tool call
func TestPrepareWiresToolCallPermissionIntoALiveSession(t *testing.T) {
	srv := fixtures.StreamableHTTPServer(fixtures.WellBehaved())
	defer srv.Close()

	cfg := config.Defaults()
	cfg.ActiveProbes = string(analyzer.ProbeToolCalls)
	cfg.AllowToolCalls = []string{"search"}
	cfg.AllowPrivateNetworks = true // the fixture server is loopback

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ac, cleanup, err := NewPreparer(cfg).Prepare(ctx, model.Target{
		Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer cleanup()
	if ac.Session == nil {
		t.Fatal("Prepare did not wire a live session for a remote target")
	}

	// The fixture response proves the allowlisted request reached the handler
	res, err := ac.Session.CallTool(ctx, "search", map[string]any{"query": "x"})
	if err != nil {
		t.Fatalf("an allowlisted tool call through the config-wired session was refused: %v", err)
	}
	if len(res.Text) != 1 || res.Text[0] != "no results" {
		t.Fatalf("call did not reach the real tool handler: %+v", res)
	}

	// The same session must reject a tool outside the allowlist
	if _, err := ac.Session.CallTool(ctx, "write_note", map[string]any{"text": "hi"}); !errors.Is(err, client.ErrToolCallNotAllowed) {
		t.Fatalf("a non-allowlisted tool call through the config-wired session was not refused: %v", err)
	}
}
