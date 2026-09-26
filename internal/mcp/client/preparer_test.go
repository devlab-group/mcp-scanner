package client

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/testdata/protocol/fixtures"
)

func TestPreparerRefusesAStaticTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	writeSnapshot(t, path, &model.Snapshot{SchemaVersion: model.SchemaVersion, ServerName: "static-server"})

	p := NewPreparer(Options{})
	if _, _, err := p.Prepare(context.Background(), model.Target{Kind: model.TargetStatic, Path: path}); err == nil {
		t.Fatal("a static target was prepared here, which means its file was read without a cap")
	}
}

func TestPreparerRemoteTarget(t *testing.T) {
	srv := fixtures.StreamableHTTPServer(fixtures.WellBehaved())
	defer srv.Close()

	p := NewPreparer(Options{Timeout: 5 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ac, cleanup, err := p.Prepare(ctx, model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if ac.Session == nil {
		t.Fatal("a remote target should get a live Session")
	}
	if ac.Dialer == nil {
		t.Fatal("a remote target should get a Dialer")
	}
	if ac.Snapshot == nil || len(ac.Snapshot.Tools) == 0 {
		t.Fatalf("got %+v", ac.Snapshot)
	}
}

func TestDialerReconnects(t *testing.T) {
	srv := fixtures.StreamableHTTPServer(fixtures.WellBehaved())
	defer srv.Close()

	d := NewDialer(Options{Timeout: 5 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"}
	s1, err := d.Dial(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	s2, err := d.Dial(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	if s1.SessionID() == "" || s2.SessionID() == "" {
		t.Fatal("expected non-empty session ids")
	}
}

func TestPreparerConnectFailureIsAnError(t *testing.T) {
	p := NewPreparer(Options{Timeout: time.Second})
	_, _, err := p.Prepare(context.Background(), model.Target{Kind: model.TargetRemote, URL: "https://127.0.0.1:1/mcp", Transport: "streamable"})
	if err == nil {
		t.Fatal("connecting to a port nothing listens on did not error")
	}
}
