// Package client is the wiring seam other packages depend on: it turns a
// model.Target into a live MCP connection (scanner.Preparer, analyzer.Dialer)
// or a replayed one (LoadSnapshotBytes), and implements analyzer.Session on
// top of
// the go-sdk client plus a minimal raw JSON-RPC channel for probes the typed
// SDK client will not build
package client

import (
	"log/slog"
	"time"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
)

// Options configures how the client connects and how much of a server's
// surface it reads
type Options struct {
	Timeout       time.Duration
	Headers       map[string]string
	Transport     string // auto | streamable | sse | stdio
	ReadResources bool
	GetPrompts    bool
	Logger        *slog.Logger

	// AllowPrivateNetworks opts into connecting to a loopback, link-local or
	// private-range target. Off by default: most MCP servers people want to
	// scan for real are on localhost, so this needs a real route rather than
	// only AllowPrivateNetworksForTesting, but the guard still has to default
	// closed for a caller who never asks for it.
	AllowPrivateNetworks bool

	// Probes and AllowedToolCalls are the scan's active-probe policy and tool allowlist
	Probes           analyzer.ProbeLevel
	AllowedToolCalls []string
}

func (o Options) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.New(slog.DiscardHandler)
}

func (o Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return 30 * time.Second
}
