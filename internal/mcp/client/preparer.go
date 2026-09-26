package client

import (
	"context"
	"fmt"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
	"github.com/revinand/mcp-scanner/pkg/scanner"
)

// preparer implements scanner.Preparer
type preparer struct{ opts Options }

// NewPreparer returns a scanner.Preparer that connects to a target, runs
// discovery, and hands back an AnalysisContext with Snapshot, Session and
// Dialer populated. A static target has nothing to connect to and is not
// accepted: its snapshot is read, and bounded, by the caller.
func NewPreparer(opts Options) scanner.Preparer { return preparer{opts: opts} }

func (p preparer) Prepare(ctx context.Context, target model.Target) (*analyzer.AnalysisContext, func(), error) {
	if target.Kind == model.TargetStatic {
		// Reading the file belongs to the caller, which is the layer that can bound it - a snapshot
		// is somebody else's output and reading one whole is an unbounded read
		return nil, nil, fmt.Errorf("a static target's snapshot is read by the caller, not by this preparer")
	}

	sess, err := dialSession(ctx, target, p.opts)
	if err != nil {
		return nil, nil, err
	}
	ac := &analyzer.AnalysisContext{
		Snapshot:             sess.snap,
		Session:              sess,
		Dialer:               NewDialer(p.opts),
		AllowPrivateNetworks: p.opts.AllowPrivateNetworks,
	}
	cleanup := func() { _ = sess.Close() }
	return ac, cleanup, nil
}
