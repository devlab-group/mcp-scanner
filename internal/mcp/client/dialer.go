package client

import (
	"context"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// dialer implements analyzer.Dialer
type dialer struct{ opts Options }

// NewDialer returns an analyzer.Dialer that opens a fresh session to a
// target. Analyzers use it to reconnect with different credentials, or to
// recover after a probe kills the primary session.
func NewDialer(opts Options) analyzer.Dialer { return dialer{opts: opts} }

func (d dialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	return dialSession(ctx, target, d.opts)
}

// WithoutContentFetch returns a Dialer equivalent to d but with resource and prompt content
// fetches (resources/read, prompts/get) turned off during discovery. Authentication probes need
// connection semantics, not dozens of repeated reads each time they open a fresh session.
func WithoutContentFetch(d analyzer.Dialer) analyzer.Dialer {
	cd, ok := d.(dialer)
	if !ok {
		return d
	}
	opts := cd.opts
	opts.ReadResources = false
	opts.GetPrompts = false
	return dialer{opts: opts}
}
