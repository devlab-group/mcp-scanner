package client

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/revinand/mcp-scanner/internal/mcp/transport"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

var _ analyzer.SessionDialer = dialer{}

// DialWithOptions opens one of the two off-spec session shapes the auth analyzer's session
// checks need. The options must alter the real wire handshake; storing a private header only in
// a test double would make every probe an ordinary connection and answer the wrong question.
func (d dialer) DialWithOptions(ctx context.Context, target model.Target, opts analyzer.DialOptions) (analyzer.Session, error) {
	switch {
	case opts.ResumeSessionID != "" && opts.ProposeSessionID != "":
		return nil, fmt.Errorf("%w: resume and propose are different probes and cannot be combined", analyzer.ErrDialOptionUnsupported)
	case opts.ResumeSessionID != "":
		return d.resume(ctx, target, opts.ResumeSessionID)
	case opts.ProposeSessionID != "":
		return d.propose(ctx, target, opts.ProposeSessionID)
	default:
		return dialSession(ctx, target, d.opts)
	}
}

// resume opens a channel that sends the given session id on every request and never runs a
// handshake, the way a client reconnecting to a session it already holds behaves
func (d dialer) resume(ctx context.Context, target model.Target, id string) (analyzer.Session, error) {
	if target.Kind == model.TargetStdio {
		return nil, fmt.Errorf("%w: a stdio transport has no session to resume", analyzer.ErrDialOptionUnsupported)
	}
	t := target
	t.Headers = withHeader(mergeHeaders(target.Headers, d.opts.Headers), "Mcp-Session-Id", id)

	kinds, err := candidateKinds(t, transportOf(t, d.opts))
	if err != nil {
		return nil, err
	}
	policy := d.opts.policy()
	var lastErr error
	for _, k := range kinds {
		if k == transport.KindSSE {
			// Legacy SSE has no Mcp-Session-Id to resume: the session is
			// the event stream and its identity lives in the endpoint URL.
			// Sending the header anyway gets an ordinary answer to an
			// ordinary request, and whatever the caller concludes from that
			// is about something else entirely.
			lastErr = fmt.Errorf("%w: legacy SSE carries no session id to resume", analyzer.ErrDialOptionUnsupported)
			continue
		}
		tr, _, berr := transport.New(t, k, policy)
		if berr != nil {
			lastErr = berr
			continue
		}
		rc, cerr := dialRaw(ctx, tr)
		if cerr != nil {
			lastErr = cerr
			continue
		}
		return &session{
			target:           t,
			kind:             k,
			policy:           policy,
			probes:           d.opts.Probes,
			allowedToolCalls: d.opts.AllowedToolCalls,
			snap:             &model.Snapshot{Transport: model.TransportInfo{Kind: k}},
			raw:              rc,
			resumedID:        id,
		}, nil
	}
	if errors.Is(lastErr, analyzer.ErrDialOptionUnsupported) {
		return nil, lastErr
	}
	return nil, fmt.Errorf("resuming session on %s: %w", t.Describe(), redactErr(t, lastErr))
}

// propose runs an ordinary handshake with the given id in Mcp-Session-Id on
// that request alone. Whether the server hands the same id back is the whole
// answer: a server that mints its own is behaving, one that adopts the
// client's has let the client fix the session.
func (d dialer) propose(ctx context.Context, target model.Target, id string) (analyzer.Session, error) {
	if target.Kind == model.TargetStdio {
		return nil, fmt.Errorf("%w: a stdio transport has no session id to propose", analyzer.ErrDialOptionUnsupported)
	}
	t := target
	t.Headers = mergeHeaders(target.Headers, d.opts.Headers)

	kinds, err := candidateKinds(t, transportOf(t, d.opts))
	if err != nil {
		return nil, err
	}
	policy := d.opts.policy()
	mc := mcp.NewClient(scannerImpl, &mcp.ClientOptions{Logger: d.opts.logger()})

	var lastErr error
	for _, k := range kinds {
		tr, _, berr := transport.NewWithProposedSessionID(t, k, policy, id)
		if berr != nil {
			lastErr = berr
			continue
		}
		sniff := snoopStatus(tr)
		cctx, cancel := context.WithTimeout(ctx, d.opts.timeout())
		cs, cerr := mc.Connect(cctx, tr, nil)
		cancel()
		if cerr != nil {
			lastErr = classifyDialErr(cerr, sniff.status.Load())
			continue
		}
		// Deliberately no discovery: the answer is in the session id the
		// handshake produced, and a probe that listed the whole server
		// would be doing work the scan has already done
		return &session{
			target:           t,
			kind:             k,
			policy:           policy,
			probes:           d.opts.Probes,
			allowedToolCalls: d.opts.AllowedToolCalls,
			primary:          cs,
			snap:             &model.Snapshot{Transport: transportInfo(k, t, cs, sniff.authHeader())},
		}, nil
	}
	return nil, fmt.Errorf("proposing a session id to %s: %w", t.Describe(), redactErr(t, lastErr))
}

// transportOf repeats connect's precedence so a probe dials the same
// transport the scan itself would
func transportOf(target model.Target, opts Options) string {
	if target.Transport != "" {
		return target.Transport
	}
	return opts.Transport
}

func withHeader(h map[string]string, name, value string) map[string]string {
	out := map[string]string{}
	maps.Copy(out, h)
	out[name] = value
	return out
}
