package client

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/revinand/mcp-scanner/internal/mcp/discovery"
	"github.com/revinand/mcp-scanner/internal/mcp/transport"
	"github.com/revinand/mcp-scanner/pkg/model"
)

var scannerImpl = &mcp.Implementation{Name: "mcp-scanner", Version: "dev"}

// allowPrivateNetworksForTests is a process-wide escape hatch for this package's own tests,
// which necessarily point at an httptest.Server (always loopback). The real route for a
// caller who wants to scan a private target is Options.AllowPrivateNetworks; this is only a
// fallback for tests that build a Policy without going through Options at all.
var allowPrivateNetworksForTests = false

// AllowPrivateNetworksForTesting disables the scanner's own SSRF guard
// (internal/mcp/transport.Policy) for the lifetime of the process, for tests that do not
// construct an Options value directly. Production callers must use Options.AllowPrivateNetworks;
// this process-wide escape hatch must never be enabled outside a test binary.
func AllowPrivateNetworksForTesting() {
	allowPrivateNetworksForTests = true
}

// policy builds the transport.Policy for a connection: private networks are
// allowed when the caller asked for them via Options, or when a test flipped
// the process-wide testing override
func (o Options) policy() transport.Policy {
	return transport.Policy{AllowPrivateNetworks: o.AllowPrivateNetworks || allowPrivateNetworksForTests}
}

// ValidateTransport rejects an unknown transport name before a connection attempt. The "auto"
// value is valid because only dialing can determine whether a remote server speaks Streamable HTTP
// or SSE.
func ValidateTransport(s string) error {
	_, err := candidateKinds(model.Target{Kind: model.TargetRemote}, s)
	return err
}

func candidateKinds(target model.Target, requested string) ([]string, error) {
	if target.Kind == model.TargetStdio {
		return []string{transport.KindStdio}, nil
	}
	switch requested {
	case "", "auto":
		return []string{transport.KindStreamable, transport.KindSSE}, nil
	case "streamable":
		return []string{transport.KindStreamable}, nil
	case "sse":
		return []string{transport.KindSSE}, nil
	case "stdio":
		return []string{transport.KindStdio}, nil
	default:
		return nil, fmt.Errorf("unknown transport %q", requested)
	}
}

// connect opens the primary session, trying each candidate transport kind in order and
// recording which one worked. The returned *transport.RedirectAttempts stays live for the
// session's HTTP client, so the caller can drain it after discovery too - a redirect can
// just as easily be attempted on a later tools/list as on the initial handshake.
func connect(ctx context.Context, target model.Target, opts Options) (cs *mcp.ClientSession, kind string, attempts *transport.RedirectAttempts, authChallenge string, err error) {
	target.Headers = mergeHeaders(target.Headers, opts.Headers)

	// The target's transport overrides the dialer's default. An explicit transport produces one
	// candidate and never falls back; only "auto" tries Streamable HTTP and then SSE.
	requested := target.Transport
	if requested == "" {
		requested = opts.Transport
	}
	kinds, err := candidateKinds(target, requested)
	if err != nil {
		return nil, "", nil, "", err
	}
	policy := opts.policy()
	mc := mcp.NewClient(scannerImpl, &mcp.ClientOptions{Logger: opts.logger()})

	var lastErr error
	for _, k := range kinds {
		tr, att, berr := transport.New(target, k, policy)
		if berr != nil {
			lastErr = berr
			continue
		}
		sniff := snoopStatus(tr)
		cctx, cancel := context.WithTimeout(ctx, opts.timeout())
		cs, cerr := mc.Connect(cctx, tr, nil)
		cancel()
		if cerr == nil {
			return cs, k, att, sniff.authHeader(), nil
		}
		lastErr = classifyDialErr(cerr, sniff.status.Load())
	}
	lastErr = explainStdioFailure(target, lastErr)
	return nil, "", nil, "", fmt.Errorf("connecting to %s: %w", target.Describe(), redactErr(target, lastErr))
}

// explainStdioFailure adds the restricted-environment hint to every stdio failure except exec.Error,
// timeout, and cancellation. The child inherits only PATH plus explicitly configured variables, so
// a plain EOF may hide the reason.
func explainStdioFailure(target model.Target, err error) error {
	if target.Kind != model.TargetStdio || err == nil {
		return err
	}
	if _, ok := errors.AsType[*exec.Error](err); ok {
		return err
	}
	// A deadline or a cancellation is the scanner running out of time, not the child giving up
	// on its environment
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("%w (the scanner does not forward HOME or the rest of the operator's "+
		"environment into a stdio target's child process, by design; some servers exit "+
		"immediately without HOME - set it in the target's declared env, such as an MCP "+
		"client config's \"env\" block, if you accept that risk)", err)
}

// redactErr strips target.URL's credential out of an error a transport returned, matching
// what target.Describe() already does for its label. net/http errors retain the raw URL in their
// chain, so both the typed field and any formatted occurrence must be scrubbed.
func redactErr(target model.Target, err error) error {
	if err == nil || target.URL == "" {
		return err
	}
	redacted := target.RedactedURL()
	if redacted == target.URL {
		return err // nothing to redact, and no reason to remake the error
	}
	if uerr, ok := errors.AsType[*url.Error](err); ok {
		uerr.URL = redacted
	}
	if msg := err.Error(); strings.Contains(msg, target.URL) {
		return redactedError{msg: strings.ReplaceAll(msg, target.URL, redacted), err: err}
	}
	return err
}

// redactedError presents a scrubbed message while keeping the original
// chain reachable, so errors.Is and errors.As go on working - a caller
// classifying a timeout should not get a different answer because the URL
// happened to contain a credential
type redactedError struct {
	msg string
	err error
}

func (e redactedError) Error() string { return e.msg }
func (e redactedError) Unwrap() error { return e.err }

func mergeHeaders(targetHeaders, optHeaders map[string]string) map[string]string {
	if len(targetHeaders) == 0 && len(optHeaders) == 0 {
		return nil
	}
	out := make(map[string]string, len(targetHeaders)+len(optHeaders))
	maps.Copy(out, targetHeaders)
	maps.Copy(out, optHeaders)
	return out
}

// dialSession connects and discovers, returning a ready analyzer.Session
func dialSession(ctx context.Context, target model.Target, opts Options) (*session, error) {
	cs, kind, attempts, authChallenge, err := connect(ctx, target, opts)
	if err != nil {
		return nil, err
	}
	snap, err := discovery.Discover(ctx, cs, discovery.Options{
		ReadResources: opts.ReadResources,
		GetPrompts:    opts.GetPrompts,
	})
	if err != nil {
		_ = cs.Close()
		return nil, err
	}
	snap.Transport = transportInfo(kind, target, cs, authChallenge)
	// Drained after discovery, not right after connecting: a redirect can be attempted on a
	// later tools/list just as easily as on the initial handshake
	notes := attempts.Notes()
	snap.RedirectsRefused = append(snap.RedirectsRefused, notes...)
	snap.Warnings = append(snap.Warnings, notes...)

	return &session{
		target:           target,
		kind:             kind,
		policy:           opts.policy(),
		probes:           opts.Probes,
		allowedToolCalls: opts.AllowedToolCalls,
		primary:          cs,
		snap:             snap,
	}, nil
}

func transportInfo(kind string, target model.Target, cs *mcp.ClientSession, authChallenge string) model.TransportInfo {
	info := model.TransportInfo{Kind: kind}
	if authChallenge != "" {
		// Only the one header readiness.authDeclared actually reads, and only the connection
		// response's value - not every header the server ever sends
		info.Headers = map[string]string{"WWW-Authenticate": authChallenge}
	}
	switch kind {
	case transport.KindStreamable, transport.KindSSE:
		// Redacted, because this lands in the snapshot, and the snapshot is
		// serialized into the report and written out whole by the snapshot
		// command. Target.MarshalJSON covers the target's own copy of the
		// URL; this is the second place the same credential reaches a file.
		info.Endpoint = target.RedactedURL()
		info.TLS = isHTTPS(target.URL)
	case transport.KindStdio:
		info.Endpoint = target.Command
	}
	// A transport that never established a session leaves cs nil; the
	// endpoint and TLS facts above are still worth recording
	if cs != nil && cs.ID() != "" {
		// Redacted for the same reason the endpoint above is: this lands in the snapshot, which is
		// serialized into the report and written out whole by the snapshot command
		info.SessionID = redactSessionID(cs.ID())
	}
	return info
}

// redactSessionID keeps enough of a session id to tell two entries in the
// same report apart without keeping enough to resume the session: the same
// shape internal/analyzers/auth uses for the session ids it reports
func redactSessionID(id string) string {
	if len(id) <= 6 {
		return fmt.Sprintf("%s(len=%d)", id, len(id))
	}
	return fmt.Sprintf("%s...(len=%d)", id[:6], len(id))
}

func isHTTPS(rawURL string) bool {
	return len(rawURL) > 8 && rawURL[:8] == "https://"
}
