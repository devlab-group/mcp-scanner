package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/revinand/mcp-scanner/internal/mcp/transport"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// fallbackProtocolVersion is used to open the raw probe channel's handshake
// when there is no primary session to copy a negotiated version from (for
// example a session built straight from a fresh Dial for probing)
const fallbackProtocolVersion = "2025-06-18"

// ErrToolCallNotAllowed is returned by Session.CallTool when the scan's
// Options did not grant permission to call the named tool
var ErrToolCallNotAllowed = errors.New("tool call not allowed")

// session implements analyzer.Session over a primary go-sdk ClientSession plus a lazily-opened
// raw JSON-RPC channel for probes. Keeping them independent lets a malformed raw probe kill its
// channel without automatically taking down the session other analyzers still use.
type session struct {
	target model.Target
	kind   string // resolved transport kind: transport.KindStdio | KindStreamable | KindSSE
	policy transport.Policy

	// probes and allowedToolCalls are copied from the Options the session was
	// dialed with. CallTool checks them directly - the session that grants
	// access to a tool is the one place that has to agree to run it, rather
	// than trusting a mark any caller could set on the context.
	probes           analyzer.ProbeLevel
	allowedToolCalls []string

	primary *mcp.ClientSession
	snap    *model.Snapshot

	// resumedID is set when this session was opened by resuming an id the caller already held
	// instead of by a handshake
	resumedID string

	mu  sync.Mutex
	raw *rawConn
}

var _ analyzer.Session = (*session)(nil)

func (s *session) Snapshot() *model.Snapshot { return s.snap }

func (s *session) SessionID() string {
	if s.resumedID != "" {
		return s.resumedID
	}
	if s.primary == nil {
		return ""
	}
	return s.primary.ID()
}

func (s *session) Close() error {
	s.mu.Lock()
	raw := s.raw
	s.raw = nil
	s.mu.Unlock()
	if raw != nil {
		raw.close()
	}
	if s.primary != nil {
		return s.primary.Close()
	}
	return nil
}

func (s *session) CallTool(ctx context.Context, name string, args map[string]any) (*analyzer.ToolCallResult, error) {
	if !analyzer.ToolCallAllowed(s.probes, s.allowedToolCalls, name) {
		return nil, ErrToolCallNotAllowed
	}
	if s.primary == nil && s.resumedID != "" {
		// A resumed session is a raw channel with no handshake behind it, which is the point of it
		// - but tools/call is an ordinary request and the channel can carry one
		raw, err := s.Call(ctx, "tools/call", &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			return nil, err
		}
		var res mcp.CallToolResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, err
		}
		return toolCallResult(&res), nil
	}
	if s.primary == nil {
		return nil, errors.New("no live session")
	}
	res, err := s.primary.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return nil, err
	}
	return toolCallResult(res), nil
}

func (s *session) ReadResource(ctx context.Context, uri string) (*analyzer.ResourceContent, error) {
	if s.primary == nil {
		return nil, errors.New("no live session")
	}
	res, err := s.primary.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
	if err != nil {
		return nil, err
	}
	out := &analyzer.ResourceContent{URI: uri}
	if len(res.Contents) > 0 {
		c := res.Contents[0]
		out.URI = c.URI
		out.MIMEType = c.MIMEType
		out.Text = c.Text
		out.Blob = c.Blob
	}
	return out, nil
}

// Call sends a raw JSON-RPC request over the probe channel. A method of "initialize" is
// special-cased: it always dials a fresh, not-yet-initialized connection and sends exactly
// the params given, then discards the connection.
func (s *session) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if method == "initialize" {
		return s.callFreshInitialize(ctx, params)
	}
	rc, err := s.ensureRaw(ctx)
	if err != nil {
		return nil, err
	}
	res, err := rc.call(ctx, method, params)
	if err != nil {
		if _, ok := errors.AsType[*analyzer.ProtocolError](err); !ok {
			// Not a clean protocol rejection: the channel itself is dead. Drop it so the next call
			// reconnects instead of reusing a broken connection - and close it, because readLoop reads
			// with a background context and only close() unblocks it.
			s.mu.Lock()
			dropped := s.raw == rc
			if dropped {
				s.raw = nil
			}
			s.mu.Unlock()
			if dropped {
				_ = rc.close()
			}
		}
		return nil, err
	}
	return res, nil
}

func (s *session) callFreshInitialize(ctx context.Context, params any) (json.RawMessage, error) {
	// The redirect guard and origin-gated headers apply here exactly as they
	// do on the primary session; only the *RedirectAttempts report is
	// discarded; a probe's own outcome already covers a redirected response
	tr, _, err := transport.New(s.target, s.kind, s.policy)
	if err != nil {
		return nil, err
	}
	rc, err := dialRaw(ctx, tr)
	if err != nil {
		return nil, err
	}
	defer rc.close()
	return rc.call(ctx, "initialize", params)
}

// ensureRaw returns the cached probe channel, opening and handshaking a new
// one if there is none
func (s *session) ensureRaw(ctx context.Context) (*rawConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.raw != nil {
		return s.raw, nil
	}
	if s.resumedID != "" {
		// A resumed session's channel is opened once, at dial time, and
		// never handshaked. Reaching here means it was dropped after a
		// failure, and re-opening it with a handshake below would quietly
		// answer a different question than the one being asked.
		return nil, fmt.Errorf("the resumed session channel is closed")
	}
	tr, _, err := transport.New(s.target, s.kind, s.policy)
	if err != nil {
		return nil, err
	}
	rc, err := dialRaw(ctx, tr)
	if err != nil {
		return nil, err
	}
	initParams := &mcp.InitializeParams{
		// Deliberately not the primary session's negotiated version: the newest protocol (SEP-2575)
		// maps some JSON-RPC error codes onto HTTP status codes over Streamable HTTP, and the SDK's
		// own client treats a bare 404 as "session missing" before it ever looks at the body -
		// which is exactly the status method-not-found maps to
		ProtocolVersion: fallbackProtocolVersion,
		ClientInfo:      &mcp.Implementation{Name: "mcp-scanner-probe", Version: "dev"},
		Capabilities:    &mcp.ClientCapabilities{},
	}
	if _, err := rc.call(ctx, "initialize", initParams); err != nil {
		rc.close()
		return nil, fmt.Errorf("probe channel handshake: %w", err)
	}
	if err := rc.notify(ctx, "notifications/initialized", &mcp.InitializedParams{}); err != nil {
		rc.close()
		return nil, fmt.Errorf("probe channel handshake: %w", err)
	}
	s.raw = rc
	return rc, nil
}

func toolCallResult(res *mcp.CallToolResult) *analyzer.ToolCallResult {
	out := &analyzer.ToolCallResult{IsError: res.IsError}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			out.Text = append(out.Text, tc.Text)
		}
	}
	if res.StructuredContent != nil {
		if b, err := json.Marshal(res.StructuredContent); err == nil {
			out.Structured = b
		}
	}
	if b, err := json.Marshal(res); err == nil {
		out.Raw = b
	}
	return out
}
