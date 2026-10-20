package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// ProposedSessionIDHeader distinguishes session resumption from proposing an
// ID during initialization. It selects fixture behavior and never reaches the transport,
// where it could accidentally turn the probe into a different request.
const ProposedSessionIDHeader = "Mcp-Session-Id-Proposed"

// HTTPDialer implements analyzer.Dialer over plain JSON-RPC-over-HTTP, exactly the shape
// the Server in this package speaks. Tests can control policy precisely while still exercising
// a real request/response exchange rather than fake Session behavior.
type HTTPDialer struct{}

var _ analyzer.SessionDialer = HTTPDialer{}

// DialWithOptions implements the same session-probe contract the production connection
// layer does, so the analyzer exercises one code path against both
func (d HTTPDialer) DialWithOptions(ctx context.Context, target model.Target, opts analyzer.DialOptions) (analyzer.Session, error) {
	t := target
	headers := map[string]string{}
	for k, v := range target.Headers {
		headers[k] = v
	}
	switch {
	case opts.ResumeSessionID != "" && opts.ProposeSessionID != "":
		return nil, fmt.Errorf("%w: resume and propose cannot be combined", analyzer.ErrDialOptionUnsupported)
	case opts.ResumeSessionID != "":
		headers["Mcp-Session-Id"] = opts.ResumeSessionID
	case opts.ProposeSessionID != "":
		headers[ProposedSessionIDHeader] = opts.ProposeSessionID
	}
	t.Headers = headers
	return d.Dial(ctx, t)
}

func (HTTPDialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	sess := &httpSession{ctx: ctx, url: target.URL, headers: target.Headers}

	if resume := target.Headers["Mcp-Session-Id"]; resume != "" {
		// The caller already holds a session id - its own, guessed,
		// reused after closing it, or outright malformed - and wants to
		// probe it directly on the first real call, the way a client
		// reconnecting to a live session does not re-run initialize
		sess.sessionID = resume
		return sess, nil
	}

	proposed := target.Headers[ProposedSessionIDHeader]
	sess.sessionID = proposed // sent as this connection's Mcp-Session-Id on the initialize call below
	res, err := sess.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcp-scanner-test", "version": "1.0"},
	})
	if err != nil {
		return nil, err
	}
	if res.header != "" {
		sess.sessionID = res.header
	}
	return sess, nil
}

type httpSession struct {
	ctx       context.Context
	url       string
	headers   map[string]string
	sessionID string
}

type rpcResult struct {
	raw    json.RawMessage
	header string
}

func (s *httpSession) call(ctx context.Context, method string, params any) (rpcResult, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return rpcResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		if k == "Mcp-Session-Id" || k == ProposedSessionIDHeader {
			continue // session id is tracked on the session, not resent verbatim from target.Headers
		}
		req.Header.Set(k, v)
	}
	if s.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", s.sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return rpcResult{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 300 {
		return rpcResult{}, &httpError{status: resp.StatusCode, body: string(b), header: resp.Header.Get("WWW-Authenticate")}
	}

	var parsed struct {
		Result json.RawMessage         `json:"result"`
		Error  *analyzer.ProtocolError `json:"error"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return rpcResult{}, fmt.Errorf("decoding response: %w", err)
	}
	if parsed.Error != nil {
		return rpcResult{}, parsed.Error
	}
	return rpcResult{raw: parsed.Result, header: resp.Header.Get("Mcp-Session-Id")}, nil
}

// httpError carries the HTTP-level rejection (status + WWW-Authenticate)
// that a plain JSON-RPC error cannot: the auth analyzer's evidence needs the
// actual response that came back, and for the matrix cases that is almost
// always an HTTP-layer 401/403, not a JSON-RPC error object
type httpError struct {
	status int
	body   string
	header string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("http %d: %s", e.status, e.body)
}

// Status and WWWAuthenticate let callers that know they are talking to this
// dialer extract HTTP-layer detail; analyzer code goes through the plain
// error interface and just needs to know accepted vs rejected
func (e *httpError) Status() int             { return e.status }
func (e *httpError) WWWAuthenticate() string { return e.header }

func (s *httpSession) Snapshot() *model.Snapshot { return nil }

func (s *httpSession) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	res, err := s.call(ctx, method, params)
	if err != nil {
		return nil, err
	}
	return res.raw, nil
}

func (s *httpSession) CallTool(ctx context.Context, name string, args map[string]any) (*analyzer.ToolCallResult, error) {
	res, err := s.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	json.Unmarshal(res.raw, &parsed)
	out := &analyzer.ToolCallResult{Raw: res.raw}
	for _, c := range parsed.Content {
		out.Text = append(out.Text, c.Text)
	}
	return out, nil
}

func (s *httpSession) ReadResource(ctx context.Context, uri string) (*analyzer.ResourceContent, error) {
	return nil, fmt.Errorf("not supported by the mock auth target")
}

func (s *httpSession) SessionID() string { return s.sessionID }

func (s *httpSession) Close() error {
	req, err := http.NewRequestWithContext(s.ctx, http.MethodDelete, s.url, nil)
	if err != nil {
		return err
	}
	if s.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", s.sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
