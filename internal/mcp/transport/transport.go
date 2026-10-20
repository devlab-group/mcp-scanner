package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/devlab-group/mcp-scanner/internal/httpx"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Resolved transport kinds, recorded in model.Snapshot.Transport.Kind
const (
	KindStdio      = "stdio"
	KindStreamable = "streamable-http"
	KindSSE        = "sse"
)

// dialTimeout bounds establishing the TCP/TLS connection, not the lifetime
// of the HTTP client built around it - a Streamable HTTP or SSE session
// needs to stay open for as long as the MCP session does
const dialTimeout = 10 * time.Second

// maxResponseBytes bounds a single non-streaming HTTP response body: a JSON-RPC reply the
// SDK decodes in one shot. This cap applies before discovery can enforce its own per-method
// budgets, so a hostile reply cannot grow memory without bound during decoding.
var maxResponseBytes int64 = 32 * 1024 * 1024

// maxEventStreamBytes bounds total bytes read from one text/event-stream response body over
// its whole lifetime - for legacy SSE, the whole session, since a single GET stays open and
// delivers every server-pushed message. A connection-total budget, not a per-message one:
// see boundedBody for why a per-message cap is not attempted.
var maxEventStreamBytes int64 = 256 * 1024 * 1024

// New builds one explicit transport; callers implement auto detection by trying HTTP
// transports in order. HTTP transports also return a live record of cross-origin redirects
// they refused, including attempts made after the handshake.
func New(target model.Target, kind string, policy Policy) (mcp.Transport, *RedirectAttempts, error) {
	switch kind {
	case KindStdio:
		if target.Command == "" {
			return nil, nil, fmt.Errorf("stdio transport needs a command")
		}
		return stdioTransport(target), nil, nil
	case KindStreamable:
		if err := policy.Check(target.URL); err != nil {
			return nil, nil, err
		}
		client, attempts := httpClient(target, policy)
		return wrapHTTP(&mcp.StreamableClientTransport{Endpoint: target.URL, HTTPClient: client}, client, false), attempts, nil
	case KindSSE:
		if err := policy.Check(target.URL); err != nil {
			return nil, nil, err
		}
		client, attempts := httpClient(target, policy)
		return wrapHTTP(&mcp.SSEClientTransport{Endpoint: target.URL, HTTPClient: client}, client, true), attempts, nil
	default:
		return nil, nil, fmt.Errorf("unknown transport kind %q", kind)
	}
}

// NewWithProposedSessionID builds the same HTTP transport New does, but adds id only to the
// initialize request. A server/discover POST may occur first; inspecting the JSON-RPC method keeps
// it from consuming the one-shot proposal.
func NewWithProposedSessionID(target model.Target, kind string, policy Policy, id string) (mcp.Transport, *RedirectAttempts, error) {
	if kind == KindStdio {
		return nil, nil, fmt.Errorf("a stdio transport has no session id to propose")
	}
	if err := policy.Check(target.URL); err != nil {
		return nil, nil, err
	}
	client, attempts := httpClient(target, policy)
	origin, _ := url.Parse(target.URL)
	client.Transport = &initializeHeader{
		name:   "Mcp-Session-Id",
		value:  id,
		origin: origin,
		base:   client.Transport,
	}
	switch kind {
	case KindStreamable:
		return wrapHTTP(&mcp.StreamableClientTransport{Endpoint: target.URL, HTTPClient: client}, client, false), attempts, nil
	case KindSSE:
		return wrapHTTP(&mcp.SSEClientTransport{Endpoint: target.URL, HTTPClient: client}, client, true), attempts, nil
	default:
		return nil, nil, fmt.Errorf("unknown transport kind %q", kind)
	}
}

// wrapHTTP keeps the transport's HTTP client observable and, for legacy SSE, detaches the event
// stream from the short handshake context. Without the latter, cancelling Connect's timeout
// context would close the stream before discovery sends its first request.
func wrapHTTP(inner mcp.Transport, client *http.Client, detachStream bool) mcp.Transport {
	return &httpTransport{inner: inner, client: client, detachStream: detachStream}
}

type httpTransport struct {
	inner        mcp.Transport
	client       *http.Client
	detachStream bool
}

// HTTPClient hands back the client this transport sends through, so a
// caller can instrument it without knowing the concrete type underneath
func (t *httpTransport) HTTPClient() *http.Client { return t.client }

func (t *httpTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	if !t.detachStream {
		return t.inner.Connect(ctx)
	}
	// The handshake stays bounded by the caller's context - a target that
	// never answers must still time out - but what Connect leaves running
	// is bound to a context of this connection's own, cancelled when the
	// connection closes and not before
	sctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	conn, err := t.inner.Connect(sctx)
	stop()
	if err != nil {
		cancel()
		return nil, err
	}
	return &detachedConn{Connection: conn, cancel: cancel}, nil
}

type detachedConn struct {
	mcp.Connection
	cancel context.CancelFunc
}

func (c *detachedConn) Close() error {
	c.cancel()
	return c.Connection.Close()
}

// maxHandshakePeek bounds how much of a request body is read to decide
// whether it is the handshake. A JSON-RPC initialize is a few hundred bytes;
// anything larger is something else, and is forwarded with its body intact -
// what was read is put back in front of the rest rather than sent on its own.
const maxHandshakePeek = 64 << 10

// initializeHeader sets one header on the initialize request and nowhere else. It identifies
// the handshake from its body because the SDK may send discovery traffic before initialize,
// and it applies only on the target's original origin.
type initializeHeader struct {
	name   string
	value  string
	origin *url.URL
	base   http.RoundTripper

	mu   sync.Mutex
	sent bool
}

func (h *initializeHeader) RoundTrip(req *http.Request) (*http.Response, error) {
	base := h.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.Method != http.MethodPost || h.value == "" || req.Body == nil || !httpx.SameOrigin(h.origin, req.URL) {
		return base.RoundTrip(req)
	}
	h.mu.Lock()
	already := h.sent
	h.mu.Unlock()
	if already {
		return base.RoundTrip(req)
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, maxHandshakePeek+1))
	if err != nil {
		req.Body.Close()
		return nil, err
	}

	out := req.Clone(req.Context())
	if len(body) > maxHandshakePeek {
		// Too large to be a handshake, and too large to have been read whole. Rebuilding the
		// request from the bytes taken so far would send a shorter body than the caller wrote - a
		// well-formed but different request, which is a worse outcome than not looking.
		out.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), req.Body), req.Body}
		return base.RoundTrip(out)
	}

	req.Body.Close()
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }

	if isInitialize(body) {
		h.mu.Lock()
		h.sent = true
		h.mu.Unlock()
		out.Header.Set(h.name, h.value)
	}
	return base.RoundTrip(out)
}

// isInitialize reports whether body is a single JSON-RPC initialize request.
// A batch (a JSON array) decodes to nothing here and is not treated as one.
func isInitialize(body []byte) bool {
	var msg struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return false
	}
	return msg.Method == "initialize"
}

// httpClient builds the client shared by the Streamable HTTP and SSE
// transports: dialing is guarded against the address actually resolved at
// connect time (httpx.Policy.Transport), a cross-origin redirect is refused
// outright, and the target's headers - which may carry a bearer token - are
// only ever attached to a request bound for the target's own origin
func httpClient(target model.Target, policy Policy) (*http.Client, *RedirectAttempts) {
	origin, _ := url.Parse(target.URL)
	attempts := &RedirectAttempts{}
	return &http.Client{
		Transport: originOnly{
			origin:   origin,
			attempts: attempts,
			base: originGatedHeaders{
				headers: target.Headers,
				origin:  origin,
				base:    boundedBody{base: policy.httpx().Transport(dialTimeout)},
			},
		},
		CheckRedirect: attempts.checkRedirect,
	}, attempts
}

// originOnly refuses any request whose URL is not the same origin as the target the
// connection started from, and records the attempt the same way checkRedirect does for a
// 3xx. This also covers absolute endpoint URLs announced inside legacy SSE, which bypass
// net/http's ordinary redirect hook.
type originOnly struct {
	origin   *url.URL
	attempts *RedirectAttempts
	base     http.RoundTripper
}

func (o originOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	if !httpx.SameOrigin(o.origin, req.URL) {
		o.attempts.record(fmt.Sprintf("refused a request to a different origin than the target: %s://%s", req.URL.Scheme, req.URL.Host))
		return nil, fmt.Errorf("refused a request to a different origin than the target")
	}
	base := o.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// boundedBody caps ordinary responses and whole event streams. Exceeding the cap returns an error
// instead of a normal-looking truncated response. A total stream cap avoids duplicating the SDK's
// SSE framing rules while still bounding the largest message the SDK can accumulate.
type boundedBody struct {
	base http.RoundTripper
}

func (b boundedBody) RoundTrip(req *http.Request) (*http.Response, error) {
	base := b.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		resp.Body = http.MaxBytesReader(nil, resp.Body, maxEventStreamBytes)
		return resp, nil
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, maxResponseBytes)
	return resp, nil
}

// originGatedHeaders injects the target's declared headers into a request only when that
// request's URL is the same origin the connection started from. Re-adding Authorization on
// every RoundTrip would otherwise undo net/http's protection on a cross-host redirect.
type originGatedHeaders struct {
	headers map[string]string
	origin  *url.URL
	base    http.RoundTripper
}

func (h originGatedHeaders) RoundTrip(req *http.Request) (*http.Response, error) {
	base := h.base
	if base == nil {
		base = http.DefaultTransport
	}
	if len(h.headers) == 0 || !httpx.SameOrigin(h.origin, req.URL) {
		return base.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	return base.RoundTrip(req)
}

// RedirectAttempts records any cross-origin redirect a target's HTTP-based
// transport was asked to follow and refused. The refusal itself is enforced
// unconditionally (see checkRedirect); this only exists so the attempt is
// visible in a report rather than surfacing as nothing more than a failed
// request.
type RedirectAttempts struct {
	mu    sync.Mutex
	notes []string
}

// Notes returns what was recorded so far, in the order it happened
func (r *RedirectAttempts) Notes() []string {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.notes...)
}

func (r *RedirectAttempts) checkRedirect(req *http.Request, via []*http.Request) error {
	err := httpx.SameOriginRedirect(req, via)
	if err != nil && len(via) > 0 {
		r.record(fmt.Sprintf("refused a cross-origin redirect attempt: %v", err))
	}
	return err
}

// record appends note. A nil receiver is a no-op so a caller that never got
// a *RedirectAttempts (stdio has none) does not need its own nil check.
func (r *RedirectAttempts) record(note string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.notes = append(r.notes, note)
	r.mu.Unlock()
}

// stdioEnvAllowlist is what a stdio target's child process gets beyond what
// it declares itself. It is deliberately short: the scanner must never hand
// a scanned server its own environment, which may hold unrelated secrets.
var stdioEnvAllowlist = []string{"PATH"}

func stdioTransport(target model.Target) *mcp.CommandTransport {
	cmd := exec.Command(target.Command, target.Args...)
	env := make([]string, 0, len(stdioEnvAllowlist)+len(target.Env))
	for _, k := range stdioEnvAllowlist {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	for k, v := range target.Env {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	return &mcp.CommandTransport{Command: cmd}
}
