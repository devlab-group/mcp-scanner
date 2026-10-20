package analyzer

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Session is a live MCP connection, reduced to what analyzers need. It exists
// so an analyzer can be tested against a fake without linking the transport
// implementation.
type Session interface {
	// Snapshot returns the discovery snapshot for this session
	Snapshot() *model.Snapshot

	// Call sends a raw JSON-RPC request. Protocol analyzers use it for probes
	// the SDK would refuse to build, such as unknown methods or malformed
	// parameters. It returns the raw result, or a ProtocolError for a
	// well-formed JSON-RPC error response.
	Call(ctx context.Context, method string, params any) (json.RawMessage, error)

	// CallTool invokes a tool. Callers must check AnalysisContext.ToolCallAllowed
	// first; implementations also enforce the allowlist and return
	// ErrToolCallNotAllowed otherwise.
	CallTool(ctx context.Context, name string, args map[string]any) (*ToolCallResult, error)

	// ReadResource fetches a resource by URI
	ReadResource(ctx context.Context, uri string) (*ResourceContent, error)

	// SessionID is the transport session identifier, when the transport has one
	SessionID() string

	Close() error
}

// Dialer opens new sessions to a target. Auth and session-security checks need
// to connect several times with different credentials.
type Dialer interface {
	Dial(ctx context.Context, target model.Target) (Session, error)
}

// DialOptions carries the two off-spec connection shapes the session checks need. At most one
// may be set, and the dialer must express it on the wire rather than as a test-only convention.
type DialOptions struct {
	// ResumeSessionID sends this id on every request and skips the
	// handshake, the way a client reconnecting to a session it already
	// holds does. It is what asks "does this server honour an id it should
	// not" - a foreign, closed or malformed one - rather than "what does
	// this server do when initialize carries a strange header".
	ResumeSessionID string

	// ProposeSessionID sends this id as Mcp-Session-Id on the handshake
	// itself and on no later request, so the answer says whether the server
	// adopts an id the client chose instead of minting its own
	ProposeSessionID string
}

// SessionDialer is a Dialer that can also open the session shapes in
// DialOptions. A Dialer that cannot honour a set option must return
// ErrDialOptionUnsupported rather than quietly dialing without it: a probe
// that reports on a connection it did not actually make is worse than one
// that says it could not be made.
type SessionDialer interface {
	Dialer
	DialWithOptions(ctx context.Context, target model.Target, opts DialOptions) (Session, error)
}

// ErrDialOptionUnsupported reports that a Dialer cannot open the session
// shape a caller asked for. Callers treat it as "this check could not run"
// rather than as "this check passed".
var ErrDialOptionUnsupported = errors.New("dialer does not support this session option")

// ToolCallResult is a tool invocation outcome
type ToolCallResult struct {
	Text       []string        `json:"text,omitempty"`
	IsError    bool            `json:"is_error"`
	Structured json.RawMessage `json:"structured,omitempty"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

// ResourceContent is the payload of resources/read
type ResourceContent struct {
	URI      string `json:"uri"`
	MIMEType string `json:"mime_type,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     []byte `json:"-"`
}

// ProtocolError is a JSON-RPC error returned by the peer. Analyzers inspect
// the code to tell "correctly rejected" from "crashed".
type ProtocolError struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *ProtocolError) Error() string { return e.Message }

// RuntimeExecutor runs a target inside a sandbox and reports what it did.
// Analyzers use it to turn a static suspicion into a confirmed finding.
type RuntimeExecutor interface {
	// Available reports whether a sandbox backend is usable right now
	Available(ctx context.Context) error
	Execute(ctx context.Context, req RuntimeRequest) RuntimeResult
}

// RuntimeRequest describes one sandboxed execution
type RuntimeRequest struct {
	Target model.Target

	// Tool and Arguments invoke a specific MCP capability inside the sandbox
	Tool      string
	Arguments map[string]any

	Timeout time.Duration

	// Canaries are the fake secrets and files planted in the sandbox. Reading
	// or exfiltrating one is the signal.
	Canaries []Canary
}

// Canary is a planted fake secret. Values are always synthetic
type Canary struct {
	ID    string
	Path  string // where it is planted in the sandbox
	Env   string // environment variable name, if planted as one
	Value string // the synthetic value to watch for
	Kind  string // aws_key | ssh_key | api_token | db_password | file

	// Content is the full file body to plant at Path, when it differs from
	// Value - an AWS credentials file or a netrc entry carries the secret
	// wrapped in the format a real parser expects, not the bare secret. A
	// canary with no Content plants Value itself, unchanged.
	Content string
}

// RuntimeResult is what the sandbox observed
type RuntimeResult struct {
	Started  bool
	ExitCode int
	TimedOut bool
	Stdout   string
	Stderr   string

	// Answered reports a JSON-RPC result or error for tools/call on stdout. An initialization
	// reply alone does not count.
	Answered bool

	Observations []Observation

	// Err is set when the sandbox itself failed, which is different from the
	// sandboxed process failing
	Err error
}

// Observation is one thing the sandbox saw the target do
type Observation struct {
	Kind     string         `json:"kind"` // process_exec | file_read | file_write | net_connect | dns_query | canary_hit
	Detail   string         `json:"detail"`
	CanaryID string         `json:"canary_id,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

// Hit reports whether any observation of the given kind was recorded
func (r RuntimeResult) Hit(kind string) bool {
	for _, o := range r.Observations {
		if o.Kind == kind {
			return true
		}
	}
	return false
}

// ModelCapabilities describes what parameters a model actually accepts, so an
// adapter never sends a field the endpoint will reject
type ModelCapabilities struct {
	SupportsTemperature bool
	SupportsJSONSchema  bool
	SupportsJSONMode    bool
	SupportsSeed        bool
	SupportsSystemRole  bool
	MaxInputTokens      int
}

// LLMClient is the semantic-analysis backend.
//
// The content handed to it is untrusted, so implementations must not expose
// tools, filesystem access or MCP access to the model.
type LLMClient interface {
	Name() string
	Model() string
	Capabilities() ModelCapabilities
	Complete(ctx context.Context, req LLMRequest) (LLMResponse, error)
}

// LLMRequest is a single completion. Schema, when set and supported, asks for
// structured output.
type LLMRequest struct {
	System      string
	User        string
	Schema      json.RawMessage
	MaxTokens   int
	Temperature *float64
}

// LLMResponse is a completion result
type LLMResponse struct {
	Text         string
	InputTokens  int
	OutputTokens int
	Truncated    bool
}
