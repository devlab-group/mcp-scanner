package model

// Snapshot is the scanner's own view of an MCP server, decoupled from the SDK
// types so it can be serialized, hashed, diffed and replayed from testdata
type Snapshot struct {
	SchemaVersion string `json:"schema_version"`

	ServerName      string `json:"server_name,omitempty"`
	ServerVersion   string `json:"server_version,omitempty"`
	ServerTitle     string `json:"server_title,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	Instructions    string `json:"instructions,omitempty"`

	Capabilities map[string]any `json:"capabilities,omitempty"`

	Tools     []ToolInfo     `json:"tools,omitempty"`
	Prompts   []PromptInfo   `json:"prompts,omitempty"`
	Resources []ResourceInfo `json:"resources,omitempty"`
	Templates []ResourceInfo `json:"resource_templates,omitempty"`

	Transport TransportInfo `json:"transport"`

	// Warnings records anything odd seen while building the snapshot, for
	// example a truncated page or a list method the server does not support
	Warnings []string `json:"warnings,omitempty"`

	// Truncated records lists the scanner stopped reading before the server
	// stopped offering. It is a count, not prose, because coverage has to
	// know how much was missed rather than infer it from a warning string.
	// A shortfall the server never revealed is recorded with Unknown set.
	Truncated []Truncation `json:"truncated,omitempty"`

	// RedirectsRefused records redirects refused by the scanner's transport, never text parsed
	// from a server error. An analyzer may therefore treat each entry as an observed fact.
	RedirectsRefused []string `json:"redirects_refused,omitempty"`
}

// Transport kinds. TransportSource marks a snapshot synthesized from source: it contains only
// fields the registration pass resolved. An absent schema, annotation, or instruction is not a
// declaration that the live server omits it.
const (
	TransportStdio      = "stdio"
	TransportStreamable = "streamable-http"
	TransportSSE        = "sse"
	TransportStatic     = "static"
	TransportSource     = "source"
)

// TransportInfo records how the snapshot was obtained
type TransportInfo struct {
	Kind      string `json:"kind"` // stdio | streamable-http | sse | static
	Endpoint  string `json:"endpoint,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	TLS       bool   `json:"tls,omitempty"`
	// Headers holds the response headers explicitly captured for analyzers, such
	// as WWW-Authenticate, not every header the server sent - it comes from
	// a server the scan does not trust, and each value is length-capped at
	// the point it is recorded
	Headers map[string]string `json:"response_headers,omitempty"`
}

// ToolInfo mirrors an MCP tool declaration
type ToolInfo struct {
	Name         string         `json:"name"`
	Title        string         `json:"title,omitempty"`
	Description  string         `json:"description,omitempty"`
	InputSchema  map[string]any `json:"input_schema,omitempty"`
	OutputSchema map[string]any `json:"output_schema,omitempty"`
	Annotations  map[string]any `json:"annotations,omitempty"`
	Meta         map[string]any `json:"meta,omitempty"`
}

// PromptInfo mirrors an MCP prompt declaration
type PromptInfo struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
	// Text is the rendered prompt body, present only when prompts/get ran
	Text string `json:"text,omitempty"`
	// Rendered distinguishes an empty response from a prompt that was never fetched
	Rendered bool `json:"rendered,omitempty"`
	// RenderError records why prompts/get failed for this prompt, when it
	// was attempted. Text empty with RenderError empty means nobody asked;
	// Text empty with RenderError set means the server was asked and
	// refused (a required argument, most often) - the two are different
	// gaps and a reader needs to tell them apart.
	RenderError string `json:"render_error,omitempty"`
	// TextTruncated marks a successful render whose body exceeded the cap
	TextTruncated bool `json:"text_truncated,omitempty"`
}

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// ResourceInfo mirrors an MCP resource or resource template declaration
type ResourceInfo struct {
	URI         string `json:"uri,omitempty"`
	URITemplate string `json:"uri_template,omitempty"`
	Name        string `json:"name,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mime_type,omitempty"`
	// Content is populated only when resources/read was allowed to run
	Content string `json:"content,omitempty"`
	// Fetched reports whether resources/read was attempted and returned
	// successfully for this resource, whatever the body turned out to
	// contain - including an empty one. Same reasoning as
	// PromptInfo.Rendered: Content alone cannot tell "never fetched" apart
	// from "fetched and empty", and an absent field in an older snapshot
	// must decode as the former.
	Fetched bool `json:"fetched,omitempty"`
	// ReadError records why resources/read failed for this resource, when
	// it was attempted - the resource equivalent of PromptInfo.RenderError
	ReadError string `json:"read_error,omitempty"`
	// ContentTruncated reports that Content is not the whole body: it was
	// cut at the scanner's own per-resource cap, or a block of it was binary
	// and went unread beside blocks that did not
	ContentTruncated bool `json:"content_truncated,omitempty"`
}

// Truncation is one list the scanner did not read to the end
type Truncation struct {
	// Method is the list call, for example "tools/list"
	Method string `json:"method"`
	// Read is how many items were taken before stopping
	Read int `json:"read"`
	// Missed is how many are known to remain. Zero with Unknown set means
	// the server was still offering more and never said how many.
	Missed int `json:"missed,omitempty"`
	// Unknown marks a shortfall of unknown size, which is an unexplained gap
	// rather than an accounted-for skip
	Unknown bool `json:"unknown,omitempty"`
	// Reason says why the scanner stopped
	Reason string `json:"reason"`
}

// CapabilityCount is the denominator for capability coverage
func (s *Snapshot) CapabilityCount() int {
	if s == nil {
		return 0
	}
	n := len(s.Tools) + len(s.Prompts) + len(s.Resources) + len(s.Templates)
	if s.Instructions != "" {
		n++
	}
	return n
}
