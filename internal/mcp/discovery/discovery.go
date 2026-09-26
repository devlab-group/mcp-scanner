// Package discovery drives the standard MCP discovery methods against an
// initialized session and converts the result into a model.Snapshot
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/revinand/mcp-scanner/pkg/model"
)

// Options controls how much of the server's surface discovery reads beyond
// the declarations themselves. Discovery never calls a tool.
type Options struct {
	// ReadResources, when set, fetches the content of every declared
	// resource (not template) via resources/read
	ReadResources bool
	// GetPrompts, when set, fetches the rendered text of every declared
	// prompt via prompts/get
	GetPrompts bool
	// MaxResourceBytes bounds how much of each resource's content discovery
	// keeps. Zero uses defaultMaxResourceBytes.
	MaxResourceBytes int
	// MaxTotalResourceBytes bounds the combined content kept across every
	// resource read in one discovery pass. Zero uses
	// defaultMaxTotalResourceBytes. The per-resource cap alone does not
	// bound this: a server with enough declared resources, each individually
	// within MaxResourceBytes, still adds up to an unbounded amount held in
	// the snapshot and then serialized into the report.
	MaxTotalResourceBytes int
	// MaxPromptBytes bounds how much of each prompt's rendered text
	// discovery keeps. Zero uses defaultMaxPromptBytes.
	MaxPromptBytes int
	// MaxTotalPromptBytes bounds the combined rendered text kept across
	// every prompt fetched in one discovery pass, for the same reason
	// MaxTotalResourceBytes exists: a server with enough declared prompts,
	// each individually within MaxPromptBytes, still adds up to an unbounded
	// amount held in the snapshot and then serialized into the report
	MaxTotalPromptBytes int
}

const (
	defaultMaxResourceBytes      = 64 * 1024
	defaultMaxTotalResourceBytes = 16 * 1024 * 1024
	defaultMaxPromptBytes        = 64 * 1024
	defaultMaxTotalPromptBytes   = 16 * 1024 * 1024
)

func (o Options) maxResourceBytes() int {
	if o.MaxResourceBytes > 0 {
		return o.MaxResourceBytes
	}
	return defaultMaxResourceBytes
}

func (o Options) maxTotalResourceBytes() int {
	if o.MaxTotalResourceBytes > 0 {
		return o.MaxTotalResourceBytes
	}
	return defaultMaxTotalResourceBytes
}

func (o Options) maxPromptBytes() int {
	if o.MaxPromptBytes > 0 {
		return o.MaxPromptBytes
	}
	return defaultMaxPromptBytes
}

func (o Options) maxTotalPromptBytes() int {
	if o.MaxTotalPromptBytes > 0 {
		return o.MaxTotalPromptBytes
	}
	return defaultMaxTotalPromptBytes
}

// Discover reads the server's declared surface - tools, prompts, resources,
// resource templates, instructions and capabilities - from an initialized
// session and returns the scanner's own view of it
func Discover(ctx context.Context, cs *mcp.ClientSession, opts Options) (*model.Snapshot, error) {
	init := cs.InitializeResult()
	if init == nil {
		return nil, fmt.Errorf("session has no InitializeResult")
	}

	snap := &model.Snapshot{
		SchemaVersion:   model.SchemaVersion,
		ProtocolVersion: init.ProtocolVersion,
		Instructions:    init.Instructions,
		Capabilities:    ToMap(init.Capabilities),
	}
	if init.ServerInfo != nil {
		snap.ServerName = init.ServerInfo.Name
		snap.ServerVersion = init.ServerInfo.Version
		snap.ServerTitle = init.ServerInfo.Title
	}

	caps := init.Capabilities

	if caps != nil && caps.Tools != nil {
		tools, trunc, err := listTools(ctx, cs)
		if err != nil {
			recordListFailure(snap, "tools", "tools/list", err)
		} else {
			snap.Tools = tools
			recordTruncation(snap, trunc)
		}
	} else {
		snap.Warnings = append(snap.Warnings, "server did not advertise the tools capability; tools/list was not attempted")
	}

	if caps != nil && caps.Prompts != nil {
		prompts, trunc, err := listPrompts(ctx, cs)
		if err != nil {
			recordListFailure(snap, "prompts", "prompts/list", err)
		} else {
			snap.Prompts = prompts
			recordTruncation(snap, trunc)
			if opts.GetPrompts {
				getPromptText(ctx, cs, snap, opts.maxPromptBytes(), opts.maxTotalPromptBytes())
			}
		}
	} else {
		snap.Warnings = append(snap.Warnings, "server did not advertise the prompts capability; prompts/list was not attempted")
	}

	if caps != nil && caps.Resources != nil {
		resources, trunc, err := listResources(ctx, cs)
		if err != nil {
			recordListFailure(snap, "resources", "resources/list", err)
		} else {
			snap.Resources = resources
			recordTruncation(snap, trunc)
			if opts.ReadResources {
				readResourceContent(ctx, cs, snap, opts.maxResourceBytes(), opts.maxTotalResourceBytes())
			}
		}
		templates, trunc, err := listResourceTemplates(ctx, cs)
		if err != nil {
			recordListFailure(snap, "resources", "resources/templates/list", err)
		} else {
			snap.Templates = templates
			recordTruncation(snap, trunc)
		}
	} else {
		snap.Warnings = append(snap.Warnings, "server did not advertise the resources capability; resources/list and resources/templates/list were not attempted")
	}

	return snap, nil
}

// recordListFailure adds structured unknown truncation when an advertised list method fails
// before returning anything. A warning string alone is not coverage, so the unknown shortfall
// must remain unbalanced and prevent a clean result.
func recordListFailure(snap *model.Snapshot, capability, method string, err error) {
	snap.Warnings = append(snap.Warnings,
		fmt.Sprintf("server advertised the %s capability but %s failed: %v", capability, method, err))
	snap.Truncated = append(snap.Truncated, model.Truncation{
		Method:  method,
		Read:    0,
		Unknown: true,
		Reason:  fmt.Sprintf("the call failed: %v", err),
	})
}

// recordTruncation folds a list method's truncation, if any, into the
// snapshot: the structured record coverage accounting reads, plus a
// human-readable line alongside it
func recordTruncation(snap *model.Snapshot, t *model.Truncation) {
	if t == nil {
		return
	}
	snap.Truncated = append(snap.Truncated, *t)
	snap.Warnings = append(snap.Warnings, fmt.Sprintf("%s: %s (%d item(s) read)", t.Method, t.Reason, t.Read))
}

// listTools follows tools/list pagination to the end, bounded by paginate's
// caps. If a page fails after some pages already succeeded, what was read is
// kept but flagged as truncated rather than silently passed off as complete.
func listTools(ctx context.Context, cs *mcp.ClientSession) ([]model.ToolInfo, *model.Truncation, error) {
	return paginate(ctx, "tools/list", func(ctx context.Context, cursor string) ([]model.ToolInfo, string, int, error) {
		res, err := cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, "", 0, err
		}
		out := make([]model.ToolInfo, len(res.Tools))
		for i, t := range res.Tools {
			out[i] = ToolInfo(t)
		}
		return out, res.NextCursor, jsonByteEstimate(res.Tools), nil
	})
}

func listPrompts(ctx context.Context, cs *mcp.ClientSession) ([]model.PromptInfo, *model.Truncation, error) {
	return paginate(ctx, "prompts/list", func(ctx context.Context, cursor string) ([]model.PromptInfo, string, int, error) {
		res, err := cs.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
		if err != nil {
			return nil, "", 0, err
		}
		out := make([]model.PromptInfo, len(res.Prompts))
		for i, p := range res.Prompts {
			out[i] = PromptInfo(p)
		}
		return out, res.NextCursor, jsonByteEstimate(res.Prompts), nil
	})
}

func listResources(ctx context.Context, cs *mcp.ClientSession) ([]model.ResourceInfo, *model.Truncation, error) {
	return paginate(ctx, "resources/list", func(ctx context.Context, cursor string) ([]model.ResourceInfo, string, int, error) {
		res, err := cs.ListResources(ctx, &mcp.ListResourcesParams{Cursor: cursor})
		if err != nil {
			return nil, "", 0, err
		}
		out := make([]model.ResourceInfo, len(res.Resources))
		for i, r := range res.Resources {
			out[i] = ResourceInfo(r)
		}
		return out, res.NextCursor, jsonByteEstimate(res.Resources), nil
	})
}

func listResourceTemplates(ctx context.Context, cs *mcp.ClientSession) ([]model.ResourceInfo, *model.Truncation, error) {
	return paginate(ctx, "resources/templates/list", func(ctx context.Context, cursor string) ([]model.ResourceInfo, string, int, error) {
		res, err := cs.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{Cursor: cursor})
		if err != nil {
			return nil, "", 0, err
		}
		out := make([]model.ResourceInfo, len(res.ResourceTemplates))
		for i, r := range res.ResourceTemplates {
			out[i] = TemplateInfo(r)
		}
		return out, res.NextCursor, jsonByteEstimate(res.ResourceTemplates), nil
	})
}

// jsonByteEstimate approximates a page's wire size for the byte cap. The SDK
// has already decoded the page by the time discovery sees it, so this is an
// estimate, not the literal bytes read off the connection - close enough for
// a defensive cap.
func jsonByteEstimate(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// getPromptText renders every declared prompt with no arguments, bounded both per prompt
// (maxBytes) and in total (maxTotalBytes) - the same two budgets readResourceContent
// enforces, for the same reason: enough declared prompts, each within maxBytes, still add
// up to an unbounded amount serialized into the report
func getPromptText(ctx context.Context, cs *mcp.ClientSession, snap *model.Snapshot, maxBytes, maxTotalBytes int) {
	remaining := maxTotalBytes
	for i := range snap.Prompts {
		if remaining <= 0 {
			recordTruncation(snap, &model.Truncation{
				Method:  "prompts/get",
				Read:    i,
				Unknown: true,
				Reason:  LimitHitReason + fmt.Sprintf("%d-byte total content cap", maxTotalBytes),
			})
			return
		}
		name := snap.Prompts[i].Name
		res, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: name})
		if err != nil {
			// A warning string alone is not a channel promptdefense's
			// coverage accounting reads; RenderError is, and it is also
			// what lets a failed render read differently from a prompt
			// nobody asked to fetch
			snap.Warnings = append(snap.Warnings, fmt.Sprintf("prompts/get failed for %q: %v", name, err))
			snap.Prompts[i].RenderError = err.Error()
			continue
		}
		promptCap := min(maxBytes, remaining)
		text, truncated := boundedPromptText(res.Messages, promptCap)
		if truncated {
			snap.Warnings = append(snap.Warnings, fmt.Sprintf("prompt %q text truncated to %d bytes", name, promptCap))
			snap.Prompts[i].TextTruncated = true
		}
		snap.Prompts[i].Text = text
		// The call succeeded whatever text came back, even "" - that is
		// what tells promptdefense apart a genuinely empty render from one
		// that never ran
		snap.Prompts[i].Rendered = true
		remaining -= len(text)
	}
}

// boundedPromptText joins text blocks up to maxBytes without building an oversized string
func boundedPromptText(messages []*mcp.PromptMessage, maxBytes int) (string, bool) {
	var b strings.Builder
	for _, m := range messages {
		if m == nil {
			continue
		}
		tc, ok := m.Content.(*mcp.TextContent)
		if !ok {
			continue
		}
		text := tc.Text
		if b.Len() > 0 {
			text = "\n" + text
		}
		room := maxBytes - b.Len()
		if room <= 0 {
			return b.String(), true
		}
		if len(text) <= room {
			b.WriteString(text)
			continue
		}
		b.WriteString(truncateAtRuneBoundary(text, room))
		return b.String(), true
	}
	return b.String(), false
}

// readResourceContent fetches every declared resource's content, bounded both per resource
// (maxBytes) and in total (maxTotalBytes). Without the total bound, enough declared
// resources, each within maxBytes, still add up to an unbounded amount in the report: ten
// thousand resources at 64 KiB each is 640 MiB.
func readResourceContent(ctx context.Context, cs *mcp.ClientSession, snap *model.Snapshot, maxBytes, maxTotalBytes int) {
	remaining := maxTotalBytes
	for i := range snap.Resources {
		if remaining <= 0 {
			recordTruncation(snap, &model.Truncation{
				Method:  "resources/read",
				Read:    i,
				Unknown: true,
				Reason:  LimitHitReason + fmt.Sprintf("%d-byte total content cap", maxTotalBytes),
			})
			return
		}
		uri := snap.Resources[i].URI
		res, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		if err != nil {
			// A warning string alone is not a channel promptdefense's
			// coverage accounting reads; ReadError is, the resource
			// equivalent of PromptInfo.RenderError
			snap.Warnings = append(snap.Warnings, fmt.Sprintf("resources/read failed for %q: %v", uri, err))
			snap.Resources[i].ReadError = err.Error()
			continue
		}
		resourceCap := min(maxBytes, remaining)
		content, truncated, binarySkipped := boundedResourceContent(res.Contents, resourceCap)
		if truncated {
			snap.Warnings = append(snap.Warnings, fmt.Sprintf("resource %q content truncated to %d bytes", uri, resourceCap))
			snap.Resources[i].ContentTruncated = true
		}
		if content == "" && binarySkipped {
			// The server returned only binary blocks (an image, a PDF, an
			// undecodable "text" MIME type). There is no text to analyze,
			// so this is not a successful, empty read - it is a read that
			// never produced content, the same as a transport error.
			const reason = "content returned as a binary blob and was not analyzed"
			snap.Warnings = append(snap.Warnings, fmt.Sprintf("resource %q: %s", uri, reason))
			snap.Resources[i].ReadError = reason
			continue
		}
		if binarySkipped {
			snap.Warnings = append(snap.Warnings, fmt.Sprintf("resource %q: one or more content blocks were binary and were not analyzed", uri))
			snap.Resources[i].ContentTruncated = true
		}
		snap.Resources[i].Content = content
		// The call succeeded whatever content came back, even "" - that is
		// what tells promptdefense apart a genuinely empty body from one
		// that was never fetched
		snap.Resources[i].Fetched = true
		remaining -= len(content)
	}
}

// boundedResourceContent concatenates a resource's content blocks up to maxBytes, one block
// at a time, so a resource with many or large blocks never grows an intermediate string
// past the cap before cutting it down
func boundedResourceContent(contents []*mcp.ResourceContents, maxBytes int) (content string, truncated, binarySkipped bool) {
	var b strings.Builder
	for _, c := range contents {
		if c == nil {
			continue
		}
		// A block is documented as carrying either text or a blob, and a server the scanner does
		// not trust is under no obligation to send only one. Reading whichever is found first would
		// let a server put something harmless in text and the body it wants past the scanner in
		// blob, which is the same evasion as sending the body as a blob alone.
		var pieces []string
		if c.Text != "" {
			pieces = append(pieces, c.Text)
		}
		if len(c.Blob) > 0 {
			if textualMIME(c.MIMEType) && utf8.Valid(c.Blob) {
				pieces = append(pieces, string(c.Blob))
			} else {
				binarySkipped = true
			}
		}
		for _, text := range pieces {
			room := maxBytes - b.Len()
			if room <= 0 {
				return b.String(), true, binarySkipped
			}
			if len(text) <= room {
				b.WriteString(text)
				continue
			}
			b.WriteString(truncateAtRuneBoundary(text, room))
			return b.String(), true, binarySkipped
		}
	}
	return b.String(), false, binarySkipped
}

// textualMIME reports whether a MIME type's body can be treated as UTF-8
// text once it arrives as a blob instead of inline text. Anything not
// matched here - images, audio, video, PDF, octet-stream - is binary and is
// left unread rather than decoded on a guess.
func textualMIME(mime string) bool {
	mime, _, _ = strings.Cut(mime, ";")
	mime = strings.TrimSpace(strings.ToLower(mime))
	switch {
	case strings.HasPrefix(mime, "text/"):
		return true
	case mime == "application/json", mime == "application/xml":
		return true
	case strings.HasPrefix(mime, "application/") && (strings.HasSuffix(mime, "+json") || strings.HasSuffix(mime, "+xml")):
		return true
	default:
		return false
	}
}

// truncateAtRuneBoundary cuts s to at most maxBytes bytes without splitting
// a multi-byte rune in half, which would leave an invalid UTF-8 sequence at
// the end of the stored content
func truncateAtRuneBoundary(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ToolInfo converts an SDK tool declaration into the scanner's own shape.
// Exported so client.LoadSnapshotBytes can reuse it when converting a plain
// MCP-shaped document that was never discovered through a live session.
func ToolInfo(t *mcp.Tool) model.ToolInfo {
	if t == nil {
		return model.ToolInfo{}
	}
	return model.ToolInfo{
		Name:         t.Name,
		Title:        t.Title,
		Description:  t.Description,
		InputSchema:  ToSchema(t.InputSchema),
		OutputSchema: ToSchema(t.OutputSchema),
		Annotations:  ToMap(t.Annotations),
		Meta:         map[string]any(t.Meta),
	}
}

// PromptInfo converts an SDK prompt declaration into the scanner's own shape
func PromptInfo(p *mcp.Prompt) model.PromptInfo {
	if p == nil {
		return model.PromptInfo{}
	}
	out := model.PromptInfo{Name: p.Name, Title: p.Title, Description: p.Description}
	for _, a := range p.Arguments {
		if a == nil {
			continue
		}
		out.Arguments = append(out.Arguments, model.PromptArgument{
			Name: a.Name, Description: a.Description, Required: a.Required,
		})
	}
	return out
}

// ResourceInfo converts an SDK resource declaration into the scanner's own shape
func ResourceInfo(r *mcp.Resource) model.ResourceInfo {
	if r == nil {
		return model.ResourceInfo{}
	}
	return model.ResourceInfo{
		URI: r.URI, Name: r.Name, Title: r.Title,
		Description: r.Description, MIMEType: r.MIMEType,
	}
}

// TemplateInfo converts an SDK resource template declaration into the
// scanner's own shape
func TemplateInfo(t *mcp.ResourceTemplate) model.ResourceInfo {
	if t == nil {
		return model.ResourceInfo{}
	}
	return model.ResourceInfo{
		URITemplate: t.URITemplate, Name: t.Name, Title: t.Title,
		Description: t.Description, MIMEType: t.MIMEType,
	}
}

// ToMap round-trips v through JSON into a map[string]any, respecting
// whatever json tags v's type declares. Used to convert SDK-typed structs
// (capabilities, annotations) into the loosely-typed shape model.Snapshot
// stores them in.
func ToMap(v any) map[string]any {
	if v == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

// ToSchema handles the client-side shape of Tool.InputSchema/OutputSchema,
// which is already a map[string]any once decoded from the wire
func ToSchema(v any) map[string]any {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return ToMap(v)
}
