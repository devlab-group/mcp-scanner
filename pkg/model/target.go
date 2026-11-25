package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// sensitiveArgNameWords are the flag-name words RedactedArgs treats as
// credential-bearing, matched as the trailing word of the flag (see
// isSensitiveArgName), not as a substring - "--keyring" and "--tokenizer"
// must survive redaction even though "key" and "token" appear in them
var sensitiveArgNameWords = []string{"key", "token", "secret", "password"}

// isSensitiveArgName reports whether flag - a stdio argument such as "--api-key" or "-t"
// with leading dashes still attached - names something RedactedArgs must not print the
// value of. Matching the final hyphen/underscore-delimited word avoids redacting lookalikes
// such as --keyring while still catching --api-key.
func isSensitiveArgName(flag string) bool {
	name := strings.TrimLeft(flag, "-")
	fields := strings.FieldsFunc(name, func(r rune) bool { return r == '-' || r == '_' })
	if len(fields) == 0 {
		return false
	}
	return slices.Contains(sensitiveArgNameWords, strings.ToLower(fields[len(fields)-1]))
}

// TargetKind selects which scanner pipeline runs
type TargetKind string

const (
	// TargetRemote is an MCP server reachable over HTTP (Streamable HTTP or legacy SSE)
	TargetRemote TargetKind = "remote"
	// TargetStdio is an MCP server launched as a child process
	TargetStdio TargetKind = "stdio"
	// TargetStatic is a JSON document describing tools/prompts/resources, with no connection
	TargetStatic TargetKind = "static"
	// TargetSource is a directory of source code
	TargetSource TargetKind = "source"
	// TargetPackage is a published package coordinate (npm, PyPI, Go, Cargo)
	TargetPackage TargetKind = "package"
	// TargetConfig names an MCP client config file listing several servers. It is not a
	// scannable target because one Target must produce one ScanResult, while config expands to
	// several targets. known-configs handles that expansion and Validate refuses this kind.
	TargetConfig TargetKind = "config"
)

// Target describes what is being scanned. One Target produces one ScanResult
type Target struct {
	Kind TargetKind `json:"kind"`
	// Name is what shows up in reports
	Name string `json:"name"`

	// Remote
	URL       string            `json:"url,omitempty"`
	Headers   map[string]string `json:"-"`                   // never serialized: may hold bearer tokens
	Transport string            `json:"transport,omitempty"` // auto | streamable | sse

	// Stdio
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"` // redacted by MarshalJSON, see RedactedArgs
	Env     map[string]string `json:"-"`              // never serialized

	// Static / source / package
	Path      string `json:"path,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"` // npm | pypi | go | cargo
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	// ResolvedVersion is the version the registry served for a package target: what was actually
	// downloaded and scanned, whatever Version asked for (nothing, "latest", a dist-tag). Set by
	// the scanner after preparation; Version keeps the request as given.
	ResolvedVersion string `json:"resolved_version,omitempty"`
}

func (t Target) Validate() error {
	switch t.Kind {
	case TargetRemote:
		if t.URL == "" {
			return fmt.Errorf("remote target needs a url")
		}
	case TargetStdio:
		if t.Command == "" {
			return fmt.Errorf("stdio target needs a command")
		}
	case TargetStatic, TargetSource:
		if t.Path == "" {
			return fmt.Errorf("%s target needs a path", t.Kind)
		}
	case TargetConfig:
		return fmt.Errorf("a %s file lists several servers and is not a target of its own; scan each server, or use known-configs", t.Kind)
	case TargetPackage:
		if t.Ecosystem == "" || t.Package == "" {
			return fmt.Errorf("package target needs an ecosystem and a package name")
		}
	default:
		return fmt.Errorf("unknown target kind %q", t.Kind)
	}
	// Only a stdio target may carry a command. The runtime analyzer executes
	// Target.Command for source and package targets too, so accepting one here
	// would bypass the target-kind gate and smuggle a process into the sandbox.
	if t.Kind != TargetStdio && (t.Command != "" || len(t.Args) > 0 || len(t.Env) > 0) {
		return fmt.Errorf("a %s target carries no command, args or env; only a stdio target names a process to run", t.Kind)
	}
	return nil
}

// Describe returns the label used in logs and reports
func (t Target) Describe() string {
	if t.Name != "" {
		return t.Name
	}
	switch t.Kind {
	case TargetRemote:
		return t.RedactedURL()
	case TargetStdio:
		return t.Command
	case TargetPackage:
		if t.Version != "" {
			return t.Ecosystem + ":" + t.Package + "@" + t.Version
		}
		return t.Ecosystem + ":" + t.Package
	default:
		return t.Path
	}
}

// nonSecretQueryParams are the only query parameter names RedactedURL leaves alone.
// Everything else is redacted: a hosted MCP endpoint authenticates with a query-string
// token far more often than with HTTP basic auth, and there is no fixed list of the token
// names servers use. Over-redacting costs only report detail; under-redacting can leak a secret.
var nonSecretQueryParams = []string{"transport", "version"}

// RedactedURL replaces userinfo credentials, non-allowlisted query values and path segments
// that look like credentials (secretLike) with the literal "redacted" while retaining their
// structural names. Report writers must use this form because target URLs often come from
// writable client configs and are archived or committed with output. Hosted MCP services often
// put the key in the path (https://host/s/<key>/mcp), so the path is redacted too.
func (t Target) RedactedURL() string {
	return redactURL(t.URL, true)
}

// redactURL is RedactedURL for any URL. paths=false keeps the path as written: FingerprintScope
// uses that form, so two endpoints that differ only by the key in their path keep distinct
// finding IDs, and IDs computed before path redaction existed stay the same.
func redactURL(raw string, paths bool) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redactUnparsableURL(raw, paths)
	}
	if u.User != nil {
		// The username goes too: GitHub, GitLab and most hosted APIs document passing a personal
		// access token over basic auth as the username, either bare (https://<token>@host) or
		// paired with a filler password (https://<token>:x-oauth-basic@host)
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword("redacted", "redacted")
		} else {
			u.User = url.User("redacted")
		}
	}
	if q := u.Query(); len(q) > 0 {
		changed := false
		for k := range q {
			if slices.Contains(nonSecretQueryParams, strings.ToLower(k)) {
				continue
			}
			q.Set(k, "redacted")
			changed = true
		}
		if changed {
			u.RawQuery = q.Encode()
		}
	}
	if paths && u.Path != "" {
		segs := strings.Split(u.Path, "/")
		changed := false
		for i, seg := range segs {
			if secretLike(seg) {
				segs[i] = "redacted"
				changed = true
			}
		}
		if changed {
			u.Path = strings.Join(segs, "/")
			u.RawPath = ""
		}
	}
	return u.String()
}

var (
	// tokenPrefix matches credentials by the prefixes their issuers give them: OpenAI/Stripe
	// style sk-/pk-/rk-, GitHub, GitLab, Slack, AWS access key IDs, Google API keys, webhook
	// secrets, and JWTs (base64 of '{"')
	tokenPrefix = regexp.MustCompile(`^(?:(?:sk|pk|rk)[-_]|gh[pousr]_|github_pat_|glpat-|xox[abposr]-|AKIA[0-9A-Z]{12}|AIza|whsec_|eyJ[A-Za-z0-9_-]{5,}\.)`)
	uuidLike    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tokenChars  = regexp.MustCompile(`^[A-Za-z0-9._~+=-]+$`)
)

// secretLike reports whether a URL path segment looks like a credential rather than a route
// name: a known token prefix, a UUID (hosted MCP services hand out UUID keys), or a run of at
// least 20 token characters mixing letters and digits. Routes such as mcp, sse, v1 or tools stay.
// Over-redacting a long route name costs report detail only.
func secretLike(seg string) bool {
	if len(seg) < 8 {
		return false
	}
	if tokenPrefix.MatchString(seg) || uuidLike.MatchString(seg) {
		return true
	}
	if len(seg) < 20 || !tokenChars.MatchString(seg) {
		return false
	}
	return strings.ContainsAny(seg, "0123456789") && strings.IndexFunc(seg, unicode.IsLetter) >= 0
}

// RedactedArgs is Args with credentials replaced by the literal "redacted". It protects stdio
// targets imported from client configs, where credentials are commonly passed as arguments
// rather than environment variables:
//
//   - the value after a credential-shaped flag name, as a separate element ("--api-key", "value")
//     or packed into one ("--api-key=value", "GITHUB_TOKEN=value");
//   - the value of a header passed with --header/-H/--headers (mcp-remote's way of sending
//     "Authorization: Bearer <token>"), and of any "Name: value" element whose name is
//     credential-shaped, keeping the header name;
//   - a URL, redacted like a remote target's URL (userinfo, query values, key-like path segments);
//   - the token after "Bearer"/"Basic"/"Token" anywhere, and an element that is itself a token
//     with a known issuer prefix or a JWT.
func (t Target) RedactedArgs() []string {
	if len(t.Args) == 0 {
		return t.Args
	}
	out := slices.Clone(t.Args)
	for i := 0; i < len(out); i++ {
		a := out[i]
		name, value, packed := strings.Cut(a, "=")
		switch {
		case isURLArg(a):
			out[i] = redactURL(a, true)
		case packed && isHeaderFlag(name):
			out[i] = name + "=" + redactHeader(value, true)
		case isHeaderFlag(a) && i+1 < len(out):
			out[i+1] = redactHeader(out[i+1], true)
			i++
		case packed && isSensitiveArgName(name):
			out[i] = name + "=redacted"
		case isSensitiveArgName(a) && i+1 < len(out):
			// whatever follows is the value, even when it starts with "-" as a base64url token can
			out[i+1] = "redacted"
			i++
		case packed && isURLArg(value):
			out[i] = name + "=" + redactURL(value, true)
		default:
			out[i] = redactHeader(a, false)
		}
		out[i] = redactInlineToken(out[i])
	}
	return out
}

func isURLArg(a string) bool {
	scheme, _, ok := strings.Cut(a, "://")
	if !ok {
		return false
	}
	switch strings.ToLower(scheme) {
	case "http", "https", "ws", "wss":
		return true
	}
	return false
}

func isHeaderFlag(a string) bool {
	switch a {
	case "--header", "-H", "--headers", "--http-header":
		return true
	}
	return false
}

// headerLine is one "Name: value" element, the way curl and mcp-remote take headers
var headerLine = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9_-]*)\s*:\s*(\S.*)$`)

// redactHeader replaces the value of a "Name: value" element: always when the element was
// passed as a header (asHeader), otherwise only when the name is credential-shaped
func redactHeader(a string, asHeader bool) string {
	m := headerLine.FindStringSubmatch(a)
	if m == nil {
		if asHeader {
			return "redacted"
		}
		return a
	}
	if !asHeader && !isSensitiveHeaderName(m[1]) {
		return a
	}
	return m[1] + ": redacted"
}

func isSensitiveHeaderName(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie":
		return true
	}
	return isSensitiveArgName(name)
}

var inlineToken = regexp.MustCompile(`(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=-]{8,}`)

// redactInlineToken replaces the credential after an authorization scheme word, and an element
// (or the value of a name=value element) that is a token by its issuer prefix or a JWT
func redactInlineToken(a string) string {
	if tokenPrefix.MatchString(a) {
		return "redacted"
	}
	if name, value, ok := strings.Cut(a, "="); ok && tokenPrefix.MatchString(value) {
		return name + "=redacted"
	}
	return inlineToken.ReplaceAllString(a, "${1}${2}redacted")
}

// redactUnparsableURL handles a string url.Parse would not take. With no safe way to distinguish
// path from query or userinfo, it removes those credential-shaped regions conservatively.
func redactUnparsableURL(raw string, paths bool) string {
	out := raw
	if i := strings.IndexByte(out, '?'); i >= 0 {
		out = out[:i] + "?redacted"
	}
	// scheme://user:pass@host -> scheme://redacted:redacted@host, textually, since there is no
	// parse to lean on. The last @ before the first / of the path is the authority's own
	// separator.
	if scheme := strings.Index(out, "://"); scheme >= 0 {
		rest := out[scheme+3:]
		end := len(rest)
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			end = slash
		}
		if at := strings.LastIndexByte(rest[:end], '@'); at >= 0 {
			userinfo := "redacted"
			if strings.IndexByte(rest[:at], ':') >= 0 {
				userinfo = "redacted:redacted"
			}
			out = out[:scheme+3] + userinfo + rest[at:]
		}
		if paths {
			// the path runs from the first / after the authority to the query
			rest = out[scheme+3:]
			if slash := strings.IndexByte(rest, '/'); slash >= 0 {
				path, tail := rest[slash:], ""
				if q := strings.IndexByte(path, '?'); q >= 0 {
					path, tail = path[:q], path[q:]
				}
				segs := strings.Split(path, "/")
				for i, seg := range segs {
					if secretLike(seg) {
						segs[i] = "redacted"
					}
				}
				out = out[:scheme+3] + rest[:slash] + strings.Join(segs, "/") + tail
			}
		}
	}
	return out
}

// MarshalJSON emits URL and Args redacted, so a plain json.Marshal/Encode
// of any struct embedding Target - a report, an API response - cannot leak
// a credential by omission. The raw values stay on the struct fields
// themselves for the transport that actually launches or dials the target.
func (t Target) MarshalJSON() ([]byte, error) {
	type alias Target // avoid recursing back into this method
	out := alias(t)
	out.URL = t.RedactedURL()
	out.Args = t.RedactedArgs()
	return json.Marshal(out)
}
