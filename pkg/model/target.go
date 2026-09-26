package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
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

// RedactedURL replaces userinfo credentials and non-allowlisted query values with the literal
// "redacted" while retaining their structural names. Report writers must use this form because
// target URLs often come from writable client configs and are archived or committed with output.
func (t Target) RedactedURL() string {
	u, err := url.Parse(t.URL)
	if err != nil {
		return redactUnparsableURL(t.URL)
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
	return u.String()
}

// RedactedArgs is Args with the value following any credential-shaped flag name replaced by
// the literal "redacted", both as a separate element ("--api-key", "value") and packed into
// one ("--api-key=value"). This protects stdio targets imported from client configs, where
// credentials are commonly passed as arguments rather than environment variables.
func (t Target) RedactedArgs() []string {
	if len(t.Args) == 0 {
		return t.Args
	}
	out := slices.Clone(t.Args)
	for i, a := range out {
		name := a
		hasValue := false
		if before, _, ok := strings.Cut(a, "="); ok {
			name, hasValue = before, true
		}
		if !isSensitiveArgName(name) {
			continue
		}
		if hasValue {
			out[i] = name + "=redacted"
		} else if i+1 < len(out) {
			out[i+1] = "redacted"
		}
	}
	return out
}

// redactUnparsableURL handles a string url.Parse would not take. With no safe way to distinguish
// path from query or userinfo, it removes those credential-shaped regions conservatively.
func redactUnparsableURL(raw string) string {
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
