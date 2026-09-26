// Package transport builds SDK transports for an MCP target and enforces the
// scanner's own SSRF guard before any of them connect
package transport

import "github.com/revinand/mcp-scanner/internal/httpx"

// Policy decides which remote endpoints the scanner may connect to. Check handles obvious URL
// violations, while the guarded dialer remains the real SSRF boundary because it inspects the
// address selected after DNS resolution and therefore closes the rebinding window.
type Policy struct {
	// AllowPrivateNetworks opts into connecting to loopback, link-local and
	// private-range destinations. Off by default.
	AllowPrivateNetworks bool
}

func (p Policy) httpx() httpx.Policy {
	return httpx.Policy{AllowPrivateNetworks: p.AllowPrivateNetworks}
}

// Check rejects a URL with a disallowed scheme, or a literal address already
// known to be blocked. See the Policy doc comment for what it deliberately
// does not do.
func (p Policy) Check(rawURL string) error {
	return p.httpx().CheckURL(rawURL)
}
