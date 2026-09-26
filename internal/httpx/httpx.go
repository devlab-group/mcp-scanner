// Package httpx is the outbound HTTP layer for everything the scanner fetches: MCP
// endpoints, package registries, vulnerability data and model providers
package httpx

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Policy decides which destinations the scanner may reach
type Policy struct {
	// AllowPrivateNetworks permits loopback, link-local and private-range
	// destinations. Off by default: the scanner is pointed at things the
	// operator does not trust, and the interesting target for a hostile
	// server is the network the scanner runs on.
	AllowPrivateNetworks bool

	// AllowedSchemes defaults to https and http
	AllowedSchemes []string
}

// EndpointSchemes is https only unless the operator allowed an insecure endpoint. A third-party
// endpoint receives the API key on every request, so plain http would send it, and the declared
// MCP surface being inspected, in the clear.
func EndpointSchemes(allowInsecure bool) []string {
	if allowInsecure {
		return []string{"https", "http"}
	}
	return []string{"https"}
}

// DefaultPolicy blocks private destinations and allows only http and https
func DefaultPolicy() Policy { return Policy{} }

func (p Policy) schemes() []string {
	if len(p.AllowedSchemes) > 0 {
		return p.AllowedSchemes
	}
	return []string{"https", "http"}
}

// CheckURL rejects a URL on its scheme and, when the host is a literal address, on the
// address itself. It is only a fast preflight check; the dial guard is the SSRF boundary because
// it checks the address actually selected after DNS resolution.
func (p Policy) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	var ok bool
	if slices.Contains(p.schemes(), scheme) {
		ok = true
	}
	if !ok {
		return fmt.Errorf("scheme %q is not allowed (want one of %v)", u.Scheme, p.schemes())
	}
	if u.Host == "" {
		return fmt.Errorf("url %q has no host", raw)
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil && !p.AllowPrivateNetworks && UnsafeIP(ip) {
		return fmt.Errorf("destination %s is in a range the scanner will not connect to", ip)
	}
	return nil
}

// ErrBlocked is returned by the dial guard
type ErrBlocked struct {
	Addr string
	IP   net.IP
}

func (e *ErrBlocked) Error() string {
	return fmt.Sprintf("blocked connection to %s: %s is in a range the scanner will not connect to", e.Addr, e.IP)
}

// Dialer returns a dialer that refuses to connect to a blocked address.
//
// Control runs after the name has been resolved and before the socket
// connects, on the address the kernel is about to use, so a name that
// answers differently on a second lookup gains nothing.
func (p Policy) Dialer(timeout time.Duration) *net.Dialer {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			return p.checkDialAddr(address)
		},
	}
}

func (p Policy) checkDialAddr(address string) error {
	if p.AllowPrivateNetworks {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Control is handed a resolved address. Anything else is a shape we
		// do not recognise, and an unrecognised destination is refused.
		return &ErrBlocked{Addr: address}
	}
	if UnsafeIP(ip) {
		return &ErrBlocked{Addr: address, IP: ip}
	}
	return nil
}

// Transport builds a guarded http.Transport
func (p Policy) Transport(timeout time.Duration) *http.Transport {
	d := p.Dialer(timeout)
	return &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// Client builds a guarded http.Client.
//
// Redirects are held to the origin the request started from. A server the
// scanner does not trust has no legitimate reason to bounce it to another
// host, and following one is how a credential ends up somewhere it was never
// meant to go.
func (p Policy) Client(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     proxyNote{base: p.Transport(timeout)},
		CheckRedirect: SameOriginRedirect,
	}
}

// proxyNote adds one sentence to a connection error when the environment asks for a proxy
// this transport deliberately does not use. Routing through a proxy would move the dial-time
// outbound guard away from the final destination, so proxy-only environments fail closed.
type proxyNote struct{ base http.RoundTripper }

func (t proxyNote) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	// Not for a destination this scanner refused on purpose: that error
	// already says exactly what happened, and blaming the proxy for it
	// would be wrong
	var blocked *ErrBlocked
	if errors.As(err, &blocked) || !proxyRequested() {
		return nil, err
	}
	return nil, fmt.Errorf("%w (the scanner connects directly and ignores %s; see docs/threat-model.md)", err, proxyVarsSet())
}

// proxyVars are the environment variables Go's own ProxyFromEnvironment
// reads, which is what an operator will have set when they expect a proxy
// to be used
var proxyVars = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"}

func proxyRequested() bool {
	return proxyVarsSet() != ""
}

// proxyVarsSet names the proxy variables that are set, so the message can
// point at the one the operator actually wrote
func proxyVarsSet() string {
	var set []string
	for _, v := range proxyVars {
		if os.Getenv(v) != "" {
			set = append(set, v)
		}
	}
	return strings.Join(set, ", ")
}

// SameOriginRedirect refuses a redirect that changes scheme or host
func SameOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	from := via[len(via)-1].URL
	if !SameOrigin(from, req.URL) {
		return fmt.Errorf("refusing redirect from %s to a different origin %s://%s",
			from.Host, req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// SameOrigin compares scheme and host, treating a missing port as the
// scheme's default
func SameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(hostPort(a), hostPort(b))
}

func hostPort(u *url.URL) string {
	host, port := u.Hostname(), u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return host + ":" + port
}

// Ranges the scanner will not connect to unless the operator opts in
var blockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",       // this network
		"10.0.0.0/8",      // private
		"100.64.0.0/10",   // carrier-grade NAT, reaches provider infrastructure
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local, including cloud metadata at 169.254.169.254
		"172.16.0.0/12",   // private
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"192.88.99.0/24",  // deprecated 6to4 relay anycast
		"192.168.0.0/16",  // private
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved, includes 255.255.255.255
		"::1/128",         // loopback
		"fc00::/7",        // unique local
		"fe80::/10",       // link-local
		"ff00::/8",        // multicast
		"::/128",          // unspecified
		"2001:db8::/32",   // documentation
		"2001::/32",       // Teredo tunneling, encodes an IPv4 address that may be private
		"64:ff9b::/96",    // NAT64, same
		"2002::/16",       // 6to4, same
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// UnsafeIP reports whether an address is one the scanner refuses by default
func UnsafeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// An IPv4-mapped IPv6 address must be judged as the IPv4 address it is,
	// or ::ffff:127.0.0.1 walks straight past the IPv4 ranges
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range blockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	// The deprecated IPv4-compatible form ::a.b.c.d (RFC 4291) carries an
	// embedded IPv4 address the same way the mapped form above does, but
	// To4 does not recognize it - it only unwraps ::ffff:0:0/96 - so
	// ::127.0.0.1 would otherwise match none of the ranges above
	if v4c := ipv4Compatible(ip); v4c != nil {
		return UnsafeIP(v4c)
	}
	return false
}

// ipv4Compatible extracts the embedded address from the deprecated
// ::a.b.c.d IPv6 form (first 12 bytes zero), or returns nil for anything
// else, including the ::ffff:a.b.c.d mapped form To4 already handles above
// (bytes 10-11 there are 0xff, not zero)
func ipv4Compatible(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	for _, b := range ip16[:12] {
		if b != 0 {
			return nil
		}
	}
	return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
}
