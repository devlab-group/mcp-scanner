package httpx

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestUnsafeIPRanges(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", // cloud metadata
		"100.64.0.1",      // carrier-grade NAT
		"192.0.0.1",       // IETF protocol assignments
		"255.255.255.255", // broadcast
		"0.0.0.0",
		"fe80::1", "fc00::1",
		"::ffff:127.0.0.1", // IPv4-mapped loopback
		"192.88.99.1",      // deprecated 6to4 relay anycast
		"::127.0.0.1",      // IPv4-compatible (deprecated) loopback
		// Cover each remaining blocked range
		"192.0.2.1", "198.51.100.1", "203.0.113.1", // documentation
		"198.18.0.1",      // benchmarking
		"224.0.0.1",       // multicast
		"240.0.0.1",       // reserved
		"ff02::1",         // IPv6 multicast
		"::",              // unspecified
		"2001:db8::1",     // IPv6 documentation
		"2001::1",         // Teredo
		"64:ff9b::7f00:1", // NAT64
		"2002::1",         // 6to4
	}
	for _, s := range blocked {
		if !UnsafeIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"} {
		if UnsafeIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestCheckURLScheme(t *testing.T) {
	p := DefaultPolicy()
	for _, bad := range []string{"file:///etc/passwd", "gopher://x/", "ftp://x/", "javascript:alert(1)"} {
		if err := p.CheckURL(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if err := p.CheckURL("https://example.com/mcp"); err != nil {
		t.Errorf("a plain https url was rejected: %v", err)
	}
	if err := p.CheckURL("http://127.0.0.1:8080/"); err == nil {
		t.Error("a literal loopback url was accepted")
	}
}

func TestDialGuardBlocksAResolvedPrivateAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should never be reached"))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	// srv listens on loopback, and CheckURL would catch the literal form, so
	// go around it and dial directly the way a rebound name would
	p := DefaultPolicy()
	_, err := p.Client(2 * time.Second).Get("http://" + u.Host + "/")
	if err == nil {
		t.Fatal("a connection to a loopback address succeeded")
	}
	var blocked *ErrBlocked
	if !errors.As(err, &blocked) && !containsBlocked(err) {
		t.Fatalf("unexpected error, want a block: %v", err)
	}
}

func containsBlocked(err error) bool {
	var b *ErrBlocked
	return errors.As(err, &b) || strings.Contains(err.Error(), "will not connect")
}

func TestAllowPrivateNetworksOptsIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p := Policy{AllowPrivateNetworks: true}
	resp, err := p.Client(2 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("opting in did not allow loopback: %v", err)
	}
	resp.Body.Close()
}

func TestSameOrigin(t *testing.T) {
	mk := func(s string) *url.URL { u, _ := url.Parse(s); return u }
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://example.com/a", "https://example.com/b", true},
		{"https://example.com", "https://example.com:443/x", true},
		{"https://example.com", "https://evil.example.net", false},
		{"https://example.com", "http://example.com", false},
		{"https://example.com", "https://example.com:8443", false},
	}
	for _, c := range cases {
		if got := SameOrigin(mk(c.a), mk(c.b)); got != c.want {
			t.Errorf("SameOrigin(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestRedirectToAnotherOriginIsRefused(t *testing.T) {
	var reached bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.Write([]byte("landed"))
	}))
	defer attacker.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusFound)
	}))
	defer target.Close()

	// Private networks are allowed here so the test exercises the redirect
	// rule rather than the dial guard
	p := Policy{AllowPrivateNetworks: true}
	if _, err := p.Client(2 * time.Second).Get(target.URL); err == nil {
		t.Fatal("a cross-origin redirect was followed")
	}
	if reached {
		t.Fatal("the request reached the other origin")
	}
}

func TestTranslationPrefixesAreBlocked(t *testing.T) {
	for _, s := range []string{
		"64:ff9b::7f00:1",                      // NAT64 wrapping 127.0.0.1
		"64:ff9b::a00:1",                       // NAT64 wrapping 10.0.0.1
		"2002:7f00:1::1",                       // 6to4 wrapping 127.0.0.1
		"2002:c0a8:101::1",                     // 6to4 wrapping 192.168.1.1
		"2001::1",                              // Teredo
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", // a real-shaped Teredo address
	} {
		if !UnsafeIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
}

func TestProxyNoteExplainsWhyADirectConnectionFailed(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.internal:3128")

	// Port 1 on loopback refuses; private destinations are allowed here so
	// the refusal comes from the network, not from the destination guard
	client := Policy{AllowPrivateNetworks: true}.Client(2 * time.Second)
	_, err := client.Get("http://127.0.0.1:1/")
	if err == nil {
		t.Fatal("expected the connection to fail")
	}
	if !strings.Contains(err.Error(), "HTTPS_PROXY") {
		t.Errorf("error does not name the proxy variable that was set: %v", err)
	}
}

func TestProxyNoteLeavesARefusedDestinationAlone(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.internal:3128")

	client := Policy{}.Client(2 * time.Second)
	_, err := client.Get("http://127.0.0.1:1/")
	if err == nil {
		t.Fatal("expected the destination to be refused")
	}
	if strings.Contains(err.Error(), "HTTPS_PROXY") {
		t.Errorf("a destination the scanner refused must not be blamed on the proxy: %v", err)
	}
}

// A proxy would make the dial guard check the proxy instead of the destination. Inspect the
// transport directly because net/http caches proxy environment variables per process.
func TestTransportNeverUsesAProxy(t *testing.T) {
	p := Policy{}
	if p.Transport(time.Second).Proxy != nil {
		t.Fatal("the guarded transport has a Proxy function")
	}
	c := p.Client(time.Second)
	note, ok := c.Transport.(proxyNote)
	if !ok {
		t.Fatalf("unexpected client transport %T", c.Transport)
	}
	if tr, ok := note.base.(*http.Transport); !ok || tr.Proxy != nil {
		t.Fatalf("the client's base transport is %T with a proxy set", note.base)
	}
}
