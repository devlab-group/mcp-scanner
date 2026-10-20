package main

import (
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/app"
	"github.com/devlab-group/mcp-scanner/internal/config"
)

// newHTTPServer must apply every configured limit
func TestNewHTTPServerSetsExplicitLimits(t *testing.T) {
	srv := newHTTPServer("127.0.0.1:0", http.NewServeMux())
	switch {
	case srv.ReadHeaderTimeout != apiReadHeaderTimeout:
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, apiReadHeaderTimeout)
	case srv.ReadTimeout != apiReadTimeout:
		t.Errorf("ReadTimeout = %v, want %v", srv.ReadTimeout, apiReadTimeout)
	case srv.WriteTimeout != apiWriteTimeout:
		t.Errorf("WriteTimeout = %v, want %v", srv.WriteTimeout, apiWriteTimeout)
	case srv.IdleTimeout != apiIdleTimeout:
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, apiIdleTimeout)
	case srv.MaxHeaderBytes != apiMaxHeaderBytes:
		t.Errorf("MaxHeaderBytes = %v, want %v", srv.MaxHeaderBytes, apiMaxHeaderBytes)
	}
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatal("a zero timeout here means the corresponding net/http default of \"wait forever\" is back")
	}
}

// Close a real socket that stalls before completing its headers, not a fake response writer.
// The shortened timeout keeps the test fast; another test checks the production value is wired in.
func TestReadHeaderTimeoutClosesIncompleteHeaderConnection(t *testing.T) {
	const timeout = 200 * time.Millisecond
	srv := &http.Server{Handler: http.NewServeMux(), ReadHeaderTimeout: timeout}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Omit the blank line that ends the header block
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n")); err != nil {
		t.Fatal(err)
	}

	// Before the deadline, the server should still be waiting
	conn.SetReadDeadline(time.Now().Add(timeout / 4))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); !isTimeoutErr(err) {
		t.Fatalf("read before the deadline returned %v, want a timeout (server responded or closed early)", err)
	}

	// After the deadline, the server should close the connection
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("read after the deadline returned %d bytes with no error; want the connection closed", n)
	}
	if isTimeoutErr(err) {
		t.Fatalf("read after the deadline timed out again (%v); want the connection closed by ReadHeaderTimeout", err)
	}
}

func isTimeoutErr(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// Production options fail incomplete scans by default, reuse the CLI scan options, and reject
// unknown target kinds
func TestAPIOptionsFromConfig(t *testing.T) {
	t.Setenv("MCP_SCANNER_API_ALLOWED_KINDS", "")
	cfg := config.Defaults()
	opts, err := apiOptions(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !opts.Policy.FailOnUnknown {
		t.Error("an incomplete scan passes the API policy by default")
	}
	want, err := app.ScanOptions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opts.ScanOptions, want) {
		t.Errorf("scan options differ from the CLI's for the same config:\n got %+v\nwant %+v", opts.ScanOptions, want)
	}

	cfg.TolerateUnknown = true
	if opts, err = apiOptions(cfg, nil); err != nil || opts.Policy.FailOnUnknown {
		t.Errorf("tolerate_unknown: true did not reach the policy (err %v)", err)
	}

	t.Setenv("MCP_SCANNER_API_ALLOWED_KINDS", "remote, stdiio")
	if _, err := apiOptions(config.Defaults(), nil); err == nil || !strings.Contains(err.Error(), "stdiio") {
		t.Errorf("an unknown allowed kind was accepted: %v", err)
	}
}
