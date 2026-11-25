package api

import (
	"net/http"
	"strings"
	"testing"
)

const remoteBody = `{"target": {"kind": "remote", "url": "https://example.com/mcp"}}`

func send(t *testing.T, method, url, body string, header map[string]string, host string) int {
	t.Helper()
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

var jsonType = map[string]string{"Content-Type": "application/json"}

// A page can send text/plain, form or multipart bodies without a CORS preflight; the API takes JSON
func TestSubmitRefusesBodiesAPageCanSendWithoutPreflight(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{})
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""} {
		h := map[string]string{}
		if ct != "" {
			h["Content-Type"] = ct
		}
		if got := send(t, http.MethodPost, ts.URL+"/v1/scans", remoteBody, h, ""); got != http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q: status = %d, want 415", ct, got)
		}
	}
	if got := send(t, http.MethodPost, ts.URL+"/v1/scans", remoteBody, map[string]string{"Content-Type": "application/json; charset=utf-8"}, ""); got != http.StatusAccepted {
		t.Errorf("application/json with a charset: status = %d, want 202", got)
	}
}

// Only browsers send Origin; a page on any site must not start or read scans
func TestRequestsFromWebPagesAreRefused(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{AllowedOrigins: []string{"https://dash.example"}})
	h := map[string]string{"Content-Type": "application/json", "Origin": "https://evil.example"}
	if got := send(t, http.MethodPost, ts.URL+"/v1/scans", remoteBody, h, ""); got != http.StatusForbidden {
		t.Errorf("POST from another origin: status = %d, want 403", got)
	}
	if got := send(t, http.MethodGet, ts.URL+"/v1/scans/scan_x", "", map[string]string{"Origin": "null"}, ""); got != http.StatusForbidden {
		t.Errorf("GET with Origin null: status = %d, want 403", got)
	}
	h["Origin"] = "https://dash.example"
	if got := send(t, http.MethodPost, ts.URL+"/v1/scans", remoteBody, h, ""); got != http.StatusAccepted {
		t.Errorf("POST from an allowed origin: status = %d, want 202", got)
	}
}

// Through DNS rebinding a page reaches a loopback listener with its own name in Host; a GET is
// same-origin then and carries no Origin header, so the Host check is what stops it
func TestReboundHostIsRefused(t *testing.T) {
	ts := newTestServer(t, testScanner(t, 0), Options{AllowedHosts: []string{"localhost", "127.0.0.1", "::1"}})
	if got := send(t, http.MethodPost, ts.URL+"/v1/scans", remoteBody, jsonType, "evil.example:8080"); got != http.StatusForbidden {
		t.Errorf("POST with a rebound Host: status = %d, want 403", got)
	}
	if got := send(t, http.MethodGet, ts.URL+"/v1/scans/scan_x", "", nil, "evil.example:8080"); got != http.StatusForbidden {
		t.Errorf("GET with a rebound Host: status = %d, want 403", got)
	}
	for _, host := range []string{"", "localhost:8080", "LOCALHOST.:8080", "[::1]:8080"} {
		if got := send(t, http.MethodPost, ts.URL+"/v1/scans", remoteBody, jsonType, host); got != http.StatusAccepted {
			t.Errorf("POST with Host %q: status = %d, want 202", host, got)
		}
	}
	if got := send(t, http.MethodGet, ts.URL+"/healthz", "", nil, "evil.example:8080"); got != http.StatusOK {
		t.Errorf("healthz with any Host: status = %d, want 200 (health checks stay open)", got)
	}
}
