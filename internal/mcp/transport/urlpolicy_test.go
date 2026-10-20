package transport

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func TestCheckRejectsNonHTTPScheme(t *testing.T) {
	p := Policy{}
	if err := p.Check("file:///etc/passwd"); err == nil {
		t.Fatal("file:// scheme was accepted")
	}
	if err := p.Check("ftp://example.com/x"); err == nil {
		t.Fatal("ftp:// scheme was accepted")
	}
}

func TestCheckRejectsLiteralPrivateIP(t *testing.T) {
	p := Policy{}
	for _, u := range []string{
		"http://127.0.0.1:8080/mcp",
		"http://169.254.1.1/mcp",
		"http://10.0.0.5/mcp",
		"http://[::1]/mcp",
	} {
		if err := p.Check(u); err == nil {
			t.Fatalf("%s: private/loopback address was accepted", u)
		}
	}
}

func TestCheckAllowsPublicAddress(t *testing.T) {
	p := Policy{}
	if err := p.Check("https://example.com/mcp"); err != nil {
		t.Fatalf("public address rejected: %v", err)
	}
}

func TestCheckAllowPrivateNetworksOptOut(t *testing.T) {
	p := Policy{AllowPrivateNetworks: true}
	if err := p.Check("http://127.0.0.1:8080/mcp"); err != nil {
		t.Fatalf("opted-in private address rejected: %v", err)
	}
}

// The post-resolution dial guard must refuse loopback addresses
func TestDialGuardRefusesALoopbackAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should never be reached"))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	target := model.Target{Kind: model.TargetRemote, URL: "http://" + u.Host + "/mcp"}
	client, _ := httpClient(target, Policy{})

	_, err := client.Get(target.URL)
	if err == nil {
		t.Fatal("a dial to a resolved loopback address succeeded")
	}
}

func TestDialGuardAllowsPrivateNetworksOptIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	target := model.Target{Kind: model.TargetRemote, URL: srv.URL}
	client, _ := httpClient(target, Policy{AllowPrivateNetworks: true})

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("opted-in loopback dial was refused: %v", err)
	}
	resp.Body.Close()
}
