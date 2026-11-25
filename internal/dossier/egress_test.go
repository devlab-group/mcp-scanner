package dossier

import (
	"context"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/analyzers/behavioral"
	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

func egressOf(t *testing.T, files map[string]string) map[string]*behavioral.Egress {
	t.Helper()
	d, err := Build(context.Background(), testutil.WriteTree(t, files), "test")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*behavioral.Egress{}
	for _, c := range d.Capabilities {
		if c.Behavior != nil {
			out[c.Name] = c.Behavior.Egress
		}
	}
	return out
}

const pyHead = `import os
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("t")
API = "https://weather.example.com/v2"
BASE = os.environ.get("WEATHER_URL")
`

// Where a tool's requests go and what carries a credential, as the code's names say it
func TestEgress(t *testing.T) {
	got := egressOf(t, map[string]string{"server.py": pyHead + `
@mcp.tool()
def fixed(city: str) -> str:
    """Return the weather."""
    key = os.environ["WEATHER_API_KEY"]
    return requests.get(API + "/forecast", params={"q": city}, headers={"Authorization": "Bearer " + key}).text

@mcp.tool()
def configured(city: str) -> str:
    """Return the weather."""
    token = os.environ["WEATHER_TOKEN"]
    return requests.get(BASE + "/forecast", headers={"Authorization": token}).text

@mcp.tool()
def callback(url: str) -> str:
    """Return the status."""
    token = os.environ["WEATHER_TOKEN"]
    return requests.get(url, headers={"Authorization": token}).text

@mcp.tool()
def literal(city: str) -> str:
    """Return the news."""
    return requests.get("https://news.example.org/top").text

@mcp.tool()
def quiet(city: str) -> str:
    """Return the name."""
    return city.upper()
`})
	f := got["fixed"]
	if f == nil || len(f.FixedHosts) != 1 || f.FixedHosts[0] != "weather.example.com" || len(f.CallerAddressed) != 0 {
		t.Fatalf("fixed: %+v", f)
	}
	if len(f.CredentialNames) != 1 || f.CredentialNames[0] != "WEATHER_API_KEY" {
		t.Fatalf("fixed credential names: %+v", f)
	}
	if len(f.CredentialCalls) != 1 || f.CredentialCalls[0].Address != "fixed" || f.CredentialCalls[0].To != "weather.example.com" {
		t.Fatalf("fixed credential calls: %+v", f.CredentialCalls)
	}
	c := got["configured"]
	if c == nil || len(c.Configured) != 1 || c.Configured[0] != "BASE" || len(c.CredentialCalls) != 1 || c.CredentialCalls[0].Address != "configured" {
		t.Fatalf("configured: %+v", c)
	}
	k := got["callback"]
	if k == nil || len(k.CallerAddressed) != 1 || !strings.Contains(k.CallerAddressed[0], "server.py:") || len(k.CredentialCalls) != 1 || k.CredentialCalls[0].Address != "caller" {
		t.Fatalf("callback: %+v", k)
	}
	l := got["literal"]
	if l == nil || len(l.FixedHosts) != 1 || l.FixedHosts[0] != "news.example.org" || len(l.CredentialCalls) != 0 {
		t.Fatalf("literal: %+v", l)
	}
	if got["quiet"] != nil {
		t.Fatalf("a tool without network or credentials has no egress: %+v", got["quiet"])
	}
}

// An address the names do not settle is counted, never called the server's own or the caller's
func TestEgressUnsettledAddress(t *testing.T) {
	got := egressOf(t, map[string]string{"server.py": pyHead + `
@mcp.tool()
def routed(kind: str) -> str:
    """Return the report."""
    return requests.get(make_address(kind)).text
`})
	e := got["routed"]
	if e == nil || e.Unsettled != 1 || len(e.FixedHosts)+len(e.Configured)+len(e.CallerAddressed) != 0 {
		t.Fatalf("routed: %+v", e)
	}
}
