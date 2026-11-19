package registration

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

// A server tree that also uses a cloud SDK and an infrastructure library: boto3.resource(...) and
// api.root.add_resource("v1") match registration names but register nothing. They are set aside
// with a reason, and the real registrations next to them are still found.
func TestDiscover_LibraryCallsShapedLikeRegistrations(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Python: {
			"server.py": `
import boto3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("store")

class Store:
    def __init__(self, region):
        self.table = boto3.resource("dynamodb", region_name=region)

@mcp.tool()
def get_item(key: str) -> str:
    """Reads one item."""
    return Store("eu-west-1").table.get(key)

def notes(name):
    return name

mcp.resource("notes://{name}")(notes)
`,
			"stack.py": `
from aws_cdk import aws_apigateway as apigw

def routes(api):
    v1 = api.root.add_resource("v1")
    v1.add_resource("{proxy+}")
`,
		},
	})
	Discover(g)
	var tools, resources int
	for _, c := range g.Capabilities {
		switch c.Kind {
		case graph.CapabilityTool:
			tools++
		case graph.CapabilityResource:
			resources++
		}
	}
	if tools != 1 || resources != 1 {
		t.Fatalf("want 1 tool and 1 resource, got %d and %d: %+v", tools, resources, g.Capabilities)
	}
	reasons := map[string]int{}
	for _, s := range g.SkippedRegistrations {
		reasons[s.Reason]++
	}
	if reasons[SkipLibraryModule] != 1 || reasons[SkipNoHandler] != 2 {
		t.Fatalf("want boto3 skipped as a module call and two add_resource calls as handler-less, got %+v", g.SkippedRegistrations)
	}
}

// The pair: a name that only looks like a module. `from app import mcp` binds the server object, and
// a project module named like the receiver is the project's own code; both stay registrations.
func TestDiscover_ImportedServerObjectStillRegisters(t *testing.T) {
	g := buildGraph(t, map[language.ID]map[string]string{
		language.Python: {
			"tools.py": `
from app import mcp
import helpers

def search(q):
    return q

mcp.add_tool(search, "search")
helpers.tool("lookup", "Looks things up", search)
`,
			"helpers.py": `
from mcp.server.fastmcp import FastMCP
`,
		},
	})
	Discover(g)
	if len(g.Capabilities) != 2 {
		t.Fatalf("want both registrations kept, got %+v (skipped %+v)", g.Capabilities, g.SkippedRegistrations)
	}
	if len(g.SkippedRegistrations) != 0 {
		t.Fatalf("nothing should be skipped, got %+v", g.SkippedRegistrations)
	}
}
