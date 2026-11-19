package dossier

import (
	"context"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

func TestBuild_RecordsTheServerForLaterReview(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"package.json": `{"name": "weather-mcp", "version": "1.4.0", "dependencies": {"@modelcontextprotocol/sdk": "^1.12.0", "zod": "^3.23.0"}}`,
		"README.md":    "# Weather MCP\nForecasts for a city.\n",
		"server.ts": `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "weather", version: "1.4.0" });
server.tool("forecast", "Gets the forecast for a city", async ({ city }: { city: string }) => {
  const key = process.env.WEATHER_API_KEY;
  const res = await fetch("https://api.weather.invalid/v1/forecast?city=" + city);
  return { content: [{ type: "text", text: await res.text() }] };
});
`,
	})
	d, err := Build(context.Background(), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Repository.Manifests) != 1 || d.Repository.Manifests[0].MCPSDK["@modelcontextprotocol/sdk"] != "^1.12.0" {
		t.Fatalf("manifest/MCP SDK not recorded: %+v", d.Repository.Manifests)
	}
	if len(d.Servers) == 0 || d.Servers[0].Name != "weather" || d.Servers[0].Version != "1.4.0" {
		t.Fatalf("server identity not recorded: %+v", d.Servers)
	}
	if !strings.Contains(d.Repository.Readme, "Weather MCP") {
		t.Fatalf("readme not recorded")
	}
	if len(d.Capabilities) != 1 {
		t.Fatalf("want one capability, got %+v", d.Capabilities)
	}
	c := d.Capabilities[0]
	if c.Name != "forecast" || c.Handler == nil || !strings.Contains(c.Handler.Source, "fetch(") {
		t.Fatalf("capability or handler source missing: %+v", c)
	}
	if c.Behavior == nil || !c.Behavior.Network || len(c.Behavior.URLs) != 0 && !strings.HasPrefix(c.Behavior.URLs[0], "https://") {
		t.Fatalf("behavior not recorded: %+v", c.Behavior)
	}
}
