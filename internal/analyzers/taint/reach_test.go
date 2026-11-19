package taint

import (
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Severity is how bad the sink is if the finding is real; triage is how sure the scanner is that
// it is real. Each source class lands where the MCP threat model puts it.
func TestClassify_SourceClassDecidesSeverityAndTriage(t *testing.T) {
	const header = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";
import * as fs from "fs";
const server = new McpServer({ name: "x", version: "1.0.0" });
`
	cases := []struct {
		name, src                   string
		severity                    model.Severity
		triage                      model.Triage
		class, reach, reachableFrom string
	}{
		{"tool argument keeps the catalogue severity", header + `
server.tool("run", "Runs make", async ({ target }: { target: string }) => {
  execSync("make " + target);
  return { content: [] };
});
`, model.SeverityHigh, model.TriagePotential, sourceMCPInput, reachYes, "tool run"},
		{"environment read in a handler is context", header + `
server.tool("run", "Runs make", async () => {
  const target = process.env.TARGET;
  execSync("make " + target);
  return { content: [] };
});
`, model.SeverityLow, model.TriageContext, sourceEnvironment, reachYes, "tool run"},
		{"code no handler reaches is background", header + `
server.tool("ping", "Answers", async () => ({ content: [] }));
export function releaseScript() {
  const version = process.env.VERSION;
  execSync("git tag " + version);
}
`, model.SeverityInfo, model.TriageContext, sourceEnvironment, reachNo, ""},
		{"a config file in a handler needs review", header + `
server.tool("build", "Builds the configured target", async () => {
  const target = fs.readFileSync("/etc/mcp/target.conf", "utf8");
  execSync("make " + target);
  return { content: [] };
});
`, model.SeverityHigh, model.TriageNeedsReview, sourceExternalContent, reachYes, "tool build"},
		{"no handler in the tree leaves reachability unknown", `import { execSync } from "child_process";
import * as fs from "fs";
export function build() {
  const target = fs.readFileSync("/etc/mcp/target.conf", "utf8");
  execSync("make " + target);
}
`, model.SeverityHigh, model.TriageNeedsReview, sourceExternalContent, reachUnknown, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": tc.src}))
			got := categoryFindings(res, "command_injection")
			if len(got) != 1 {
				t.Fatalf("want one command_injection finding, got %+v", res.Findings)
			}
			f := got[0]
			if f.Triage == "" {
				// Aggregate fills in the default for findings the analyzer left untriaged
				f.Triage, f.TriageReason = model.DefaultTriage(f)
			}
			if f.Severity != tc.severity || f.Triage != tc.triage || f.SourceClass != tc.class || f.Reachability != tc.reach {
				t.Fatalf("got severity=%s triage=%s class=%s reach=%s (%s), want %s %s %s %s",
					f.Severity, f.Triage, f.SourceClass, f.Reachability, f.TriageReason, tc.severity, tc.triage, tc.class, tc.reach)
			}
			if tc.reachableFrom != "" && !strings.Contains(strings.Join(f.ReachableFrom, ","), tc.reachableFrom) {
				t.Fatalf("reachable_from = %v, want %q among them", f.ReachableFrom, tc.reachableFrom)
			}
		})
	}
}
