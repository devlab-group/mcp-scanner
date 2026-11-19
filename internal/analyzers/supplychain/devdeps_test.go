package supplychain

import (
	"context"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/supplychain/osv"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A vulnerable package the lockfile marks "dev": true is not in a production install: it keeps
// its severity but goes to context. The pair: the same vulnerable package installed for
// production in another lockfile stays a plain finding.
func TestDevOnlyDependencyIsContext(t *testing.T) {
	vuln := func(id string) []osv.Vuln {
		return []osv.Vuln{{ID: id, Summary: "bad", DatabaseSpecific: map[string]any{"severity": "CRITICAL"}}}
	}
	q := &fakeQuerier{byCoord: map[osv.Coordinate][]osv.Vuln{
		{Ecosystem: "npm", Name: "tinypool", Version: "1.0.2"}:   vuln("GHSA-test-tiny"),
		{Ecosystem: "npm", Name: "proxy-addr", Version: "2.0.7"}: vuln("GHSA-test-addr"),
		{Ecosystem: "npm", Name: "shared", Version: "1.0.0"}:     vuln("GHSA-test-shared"),
	}}
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", `{"lockfileVersion": 3, "packages": {
  "": {"name": "srv"},
  "node_modules/tinypool": {"version": "1.0.2", "dev": true},
  "node_modules/proxy-addr": {"version": "2.0.7"},
  "node_modules/shared": {"version": "1.0.0", "dev": true}
}}`)
	writeFile(t, dir, "web/package-lock.json", `{"lockfileVersion": 3, "packages": {
  "": {"name": "web"},
  "node_modules/shared": {"version": "1.0.0"}
}}`)
	res := (&Analyzer{}).Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, q))
	got := map[string]model.Finding{}
	for _, f := range res.Findings {
		got[f.Taxonomy[0].ID] = f
	}
	if f := got["GHSA-test-tiny"]; f.Triage != model.TriageContext || f.Severity != model.SeverityCritical {
		t.Errorf("dev-only package: want CRITICAL in context, got %s %q", f.Severity, f.Triage)
	}
	if f := got["GHSA-test-addr"]; f.Triage == model.TriageContext {
		t.Errorf("production package must not be context: %+v", f)
	}
	if f := got["GHSA-test-shared"]; f.Triage == model.TriageContext || f.File != "web/package-lock.json" {
		t.Errorf("a package another lockfile installs for production stays a finding there, got %q in %s", f.Triage, f.File)
	}
}
