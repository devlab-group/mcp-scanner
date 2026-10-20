package source

import (
	"context"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func TestRegisterTool_ConfigObjectDescriptionResolves(t *testing.T) {
	dir := "../../testdata/source/registration/registertool_config_object"
	a := &Analyzer{}
	target := model.Target{Kind: model.TargetSource, Path: dir}
	ac := &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()}
	res := a.Analyze(context.Background(), target, ac)

	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, errors: %+v", res.Status, res.Errors)
	}
	for _, f := range res.Findings {
		if f.RuleID == "source.capability_no_description" {
			t.Errorf("want no capability_no_description finding for a config-object-described tool, got %+v", f)
		}
		if f.RuleID == "source.capability_name_unresolved" {
			t.Errorf("want the name resolved from the first positional argument, got %+v", f)
		}
	}

	g, _, err := Build(context.Background(), dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(g.Capabilities) != 1 {
		t.Fatalf("want exactly 1 capability, got %d: %+v", len(g.Capabilities), g.Capabilities)
	}
	c := g.Capabilities[0]
	if !c.NameResolved || c.Name != "config_echo" {
		t.Errorf("want name config_echo resolved from the first positional argument, got %+v", c)
	}
	if !c.DescriptionResolved || c.Description != "Echoes the given text back to the caller." {
		t.Errorf("want description resolved from the config object's description key, got %+v", c)
	}
}
