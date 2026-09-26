package source

import (
	"context"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func TestEvasion_DirectoryContentAndNameNoLongerExcludeFiles(t *testing.T) {
	for _, dir := range []string{
		"../../testdata/source/inventory/evasion/dist_only",
		"../../testdata/source/inventory/evasion/dot_directory",
		"../../testdata/source/inventory/evasion/generated_header",
		"../../testdata/source/inventory/evasion/generated_suffix",
	} {
		g, cov, err := Build(context.Background(), dir)
		if err != nil {
			t.Fatalf("%s: Build: %v", dir, err)
		}
		if cov.FilesDiscovered == 0 {
			t.Fatalf("%s: want the file discovered despite the evasion attempt, got %+v", dir, cov)
		}
		if cov.FilesParsed == 0 {
			t.Fatalf("%s: want the file parsed, got %+v", dir, cov)
		}
		if len(g.Capabilities) == 0 {
			t.Fatalf("%s: want the registration found, got none", dir)
		}
	}
}

func TestAppliesTo_Package(t *testing.T) {
	a := &Analyzer{}
	if !a.AppliesTo(model.TargetPackage) {
		t.Fatal("want source to apply to a package target")
	}
	if !a.AppliesTo(model.TargetSource) {
		t.Fatal("want source to still apply to a source target")
	}
}

func TestPackageTarget_UsesExtractionDirectoryAsRoot(t *testing.T) {
	a := &Analyzer{}
	extractDir := "../../testdata/source/discovery/go"
	target := model.Target{Kind: model.TargetPackage, Ecosystem: "npm", Package: "example"}
	ac := &analyzer.AnalysisContext{Root: extractDir, Artifacts: analyzer.NewArtifacts()}
	res := a.Analyze(context.Background(), target, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, errors: %+v", res.Status, res.Errors)
	}
	if res.Coverage.FilesDiscovered == 0 {
		t.Fatalf("want the extraction directory scanned, got %+v", res.Coverage)
	}
}

func TestEvasion_EmptyTreeIsNotSafe(t *testing.T) {
	// Use a real empty directory because Git cannot store one and a missing path fails differently
	dir := t.TempDir()
	a := &Analyzer{}
	target := model.Target{Kind: model.TargetSource, Path: dir}
	ac := &analyzer.AnalysisContext{Root: target.Path, Artifacts: analyzer.NewArtifacts()}
	res := a.Analyze(context.Background(), target, ac)

	if res.Status == model.AnalyzerCompleted {
		t.Fatalf("an empty tree must not report COMPLETED, got %+v", res)
	}
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Message, "no candidate source file") {
		t.Fatalf("want the error that says nothing was found, got %+v", res.Errors)
	}
}
