package readiness

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func TestAnalyzeNoSnapshotIsSkipped(t *testing.T) {
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStatic, Path: "x"}, &analyzer.AnalysisContext{})
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("status = %s, want SKIPPED", res.Status)
	}
}

func TestCancelledContextIsPartial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &Analyzer{}
	res := a.Analyze(ctx, model.Target{Kind: model.TargetStatic, Path: "x"}, &analyzer.AnalysisContext{
		Snapshot: &model.Snapshot{Instructions: "hi"},
	})
	if res.Status != model.AnalyzerPartial {
		t.Fatalf("status = %s, want PARTIAL", res.Status)
	}
}

func TestCheckAuthSignalReadsResponseHeader(t *testing.T) {
	declared := &model.Snapshot{Transport: model.TransportInfo{
		Headers: map[string]string{"WWW-Authenticate": `Bearer realm="mcp"`},
	}}
	if fs := checkAuthSignal(declared); len(fs) != 0 {
		t.Fatalf("a server that sent a WWW-Authenticate challenge was still flagged as declaring no auth: %v", fs)
	}

	undeclared := &model.Snapshot{}
	fs := checkAuthSignal(undeclared)
	if len(fs) != 1 || fs[0].RuleID != "readiness.no-auth-declared" {
		t.Fatalf("a snapshot with neither a header nor a capability signal was not flagged: %v", fs)
	}
}

// --- corpus-driven tests ---------------------------------------------

type fixtureTool struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Annotations map[string]any `yaml:"annotations"`
	InputSchema map[string]any `yaml:"input_schema"`
}

type fixtureResource struct {
	URI         string `yaml:"uri"`
	URITemplate string `yaml:"uri_template"`
	Description string `yaml:"description"`
}

type fixtureSnapshot struct {
	Instructions string            `yaml:"instructions"`
	Tools        []fixtureTool     `yaml:"tools"`
	Resources    []fixtureResource `yaml:"resources"`
	Templates    []fixtureResource `yaml:"resource_templates"`
	Capabilities map[string]any    `yaml:"capabilities"`
	Headers      map[string]string `yaml:"response_headers"`
}

func (f fixtureSnapshot) toModel() *model.Snapshot {
	snap := &model.Snapshot{Instructions: f.Instructions, Capabilities: f.Capabilities}
	snap.Transport.Headers = f.Headers
	for _, t := range f.Tools {
		snap.Tools = append(snap.Tools, model.ToolInfo{
			Name: t.Name, Description: t.Description, Annotations: t.Annotations, InputSchema: t.InputSchema,
		})
	}
	toResource := func(r fixtureResource) model.ResourceInfo {
		return model.ResourceInfo{URI: r.URI, URITemplate: r.URITemplate, Description: r.Description}
	}
	for _, r := range f.Resources {
		snap.Resources = append(snap.Resources, toResource(r))
	}
	for _, r := range f.Templates {
		snap.Templates = append(snap.Templates, toResource(r))
	}
	return snap
}

type caseFile struct {
	Rule       string          `yaml:"rule"`
	ExpectFire bool            `yaml:"expect_fire"`
	Note       string          `yaml:"note"`
	Snapshot   fixtureSnapshot `yaml:"snapshot"`
}

func TestCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "rules", "readiness")
	a := &Analyzer{}

	var total, pass int
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		t.Run(rel, func(t *testing.T) {
			total++
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			var tc caseFile
			if err := yaml.Unmarshal(data, &tc); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			if tc.Rule == "" {
				t.Fatalf("%s: missing rule", path)
			}

			res := a.Analyze(context.Background(), model.Target{Kind: model.TargetStatic, Path: "x"}, &analyzer.AnalysisContext{
				Snapshot: tc.Snapshot.toModel(),
			})
			for _, f := range res.Findings {
				if err := f.Validate(); err != nil {
					t.Errorf("finding from rule %s fails Finding.Validate: %v", f.RuleID, err)
				}
			}

			fired := false
			for _, f := range res.Findings {
				if f.RuleID == tc.Rule {
					fired = true
				}
			}
			if tc.ExpectFire && !fired {
				t.Errorf("expected %s to fire, it did not", tc.Rule)
				return
			}
			if !tc.ExpectFire && fired {
				t.Errorf("expected %s NOT to fire, it did", tc.Rule)
				return
			}
			pass++
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if total == 0 {
		t.Fatal("no fixtures found")
	}
	t.Logf("readiness corpus: %d/%d fixtures behaved as declared (%.1f%% precision on this corpus)",
		pass, total, 100*float64(pass)/float64(total))
}

// checkIDs are every readiness rule id, used to enforce fixture discipline:
// each one needs at least one firing and one clean fixture
var checkIDs = []string{
	"readiness.no-instructions",
	"readiness.tool-missing-description",
	"readiness.tool-missing-schema",
	"readiness.destructive-not-annotated",
	"readiness.no-auth-declared",
	"readiness.resource-unconstrained-uri",
}

func TestEveryCheckHasFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "rules", "readiness", "cases")
	haveFire := map[string]bool{}
	haveClear := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var c caseFile
		if err := yaml.Unmarshal(data, &c); err != nil {
			return err
		}
		if c.ExpectFire {
			haveFire[c.Rule] = true
		} else {
			haveClear[c.Rule] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for _, id := range checkIDs {
		if !haveFire[id] {
			t.Errorf("check %s has no fixture where it is expected to fire", id)
		}
		if !haveClear[id] {
			t.Errorf("check %s has no fixture where it is expected to stay clear", id)
		}
	}
}
