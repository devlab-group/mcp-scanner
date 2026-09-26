package yara

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func rulesDirForTest(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "rules", "yara")
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("rules directory %s not found: %v", dir, err)
	}
	return dir
}

func TestYaraRuleFilesAreStructurallySane(t *testing.T) {
	dir := rulesDirForTest(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && (filepath.Ext(e.Name()) == ".yar" || filepath.Ext(e.Name()) == ".yara") {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		t.Fatalf("no *.yar files found under %s", dir)
	}

	for _, name := range files {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		src := string(data)
		if strings.TrimSpace(src) == "" {
			t.Errorf("%s is empty", path)
			continue
		}
		if strings.Count(src, "{") != strings.Count(src, "}") {
			t.Errorf("%s: unbalanced braces", path)
		}
		ruleCount := strings.Count(src, "rule ")
		if ruleCount == 0 {
			t.Errorf("%s declares no rule", path)
		}
		titleCount := strings.Count(src, "title =")
		if titleCount < ruleCount {
			t.Errorf("%s: %d rule(s) but only %d meta.title entries", path, ruleCount, titleCount)
		}
	}
}

func TestEmbeddedRulesMatchSource(t *testing.T) {
	sourceDir := rulesDirForTest(t)
	embeddedDir := filepath.Join("rulesdata")

	readYarFiles := func(dir string) map[string][]byte {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		out := map[string][]byte{}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".yar" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			out[e.Name()] = data
		}
		return out
	}

	source := readYarFiles(sourceDir)
	embedded := readYarFiles(embeddedDir)

	for name, want := range source {
		got, ok := embedded[name]
		if !ok {
			t.Errorf("rulesdata/%s is missing; copy it from rules/yara/%s", name, name)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("rulesdata/%s has drifted from rules/yara/%s; copy the source file over the embedded one", name, name)
		}
	}
	for name := range embedded {
		if _, ok := source[name]; !ok {
			t.Errorf("rulesdata/%s has no matching file in rules/yara/; remove it or add the source", name)
		}
	}
}

type fixtureTool struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

type fixtureSnapshot struct {
	Tools []fixtureTool `yaml:"tools"`
}

type caseFile struct {
	Rule       string          `yaml:"rule"`
	ExpectFire bool            `yaml:"expect_fire"`
	Note       string          `yaml:"note"`
	Snapshot   fixtureSnapshot `yaml:"snapshot"`
}

func TestFixtureCorpusParses(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "rules", "yara", "cases")
	var total int
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		total++
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var c caseFile
		if err := yaml.Unmarshal(data, &c); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		if c.Rule == "" {
			t.Errorf("%s: missing rule", path)
		}
		if len(c.Snapshot.Tools) == 0 {
			t.Errorf("%s: fixture has no tools to scan", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if total == 0 {
		t.Fatal("no yara fixtures found")
	}
	t.Logf("yara fixture corpus: %d fixtures parsed; firing behavior is unverified without -tags yara", total)
}
