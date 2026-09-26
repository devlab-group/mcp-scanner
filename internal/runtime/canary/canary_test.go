package canary

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateNeverLeaksRealEnv(t *testing.T) {
	os.Setenv("MCP_SCANNER_TEST_SECRET", "this-is-a-real-value-do-not-leak")
	defer os.Unsetenv("MCP_SCANNER_TEST_SECRET")

	real := os.Environ()
	realValues := map[string]bool{}
	for _, kv := range real {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 && parts[1] != "" {
			realValues[parts[1]] = true
		}
	}

	set, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	for env, val := range set.Env {
		if _, ok := os.LookupEnv(env); ok && env != "" {
			// The name may coincidentally collide with a real var name
			// (e.g. PATH is common); what matters is the value
		}
		if realValues[val] {
			t.Fatalf("canary env %s got a value that matches a real environment variable value", env)
		}
	}
	for _, c := range set.Canaries {
		if realValues[c.Value] {
			t.Fatalf("canary %s (%s) value matches a real environment variable value", c.ID, c.Kind)
		}
	}

	// No canary content may reference a real path outside a sandbox-owned
	// temp dir; canary file paths are always relative, never absolute
	for _, c := range set.Canaries {
		if c.Path != "" && filepath.IsAbs(c.Path) {
			t.Fatalf("canary %s has an absolute path %q; canary paths must be relative to a scanner-owned temp dir", c.ID, c.Path)
		}
	}
	for rel := range set.Files {
		if filepath.IsAbs(rel) {
			t.Fatalf("canary file %q is absolute; must be relative", rel)
		}
	}
}

func TestGenerateIsPerRunAndAttributable(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if a.RunID == b.RunID {
		t.Fatalf("two runs produced the same run id")
	}
	if len(a.Canaries) == 0 {
		t.Fatalf("no canaries generated")
	}
	seen := map[string]bool{}
	for _, c := range a.Canaries {
		if c.ID == "" {
			t.Fatalf("canary has no ID, cannot attribute a hit to a run")
		}
		if seen[c.ID] {
			t.Fatalf("duplicate canary ID %q", c.ID)
		}
		seen[c.ID] = true
		if c.Value == "" {
			t.Fatalf("canary %s has no value", c.ID)
		}
		if !strings.Contains(strings.ToUpper(c.Value), "CANARY") && c.Kind != KindSSHKey {
			t.Fatalf("canary %s (%s) value %q is not unmistakably synthetic", c.ID, c.Kind, c.Value)
		}
	}
}

func TestMaterializeStaysUnderRoot(t *testing.T) {
	set, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	root := t.TempDir()
	if err := set.Materialize(root); err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil || strings.HasPrefix(rel, "..") {
				t.Fatalf("materialized file %q escaped root %q", path, root)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

func TestMaterializeRejectsPathEscape(t *testing.T) {
	outside := t.TempDir()
	root := t.TempDir()

	set := &Set{Files: map[string]string{
		"../" + filepath.Base(outside) + "/escaped.txt": "should never land here",
	}}
	if err := set.Materialize(root); !errors.Is(err, ErrPathEscape) {
		t.Fatalf("Materialize error = %v, want ErrPathEscape", err)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("root %q has %d entries after a rejected write, want 0", root, len(entries))
	}
	if _, err := os.Stat(filepath.Join(outside, "escaped.txt")); !os.IsNotExist(err) {
		t.Fatalf("escaped.txt was written outside root: stat err = %v", err)
	}
}

// TestMaterializeRejectsAbsolutePath covers the other shape cleanRelPath
// rejects: an absolute Path bypasses the root join entirely rather than
// composing with it
func TestMaterializeRejectsAbsolutePath(t *testing.T) {
	target := filepath.Join(t.TempDir(), "absolute.txt")
	root := t.TempDir()

	set := &Set{Files: map[string]string{target: "should never land here"}}
	if err := set.Materialize(root); !errors.Is(err, ErrPathEscape) {
		t.Fatalf("Materialize error = %v, want ErrPathEscape", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("absolute.txt was written: stat err = %v", err)
	}
}
