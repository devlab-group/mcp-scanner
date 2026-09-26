package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalk_UnsupportedLanguageFileDowngradesTheScan(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Program.cs"), []byte("class Program {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Files) != 0 {
		t.Fatalf("want the C# file left out of Files, got %+v", res.Files)
	}
	if res.Coverage.FilesDiscovered != 1 || res.Coverage.FilesSkipped != 1 {
		t.Fatalf("want the file counted as discovered and skipped, got %+v", res.Coverage)
	}
	if len(res.Coverage.SkipReasons) == 0 {
		t.Fatal("want a skip reason naming the unsupported extension")
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("want a LimitsHit entry - this is the scanner's own incapacity, not an explained skip that leaves the scan clean")
	}
	found := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, `".cs"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("want the .cs extension named in LimitsHit, got %v", res.Coverage.LimitsHit)
	}
}

func TestWalk_UnsupportedLanguageFileDowngradesEvenBesideParsedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Program.cs"), []byte("class Program {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tools.py"), []byte("def slugify(name):\n    return name\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != "tools.py" {
		t.Fatalf("want only tools.py admitted to Files, got %+v", res.Files)
	}
	if res.Coverage.FilesDiscovered != 2 {
		t.Fatalf("want both files discovered, got %d", res.Coverage.FilesDiscovered)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("want the C# file to downgrade the scan even though the Python file parsed cleanly")
	}
}

func TestWalk_OrdinaryNonSourceStaysUncounted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tools.py"), []byte("def slugify(name):\n    return name\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if res.Coverage.FilesDiscovered != 1 {
		t.Fatalf("want only tools.py counted as discovered, README.md must stay invisible, got %+v", res.Coverage)
	}
	if len(res.Coverage.LimitsHit) != 0 {
		t.Fatalf("want no LimitsHit from a plain non-source file, got %v", res.Coverage.LimitsHit)
	}
}

func TestWalk_UnsupportedLanguageFileCountedInsideExcludedDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "vendor", "dep")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "Dep.cs"), []byte("class Dep {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if res.Coverage.FilesDiscovered == 0 || res.Coverage.FilesSkipped == 0 {
		t.Fatalf("want the vendored C# file counted as discovered and skipped, got %+v", res.Coverage)
	}
}

func TestWalk_ExtensionlessScriptIsCountedLikeAShellScript(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		mode os.FileMode
	}{
		{"run", "#!/bin/sh\nexec python3 server.py\n", 0o644}, // shebang, not executable
		{"launch", "exec python3 server.py\n", 0o755},         // executable, no shebang
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.name), []byte(tc.body), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "server.py"), []byte("def hello(name):\n    return name\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			res, err := Walk(t.Context(), dir, DefaultLimits())
			if err != nil {
				t.Fatalf("Walk: %v", err)
			}
			if len(res.Files) != 1 || res.Files[0].Path != "server.py" {
				t.Fatalf("want only server.py admitted to Files, got %+v", res.Files)
			}
			if res.Coverage.FilesDiscovered != 2 || res.Coverage.FilesSkipped != 1 {
				t.Fatalf("want the wrapper counted as discovered and skipped, got %+v", res.Coverage)
			}
			if len(res.Coverage.LimitsHit) == 0 {
				t.Fatalf("want the wrapper to downgrade the scan the way a .sh name already does, got %+v", res.Coverage)
			}
		})
	}
}

func TestWalk_ExtensionlessNonScriptStaysUncounted(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"LICENSE":  "MIT\n",
		"Makefile": "build:\n\tgo build ./...\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "tools.py"), []byte("def slugify(name):\n    return name\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if res.Coverage.FilesDiscovered != 1 {
		t.Fatalf("want only tools.py counted as discovered, got %+v", res.Coverage)
	}
	if len(res.Coverage.LimitsHit) != 0 {
		t.Fatalf("want no LimitsHit from files that are not scripts, got %v", res.Coverage.LimitsHit)
	}
}
