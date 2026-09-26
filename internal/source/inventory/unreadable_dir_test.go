package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWalk_UnreadableDirectoryDowngradesTheScan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits do not work the same way on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the directory would still be readable")
	}

	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "handler.py"), []byte("def handler():\n    pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) }) // let TempDir's own cleanup remove it

	if err := os.WriteFile(filepath.Join(dir, "clean.py"), []byte("def other():\n    pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(res.Files) != 1 || res.Files[0].Path != "clean.py" {
		t.Fatalf("want only clean.py discovered, got %+v", res.Files)
	}

	foundSkip := false
	for _, r := range res.Coverage.SkipReasons {
		if strings.Contains(r, "could not read directory") {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Errorf("want a skip reason naming the unreadable directory, got %v", res.Coverage.SkipReasons)
	}

	foundLimit := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "locked") && strings.Contains(l, "could not be read") {
			foundLimit = true
		}
	}
	if !foundLimit {
		t.Fatalf("want a LimitsHit entry for the unreadable directory, got %v", res.Coverage.LimitsHit)
	}

	if gaps := res.Coverage.Gaps(); len(gaps) == 0 {
		t.Error("want Coverage.Gaps() to report the unreadable directory as a gap, got none")
	}
}
