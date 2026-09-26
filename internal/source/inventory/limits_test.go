package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalk_FileCountLimitFinishesTheCount(t *testing.T) {
	dir := "../../../testdata/source/discovery/go" // 8 real .go files
	limits := DefaultLimits()
	limits.MaxFiles = 3

	res, err := Walk(t.Context(), dir, limits)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Files) != 3 {
		t.Fatalf("want exactly MaxFiles=3 files included, got %d", len(res.Files))
	}
	if res.Coverage.FilesDiscovered != 8 {
		t.Fatalf("want all 8 files still discovered despite the limit, got %d", res.Coverage.FilesDiscovered)
	}
	if res.Coverage.FilesSkipped != 5 {
		t.Fatalf("want the 5 files past the limit counted as skipped, got %d", res.Coverage.FilesSkipped)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("want the file count limit recorded in LimitsHit")
	}
	found := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "file count limit") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a file-count-limit entry in LimitsHit, got %v", res.Coverage.LimitsHit)
	}
}

// TestWalk_TotalSizeLimitFinishesTheCount is the same case for
// MaxTotalSize: reaching it must not abandon the rest of the tree either
func TestWalk_TotalSizeLimitFinishesTheCount(t *testing.T) {
	dir := "../../../testdata/source/discovery/go"
	limits := DefaultLimits()
	limits.MaxTotalSize = 1 // the very first file already exceeds this

	res, err := Walk(t.Context(), dir, limits)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Files) != 0 {
		t.Fatalf("want no files included under a 1-byte total limit, got %d", len(res.Files))
	}
	if res.Coverage.FilesDiscovered != 8 {
		t.Fatalf("want all 8 files still discovered despite the limit, got %d", res.Coverage.FilesDiscovered)
	}
	if res.Coverage.FilesSkipped != 8 {
		t.Fatalf("want all 8 files counted as skipped, got %d", res.Coverage.FilesSkipped)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("want the total-size limit recorded in LimitsHit")
	}
}

func TestWalk_OversizedFileIsTruncatedNotDropped(t *testing.T) {
	dir := t.TempDir()
	padding := strings.Repeat("x", 5<<20) // 5 MiB, over the 512 KiB default
	content := "package main\n\nfunc Vulnerable() {}\n\n// " + padding + "\n"
	if err := os.WriteFile(filepath.Join(dir, "big.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("want the oversized file still included, got %d files", len(res.Files))
	}
	if res.Files[0].MaxBytes != DefaultLimits().MaxFileSize {
		t.Fatalf("want MaxBytes set to the size limit, got %d", res.Files[0].MaxBytes)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("want the size limit recorded in LimitsHit, downgrading the scan")
	}
}

func TestWalk_DeepCacheDirDowngradesRatherThanUndercounting(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxSymlinkDepth = 2 // small on purpose, so the test tree stays small

	dir := t.TempDir()
	nested := filepath.Join(dir, "__pycache__")
	deep := nested
	for i := 0; i < limits.MaxSymlinkDepth+2; i++ {
		deep = filepath.Join(deep, "nested")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "shell.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, limits)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("want the depth cap to downgrade the scan rather than reporting the directory empty")
	}
}

func TestWalk_DirDepthLimitDowngradesRatherThanRecursingForever(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxDirDepth = 5 // small on purpose, so the test tree stays small

	dir := t.TempDir()
	deep := dir
	for i := 0; i < limits.MaxDirDepth+3; i++ {
		deep = filepath.Join(deep, "nested")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "shell.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, limits)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("want the depth limit to downgrade the scan rather than reading past it in silence")
	}
	if res.Coverage.FilesDiscovered == 0 {
		t.Fatal("want the file past the depth limit still counted as discovered, not silently uncounted")
	}
}
