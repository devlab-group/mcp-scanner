package inventory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalk_RespectsScanRootBoundary(t *testing.T) {
	res, err := Walk(t.Context(), "../../../testdata/source/inventory/boundary", DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(res.Files) != 1 {
		t.Fatalf("want exactly the one file inside the root, got %d: %+v", len(res.Files), res.Files)
	}
	if res.Files[0].Path != "pkg/main.go" {
		t.Fatalf("want pkg/main.go, got %q", res.Files[0].Path)
	}

	for _, f := range res.Files {
		if strings.Contains(f.Abs, "/etc/") || f.Abs == "/etc" {
			t.Fatalf("walk followed the symlink outside the scan root: %s", f.Abs)
		}
	}

	found := false
	for _, r := range res.Coverage.SkipReasons {
		if strings.Contains(r, "symlink escapes scan root") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a skip reason about the symlink escaping the root, got %v", res.Coverage.SkipReasons)
	}

	foundVendor := false
	for _, r := range res.Coverage.SkipReasons {
		if strings.Contains(r, `excluded directory "vendor"`) {
			foundVendor = true
		}
	}
	if !foundVendor {
		t.Fatalf("expected vendor/ to be counted as an excluded directory, got %v", res.Coverage.SkipReasons)
	}

	if res.Coverage.FilesDiscovered < 1 {
		t.Fatalf("want the vendored source file counted as discovered, got %+v", res.Coverage)
	}

	if res.Coverage.FilesSkipped == 0 {
		t.Fatal("expected a nonzero FilesSkipped")
	}
	if len(res.Coverage.SkipReasons) == 0 {
		t.Fatal("every skip must carry a reason")
	}

	if unaccounted := res.Coverage.FilesDiscovered - len(res.Files) - res.Coverage.FilesSkipped; unaccounted != 0 {
		t.Fatalf("coverage accounting must balance exactly: discovered=%d parsed(as files)=%d skipped=%d, unaccounted=%d",
			res.Coverage.FilesDiscovered, len(res.Files), res.Coverage.FilesSkipped, unaccounted)
	}
}

func TestWalk_ArbitraryDotDirectoryIsWalked(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".internal", "shell.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != ".internal/shell.go" {
		t.Fatalf("want .internal/shell.go walked like any other directory, got %+v", res.Files)
	}
	if len(res.Coverage.LimitsHit) != 0 {
		t.Fatalf("a walked directory must not appear in LimitsHit, got %v", res.Coverage.LimitsHit)
	}
}

func TestWalk_DependencyDirsAreExcludedButDowngradeTheScan(t *testing.T) {
	for _, name := range []string{"node_modules", "vendor", "venv", ".venv"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			nested := filepath.Join(dir, name, "helper")
			if err := os.MkdirAll(nested, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(nested, "shell.go"), []byte("package main\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			res, err := Walk(t.Context(), dir, DefaultLimits())
			if err != nil {
				t.Fatalf("Walk: %v", err)
			}
			if len(res.Files) != 0 {
				t.Fatalf("want %s left unwalked, got %+v", name, res.Files)
			}
			if res.Coverage.FilesDiscovered == 0 || res.Coverage.FilesSkipped == 0 {
				t.Fatalf("want the file inside %s counted as discovered and skipped, got %+v", name, res.Coverage)
			}
			if len(res.Coverage.LimitsHit) == 0 {
				t.Fatalf("want excluding %s recorded in LimitsHit, downgrading the scan, got %+v", name, res.Coverage)
			}
		})
	}
}

func TestWalk_EmptyVCSAndCacheDirsStaySilent(t *testing.T) {
	for _, name := range []string{".git", "__pycache__", ".mypy_cache", ".pytest_cache"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			nested := filepath.Join(dir, name)
			if err := os.MkdirAll(nested, 0o755); err != nil {
				t.Fatal(err)
			}
			// Whatever these directories actually hold day to day - a git
			// object, a compiled .pyc - none of it has an extension any
			// language adapter claims
			if err := os.WriteFile(filepath.Join(nested, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			res, err := Walk(t.Context(), dir, DefaultLimits())
			if err != nil {
				t.Fatalf("Walk: %v", err)
			}
			if len(res.Coverage.LimitsHit) != 0 {
				t.Fatalf("want %s excluded silently, no LimitsHit entry, got %v", name, res.Coverage.LimitsHit)
			}
		})
	}
}

func TestWalk_SourcePlantedInCacheDirDowngradesTheScan(t *testing.T) {
	for _, name := range []string{".git", "__pycache__", ".mypy_cache", ".pytest_cache"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			nested := filepath.Join(dir, name)
			if err := os.MkdirAll(nested, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(nested, "shell.go"), []byte("package main\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			res, err := Walk(t.Context(), dir, DefaultLimits())
			if err != nil {
				t.Fatalf("Walk: %v", err)
			}
			if len(res.Coverage.LimitsHit) == 0 {
				t.Fatalf("want %s downgraded once it actually holds source, got %+v", name, res.Coverage)
			}
			if res.Coverage.FilesSkipped == 0 {
				t.Fatalf("want the file inside %s still counted as skipped, got %+v", name, res.Coverage)
			}
		})
	}
}

func TestWalk_SymlinkToOversizedFileHitsSizeLimit(t *testing.T) {
	dir := t.TempDir()
	limits := DefaultLimits()
	limits.MaxFileSize = 1024

	target := filepath.Join(dir, "big.py")
	if err := os.WriteFile(target, make([]byte, limits.MaxFileSize*4), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "handler.py")
	if err := os.Symlink("big.py", link); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, limits)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	var linkEntry *Entry
	for i := range res.Files {
		if res.Files[i].Path == "handler.py" {
			linkEntry = &res.Files[i]
		}
	}
	if linkEntry == nil {
		t.Fatalf("expected handler.py (the symlink) in the inventory, got %+v", res.Files)
	}
	if linkEntry.MaxBytes != limits.MaxFileSize {
		t.Fatalf("symlinked file's real size was not seen: want MaxBytes=%d (capped), got %d", limits.MaxFileSize, linkEntry.MaxBytes)
	}

	found := false
	for _, r := range res.Coverage.LimitsHit {
		if strings.Contains(r, "exceeded the") && strings.Contains(r, "byte size limit") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the size limit to be recorded in Coverage.LimitsHit, got %v", res.Coverage.LimitsHit)
	}
}

func TestWalk_LimitsStopHostileTrees(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxFiles = 0
	res, err := Walk(t.Context(), "../../../testdata/source/inventory/boundary", limits)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Files) != 0 {
		t.Fatalf("MaxFiles=0 should admit no files, got %d", len(res.Files))
	}
	if res.Coverage.FilesSkipped == 0 {
		t.Fatal("expected the discovered file to be recorded as skipped once the limit hit")
	}
}

func TestWalk_SelfReferentialSymlinksDoNotFanOut(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const n = 4
	for i := range n {
		if err := os.Symlink(".", filepath.Join(dir, fmt.Sprintf("link%d", i))); err != nil {
			t.Fatal(err)
		}
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(res.Files) != 1 || res.Files[0].Path != "a.go" {
		t.Fatalf("want exactly a.go admitted once, got %+v", res.Files)
	}

	if res.Coverage.FilesDiscovered != n+1 {
		t.Fatalf("want %d discovered (the file plus each refused symlink), got %d: %+v", n+1, res.Coverage.FilesDiscovered, res.Coverage)
	}
	if res.Coverage.FilesSkipped != n {
		t.Fatalf("want %d skipped (one per duplicate symlink), got %d: %+v", n, res.Coverage.FilesSkipped, res.Coverage)
	}
	if unaccounted := res.Coverage.FilesDiscovered - len(res.Files) - res.Coverage.FilesSkipped; unaccounted != 0 {
		t.Fatalf("coverage accounting must balance exactly, got unaccounted=%d: %+v", unaccounted, res.Coverage)
	}
	if len(res.Coverage.LimitsHit) != 0 {
		t.Fatalf("a directory duplicate is not a resource limit - the content was seen via the first path - got LimitsHit=%v", res.Coverage.LimitsHit)
	}
	if len(res.Coverage.SkipReasons) != 1 || !strings.Contains(res.Coverage.SkipReasons[0], "already walked as") {
		t.Fatalf("want one aggregated skip reason naming the path already walked, got %v", res.Coverage.SkipReasons)
	}
	if !strings.Contains(res.Coverage.SkipReasons[0], "(x4)") {
		t.Fatalf("want the four identical duplicate refusals aggregated into one reason with a count, got %q", res.Coverage.SkipReasons[0])
	}
}

func TestWalk_DirectoryReachedTwiceIsNotDoubleCounted(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "zzreal"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "zzreal", "file.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("zzreal", filepath.Join(dir, "alink")); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(res.Files) != 1 {
		t.Fatalf("want file.go admitted exactly once regardless of the two routes to it, got %+v", res.Files)
	}
	if res.Files[0].Path != "alink/file.go" {
		t.Fatalf("want the file reached via whichever route was walked first (alink), got %q", res.Files[0].Path)
	}

	if res.Coverage.FilesDiscovered != 2 {
		t.Fatalf("want 2 discovered (the file once, plus the duplicate directory entry), got %d: %+v", res.Coverage.FilesDiscovered, res.Coverage)
	}
	if res.Coverage.FilesSkipped != 1 {
		t.Fatalf("want exactly 1 skipped (the duplicate directory), got %d: %+v", res.Coverage.FilesSkipped, res.Coverage)
	}
	if unaccounted := res.Coverage.FilesDiscovered - len(res.Files) - res.Coverage.FilesSkipped; unaccounted != 0 {
		t.Fatalf("coverage accounting must balance exactly, got unaccounted=%d: %+v", unaccounted, res.Coverage)
	}
	if len(res.Coverage.LimitsHit) != 0 {
		t.Fatalf("a directory reached twice is not a coverage gap - it was fully seen via the first route - got LimitsHit=%v", res.Coverage.LimitsHit)
	}
}

func TestWalk_ContextCancellationRecordsALimitAndStopsTheWalk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	res, err := Walk(ctx, dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Files) != 0 {
		t.Fatalf("want nothing read once ctx is already canceled, got %+v", res.Files)
	}
	found := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "deadline") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a deadline entry in LimitsHit - a walk the scanner cut short protects itself, it does not explain away a skip - got %v", res.Coverage.LimitsHit)
	}
}

func TestWalk_SymlinkedFileIsRecordedByItsResolvedPath(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "real")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(sub, "tools.py")
	if err := os.WriteFile(target, []byte("def slugify(name):\n    return name\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.py")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range res.Files {
		if f.Path != "link.py" {
			continue
		}
		found = true
		if f.Abs != want {
			t.Fatalf("want the symlinked entry read by its resolved target %q, got %q", want, f.Abs)
		}
	}
	if !found {
		t.Fatalf("want the symlinked file in the inventory, got %+v", res.Files)
	}
}
