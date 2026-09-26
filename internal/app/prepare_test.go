package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// Preparation must never treat a non-empty, possibly caller-owned directory as disposable
func TestPackagePrepareRefusesANonEmptyExtractionDirectory(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "not-mine.txt")
	if err := os.WriteFile(victim, []byte("do not delete me"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewPreparer(config.Config{})
	target := model.Target{Kind: model.TargetPackage, Ecosystem: "npm", Package: "whatever", Path: dir}
	ac, cleanup, err := p.Prepare(context.Background(), target)
	if err == nil {
		t.Fatal("expected Prepare to refuse a non-empty extraction directory")
	}
	if ac != nil {
		t.Fatalf("expected no analysis context on refusal, got %+v", ac)
	}
	if cleanup != nil {
		cleanup()
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("the pre-existing file was deleted despite Prepare refusing the directory: %v", err)
	}
}

// A failed download still removes its empty, scanner-owned directory
func TestPackagePrepareCleansUpAnEmptyExtractionDirectoryOnFailure(t *testing.T) {
	dir, err := os.MkdirTemp("", "mcp-scanner-prepare-test-")
	if err != nil {
		t.Fatal(err)
	}

	p := NewPreparer(config.Config{})
	target := model.Target{Kind: model.TargetPackage, Ecosystem: "not-a-real-ecosystem", Package: "whatever", Path: dir}
	_, cleanup, err := p.Prepare(context.Background(), target)
	if err == nil {
		t.Fatal("expected the bogus ecosystem to fail downloadPackage")
	}
	if cleanup == nil {
		t.Fatal("expected a cleanup function even on a download failure")
	}
	cleanup()
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("extraction directory still exists after cleanup: %v", statErr)
	}
}

// ReadCapped accepts the limit exactly and rejects one extra byte
func TestReadCappedRefusesOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCapped(path, 9); err == nil {
		t.Fatal("expected an error for a file over the limit")
	}
	data, err := ReadCapped(path, 10)
	if err != nil {
		t.Fatalf("a file exactly at the limit was refused: %v", err)
	}
	if string(data) != "0123456789" {
		t.Fatalf("got %q", data)
	}
}

// Static targets must use the capped reader
func TestPrepareRefusesAnOversizedStaticTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Lower the cap instead of creating a 100 MB fixture
	orig := MaxStaticSnapshotBytes
	MaxStaticSnapshotBytes = info.Size() - 1
	defer func() { MaxStaticSnapshotBytes = orig }()

	p := NewPreparer(config.Config{})
	target := model.Target{Kind: model.TargetStatic, Path: path}
	if _, _, err := p.Prepare(context.Background(), target); err == nil {
		t.Fatal("expected the oversized static target to be refused")
	}
}

// Sandbox-only snapshots use the same read cap as static targets
func TestSandboxOnlyPrepareRefusesAnOversizedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	orig := MaxStaticSnapshotBytes
	MaxStaticSnapshotBytes = info.Size() - 1
	defer func() { MaxStaticSnapshotBytes = orig }()

	p := NewSandboxOnlyPreparer(config.Config{}, path)
	target := model.Target{Kind: model.TargetStdio, Command: "irrelevant"}
	_, _, err = p.Prepare(context.Background(), target)
	if err == nil {
		t.Fatal("expected the oversized snapshot to be refused")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d byte limit", MaxStaticSnapshotBytes)) {
		t.Fatalf("expected the error to name the limit, got: %v", err)
	}
}
