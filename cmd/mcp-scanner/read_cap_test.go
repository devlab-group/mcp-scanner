package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/internal/app"
)

// Cap whole-file reads of untrusted snapshots, baselines, and client configs
func TestCLIReadsOfHostileAdjacentFilesAreCapped(t *testing.T) {
	orig := app.MaxStaticSnapshotBytes
	app.MaxStaticSnapshotBytes = 16
	t.Cleanup(func() { app.MaxStaticSnapshotBytes = orig })

	dir := t.TempDir()
	big := strings.Repeat("x", 64)

	snap := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(snap, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSnapshotFile(snap); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("loadSnapshotFile on an oversized file: %v, want the size limit", err)
	}

	baseline := filepath.Join(dir, "baseline.yaml")
	if err := os.WriteFile(baseline, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(baseline); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("loadBaseline on an oversized file: %v, want the size limit", err)
	}

	// Discovery reports capped files as skipped rather than returning an error
	small := filepath.Join(dir, "fits.json")
	if err := os.WriteFile(small, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ReadCapped(snap, app.MaxStaticSnapshotBytes); err == nil {
		t.Error("ReadCapped accepted a file over the cap")
	}
}
