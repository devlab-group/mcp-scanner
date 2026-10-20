// Package testutil holds helpers shared by tests in several packages
package testutil

import (
	"context"
	"debug/elf"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/supplychain"
)

// DynamicSystemBinary returns a dynamically linked system binary, which the scratch sandbox image
// cannot run because it has no ELF interpreter, or skips the test when the host has none
func DynamicSystemBinary(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"/bin/true", "/bin/echo", "/bin/cat", "/bin/ls", "/usr/bin/env"} {
		f, err := elf.Open(candidate)
		if err != nil {
			continue
		}
		dynamic := false
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				dynamic = true
				break
			}
		}
		f.Close()
		if dynamic {
			return candidate
		}
	}
	t.Skip("no dynamically linked system binary found among the usual candidates")
	return ""
}

// WriteTree writes files, keyed by path relative to the root, into a fresh temporary directory and
// returns that directory
func WriteTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// CountPackageExtractionDirs counts package extraction directories in the system temp directory,
// so a test can check that a scan removed the one it created
func CountPackageExtractionDirs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), supplychain.ExtractionDirPrefix) {
			n++
		}
	}
	return n
}

// CancelAfter reports cancellation once Err has been called more than Limit times, so a test can
// stop work part way without depending on a clock
type CancelAfter struct {
	context.Context
	Limit int32
	calls atomic.Int32
}

func (c *CancelAfter) Err() error {
	if c.calls.Add(1) > c.Limit {
		return context.Canceled
	}
	return nil
}
