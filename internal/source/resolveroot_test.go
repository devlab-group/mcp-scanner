package source

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveRoot_PrefersAndEnforcesTheConfiguredRoot: a caller
// that set ac.Root has fixed the scan boundary, and target.Path must not
// be able to widen or move it
func TestResolveRoot_PrefersAndEnforcesTheConfiguredRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "sub")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	t.Run("root only", func(t *testing.T) {
		got, err := ResolveRoot("", root)
		if err != nil || got != root {
			t.Fatalf("got %q, %v; want %q, nil", got, err, root)
		}
	})

	t.Run("target only, no configured root", func(t *testing.T) {
		got, err := ResolveRoot(outside, "")
		if err != nil || got != outside {
			t.Fatalf("got %q, %v; want %q, nil", got, err, outside)
		}
	})

	t.Run("both set, target under root: root wins", func(t *testing.T) {
		got, err := ResolveRoot(inside, root)
		if err != nil || got != root {
			t.Fatalf("got %q, %v; want the configured root %q, nil", got, err, root)
		}
	})

	t.Run("both set, target outside root: refused", func(t *testing.T) {
		if _, err := ResolveRoot(outside, root); err == nil {
			t.Fatal("want an error when target.Path is not under ac.Root, got nil")
		}
	})

	t.Run("neither set", func(t *testing.T) {
		got, err := ResolveRoot("", "")
		if err != nil || got != "" {
			t.Fatalf("got %q, %v; want empty, nil", got, err)
		}
	})
}
