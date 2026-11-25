package targetfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/bundle"
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/inventory"
)

// tree makes <tmp>/root and <tmp>/outside; the returned root is the scan root
func tree(t *testing.T) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root, outside = filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "sub"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root, outside
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, target, at string) {
	t.Helper()
	if err := os.Symlink(target, at); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func TestReadInsideRoot(t *testing.T) {
	root, _ := tree(t)
	write(t, filepath.Join(root, "sub", "a.txt"), "hello")
	for _, rel := range []string{"sub/a.txt", filepath.Join("sub", "a.txt"), "./sub/a.txt"} {
		data, truncated, err := Read(root, rel, 100)
		if err != nil || truncated || string(data) != "hello" {
			t.Errorf("Read(%q) = %q, %v, %v; want hello", rel, data, truncated, err)
		}
	}
}

func TestSymlinkInsideRootIsFollowed(t *testing.T) {
	root, _ := tree(t)
	write(t, filepath.Join(root, "sub", "real.md"), "inside")
	link(t, filepath.Join("sub", "real.md"), filepath.Join(root, "README.md"))
	data, err := ReadWhole(root, "README.md", 100)
	if err != nil || string(data) != "inside" {
		t.Fatalf("ReadWhole = %q, %v; want the linked file inside the root", data, err)
	}
}

func TestSymlinkOutOfRootIsRefused(t *testing.T) {
	root, outside := tree(t)
	write(t, filepath.Join(outside, "credentials"), "[default]\naws_secret_access_key = SECRET")
	link(t, filepath.Join("..", "outside", "credentials"), filepath.Join(root, "README.md"))
	link(t, filepath.Join(outside, "credentials"), filepath.Join(root, "sub", "abs.md"))
	for _, rel := range []string{"README.md", "sub/abs.md"} {
		data, _, err := Read(root, rel, 1<<20)
		if err == nil || strings.Contains(string(data), "SECRET") {
			t.Errorf("Read(%q) = %q, %v; a link out of the root must fail", rel, data, err)
		}
	}
}

func TestEndlessDeviceIsRefused(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero")
	}
	root, _ := tree(t)
	link(t, "/dev/zero", filepath.Join(root, "package.json"))
	if _, _, err := Read(root, "package.json", 1<<20); err == nil {
		t.Fatal("a link to /dev/zero must fail, not be read")
	}
	// with no root, the path is read as given: still a device, still refused
	if _, _, err := Read("", "/dev/zero", 1<<20); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Read of /dev/zero without a root: err = %v, want ErrNotRegular", err)
	}
}

func TestPathsThatLeaveTheRoot(t *testing.T) {
	root, outside := tree(t)
	write(t, filepath.Join(outside, "x"), "outside")
	for _, rel := range []string{"../outside/x", filepath.Join(outside, "x"), "sub/../../outside/x"} {
		if _, _, err := Read(root, rel, 100); err == nil {
			t.Errorf("Read(%q) succeeded; a path that leaves the root must fail", rel)
		}
	}
}

func TestDirectoryIsNotRegular(t *testing.T) {
	root, _ := tree(t)
	if _, _, err := Read(root, "sub", 100); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestCapAndTruncation(t *testing.T) {
	root, _ := tree(t)
	write(t, filepath.Join(root, "big.txt"), "0123456789")
	data, truncated, err := Read(root, "big.txt", 4)
	if err != nil || !truncated || string(data) != "0123" {
		t.Fatalf("Read = %q, %v, %v; want 0123, truncated", data, truncated, err)
	}
	if data, truncated, err := Read(root, "big.txt", 10); err != nil || truncated || string(data) != "0123456789" {
		t.Fatalf("Read at exactly the size = %q, %v, %v; want whole, not truncated", data, truncated, err)
	}
	if _, err := ReadWhole(root, "big.txt", 9); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadWhole over the cap: err = %v, want ErrTooLarge", err)
	}
}

func TestNoRootReadsThePathAsGiven(t *testing.T) {
	root, _ := tree(t)
	p := filepath.Join(root, "sub", "a.txt")
	write(t, p, "plain")
	if data, err := ReadWhole("", p, 100); err != nil || string(data) != "plain" {
		t.Fatalf("ReadWhole = %q, %v", data, err)
	}
}

func TestCapFollowsWhatTheWalkRead(t *testing.T) {
	g := &graph.Graph{Files: map[string]*graph.File{
		"big.js":    {Path: "big.js", MaxBytes: 1000},
		"bundle.js": {Path: "bundle.js", Bundle: true},
		"small.py":  {Path: "small.py"},
	}}
	for rel, want := range map[string]int64{
		"big.js":     1000,
		"bundle.js":  bundle.MaxSize,
		"small.py":   inventory.DefaultLimits().MaxFileSize,
		"unknown.go": inventory.DefaultLimits().MaxFileSize,
	} {
		if got := Cap(g, rel); got != want {
			t.Errorf("Cap(%q) = %d, want %d", rel, got, want)
		}
	}
}

func TestReadGraphFileReadsOnlyWhatTheWalkParsed(t *testing.T) {
	root, _ := tree(t)
	write(t, filepath.Join(root, "big.js"), strings.Repeat("x", 50)+"TAIL")
	g := &graph.Graph{Root: root, Files: map[string]*graph.File{"big.js": {Path: "big.js", MaxBytes: 50}}}
	data, err := ReadGraphFile(g, "big.js")
	if err != nil || len(data) != 50 || strings.Contains(string(data), "TAIL") {
		t.Fatalf("ReadGraphFile = %d bytes, %v; want the first 50 only", len(data), err)
	}
}

// A missing file is not a refusal; a link out of the tree, a directory and a file over the cap are
func TestRefusedTellsAMissingFileFromARefusal(t *testing.T) {
	root, outside := tree(t)
	write(t, filepath.Join(outside, "x"), "outside")
	write(t, filepath.Join(root, "big.txt"), "0123456789")
	link(t, filepath.Join("..", "outside", "x"), filepath.Join(root, "out.md"))
	if _, err := ReadWhole(root, "missing.json", 100); err == nil || Refused(err) {
		t.Errorf("missing file: err = %v, Refused = %v; want an error that is not a refusal", err, Refused(err))
	}
	for rel, max := range map[string]int64{"out.md": 100, "sub": 100, "big.txt": 4} {
		if _, err := ReadWhole(root, rel, max); !Refused(err) {
			t.Errorf("%s: err = %v, want a refusal", rel, err)
		}
	}
	if Refused(nil) {
		t.Error("Refused(nil) = true")
	}
}
