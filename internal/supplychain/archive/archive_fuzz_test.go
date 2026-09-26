package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func FuzzExtract(f *testing.F) {
	f.Add(buildTar([]tarEntry{{name: "a/b.txt", content: "hello"}}))
	f.Add(buildZip([]zipEntry{{name: "a/b.txt", content: "hello"}}))
	f.Add(buildTar([]tarEntry{{name: "../../etc/passwd", content: "x"}}))
	f.Add(buildZip([]zipEntry{{name: "link", content: "../../etc/passwd", symlink: true}}))

	f.Add(buildTar([]tarEntry{
		{name: "d/", typeflag: tar.TypeDir},
		{name: "d/up", typeflag: tar.TypeSymlink, linkname: ".."},
		{name: "esc", typeflag: tar.TypeSymlink, linkname: "d/up/.."},
		{name: "esc/PWNED", content: "x"},
	}))
	f.Add(buildTar([]tarEntry{{name: "hard", typeflag: tar.TypeLink, linkname: "../outside"}}))
	f.Add(buildTar([]tarEntry{
		{name: "d/d/", typeflag: tar.TypeDir},
		{name: "d/d/l", typeflag: tar.TypeSymlink, linkname: "../../secret"},
		{name: "l2", typeflag: tar.TypeLink, linkname: "d/d/l"},
	}))
	f.Add([]byte("not an archive at all"))
	f.Add([]byte{})

	limits := Limits{
		MaxCompressedBytes:   1 << 20,
		MaxUncompressedBytes: 4 << 20,
		MaxFiles:             200,
		MaxFileBytes:         1 << 20,
		MaxDepth:             16,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, format := range []Format{FormatTar, FormatTarGz, FormatZip} {
			parent := t.TempDir()
			dest := filepath.Join(parent, "dest")
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := Extract(bytes.NewReader(data), format, dest, limits); err == nil {
				assertNoEscapingLink(t, dest)
			}
			assertNothingOutsideDest(t, parent)
		}
	})
}

func assertNothingOutsideDest(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name() != "dest" {
			t.Fatalf("extraction created %q next to destDir instead of inside it", filepath.Join(parent, e.Name()))
		}
	}
}

// assertNoEscapingLink resolves extracted symlinks through an os.Root, which refuses paths that
// leave dest. Dangling links remain allowed.
func assertNoEscapingLink(t *testing.T, dest string) {
	t.Helper()
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	filepath.WalkDir(dest, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.Type()&os.ModeSymlink == 0 {
			return nil
		}
		rel, _ := filepath.Rel(dest, p)
		if _, err := root.Stat(rel); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a successful extraction left a link that leaves destDir: %s (%v)", rel, err)
		}
		return nil
	})
}
