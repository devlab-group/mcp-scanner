package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	name     string
	linkname string
	typeflag byte
	mode     int64
	content  string
}

func buildTar(entries []tarEntry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     e.name,
			Linkname: e.linkname,
			Typeflag: typeflag,
			Mode:     e.mode,
			Size:     int64(len(e.content)),
		}
		if hdr.Mode == 0 {
			hdr.Mode = 0o644
		}
		if err := tw.WriteHeader(hdr); err != nil {
			panic(err)
		}
		if e.content != "" {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				panic(err)
			}
		}
	}
	tw.Close()
	return buf.Bytes()
}

type zipEntry struct {
	name    string
	content string
	symlink bool
	mode    os.FileMode
}

func buildZip(entries []zipEntry) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		fh := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		switch {
		case e.symlink:
			fh.SetMode(os.ModeSymlink | 0o777)
		case e.mode != 0:
			fh.SetMode(e.mode)
		default:
			fh.SetMode(0o644)
		}
		w, err := zw.CreateHeader(fh)
		if err != nil {
			panic(err)
		}
		if _, err := w.Write([]byte(e.content)); err != nil {
			panic(err)
		}
	}
	zw.Close()
	return buf.Bytes()
}

func extractInto(t *testing.T, data []byte, format Format, limits Limits) (string, Result, error) {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(bytes.NewReader(data), format, dest, limits)
	return dest, res, err
}

func TestValidTarExtractsCleanly(t *testing.T) {
	data := buildTar([]tarEntry{
		{name: "pkg/", typeflag: tar.TypeDir},
		{name: "pkg/index.js", content: "console.log('hi')"},
		{name: "pkg/lib/util.js", content: "module.exports = {}"},
	})
	dest, res, err := extractInto(t, data, FormatTar, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Files != 2 {
		t.Fatalf("Files = %d, want 2", res.Files)
	}
	got, err := os.ReadFile(filepath.Join(dest, "pkg/index.js"))
	if err != nil || string(got) != "console.log('hi')" {
		t.Fatalf("index.js content = %q, err = %v", got, err)
	}
}

func TestValidZipExtractsCleanly(t *testing.T) {
	data := buildZip([]zipEntry{
		{name: "pkg/index.js", content: "console.log('hi')"},
		{name: "pkg/lib/util.js", content: "module.exports = {}"},
	})
	dest, res, err := extractInto(t, data, FormatZip, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Files != 2 {
		t.Fatalf("Files = %d, want 2", res.Files)
	}
	got, err := os.ReadFile(filepath.Join(dest, "pkg/lib/util.js"))
	if err != nil || string(got) != "module.exports = {}" {
		t.Fatalf("util.js content = %q, err = %v", got, err)
	}
}

func TestExtractedFilesAreNeverExecutable(t *testing.T) {
	tarData := buildTar([]tarEntry{{name: "run.sh", mode: 0o755, content: "#!/bin/sh\necho hi\n"}})
	dest, _, err := extractInto(t, tarData, FormatTar, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, err := os.Stat(filepath.Join(dest, "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("tar-extracted file mode = %v, want 0o644 regardless of the archive entry's declared mode", info.Mode().Perm())
	}

	zipData := buildZip([]zipEntry{{name: "run.sh", mode: 0o755, content: "#!/bin/sh\necho hi\n"}})
	dest, _, err = extractInto(t, zipData, FormatZip, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, err = os.Stat(filepath.Join(dest, "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("zip-extracted file mode = %v, want 0o644 regardless of the archive entry's declared mode", info.Mode().Perm())
	}
}

func TestTarPathTraversalRejected(t *testing.T) {
	data := buildTar([]tarEntry{{name: "../../etc/passwd", content: "root:x:0:0"}})
	_, _, err := extractInto(t, data, FormatTar, DefaultLimits())
	if !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("got %v, want ErrPathTraversal", err)
	}
}

func TestZipPathTraversalRejected(t *testing.T) {
	data := buildZip([]zipEntry{{name: "../../etc/passwd", content: "root:x:0:0"}})
	_, _, err := extractInto(t, data, FormatZip, DefaultLimits())
	if !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("got %v, want ErrPathTraversal", err)
	}
}

func TestPathTraversalNeverWritesOutsideDest(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	marker := filepath.Join(root, "marker")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(marker, 0o755); err != nil {
		t.Fatal(err)
	}
	data := buildTar([]tarEntry{{name: "../marker/pwned.txt", content: "pwned"}})
	if _, err := Extract(bytes.NewReader(data), FormatTar, dest, DefaultLimits()); !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("got %v, want ErrPathTraversal", err)
	}
	if _, err := os.Stat(filepath.Join(marker, "pwned.txt")); !os.IsNotExist(err) {
		t.Fatalf("traversal entry escaped into a sibling directory (stat err = %v)", err)
	}
}

func TestTarAbsolutePathRejected(t *testing.T) {
	data := buildTar([]tarEntry{{name: "/etc/passwd", content: "root:x:0:0"}})
	_, _, err := extractInto(t, data, FormatTar, DefaultLimits())
	if !errors.Is(err, ErrAbsolutePath) {
		t.Fatalf("got %v, want ErrAbsolutePath", err)
	}
}

func TestZipAbsolutePathRejected(t *testing.T) {
	data := buildZip([]zipEntry{{name: "/etc/passwd", content: "root:x:0:0"}})
	_, _, err := extractInto(t, data, FormatZip, DefaultLimits())
	if !errors.Is(err, ErrAbsolutePath) {
		t.Fatalf("got %v, want ErrAbsolutePath", err)
	}
}

func TestSymlinkEscapeRejected(t *testing.T) {
	data := buildTar([]tarEntry{
		{name: "link", typeflag: tar.TypeSymlink, linkname: "../../../etc/passwd"},
	})
	_, _, err := extractInto(t, data, FormatTar, DefaultLimits())
	if !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("got %v, want ErrSymlinkEscape", err)
	}
}

func TestZipSymlinkEscapeRejected(t *testing.T) {
	data := buildZip([]zipEntry{{name: "link", content: "../../../etc/passwd", symlink: true}})
	_, _, err := extractInto(t, data, FormatZip, DefaultLimits())
	if !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("got %v, want ErrSymlinkEscape", err)
	}
}

func TestSymlinkWithinTreeIsAllowed(t *testing.T) {
	data := buildTar([]tarEntry{
		{name: "real.txt", content: "hi"},
		{name: "sub/link", typeflag: tar.TypeSymlink, linkname: "../real.txt"},
	})
	_, res, err := extractInto(t, data, FormatTar, DefaultLimits())
	if err != nil {
		t.Fatalf("a symlink that stays inside the tree must be allowed: %v", err)
	}
	if res.Files != 2 {
		t.Fatalf("Files = %d, want 2", res.Files)
	}
}

func TestHardlinkEscapeRejected(t *testing.T) {
	data := buildTar([]tarEntry{
		{name: "link", typeflag: tar.TypeLink, linkname: "../../../etc/passwd"},
	})
	_, _, err := extractInto(t, data, FormatTar, DefaultLimits())
	if !errors.Is(err, ErrHardlinkEscape) {
		t.Fatalf("got %v, want ErrHardlinkEscape", err)
	}
}

func TestDeviceNodeRejected(t *testing.T) {
	data := buildTar([]tarEntry{{name: "dev/null", typeflag: tar.TypeChar}})
	_, _, err := extractInto(t, data, FormatTar, DefaultLimits())
	if !errors.Is(err, ErrDeviceNode) {
		t.Fatalf("got %v, want ErrDeviceNode", err)
	}
}

func TestZipBombRejectedBySizeLimit(t *testing.T) {
	huge := strings.Repeat("A", 5<<20) // 5MB, compresses to almost nothing
	data := buildZip([]zipEntry{{name: "bomb.txt", content: huge}})
	limits := DefaultLimits()
	limits.MaxFileBytes = 1 << 20 // 1MB
	_, _, err := extractInto(t, data, FormatZip, limits)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("got %v, want ErrFileTooLarge", err)
	}
}

func TestZipDeclaredSizeRejectsInt64Overflow(t *testing.T) {
	f := &zip.File{FileHeader: zip.FileHeader{UncompressedSize64: math.MaxUint64}}
	if _, ok := zipDeclaredSize(f); ok {
		t.Fatal("a declared size above math.MaxInt64 was accepted")
	}

	f = &zip.File{FileHeader: zip.FileHeader{UncompressedSize64: 1 << 20}}
	size, ok := zipDeclaredSize(f)
	if !ok || size != 1<<20 {
		t.Fatalf("got (%d, %v), want (%d, true)", size, ok, 1<<20)
	}
}

func TestAggregateUncompressedLimitRejected(t *testing.T) {
	entries := []zipEntry{
		{name: "a.txt", content: strings.Repeat("a", 1000)},
		{name: "b.txt", content: strings.Repeat("b", 1000)},
		{name: "c.txt", content: strings.Repeat("c", 1000)},
	}
	data := buildZip(entries)
	limits := DefaultLimits()
	limits.MaxFileBytes = 2000
	limits.MaxUncompressedBytes = 1500 // smaller than the sum of all three files
	_, _, err := extractInto(t, data, FormatZip, limits)
	if !errors.Is(err, ErrUncompressedTooLarge) {
		t.Fatalf("got %v, want ErrUncompressedTooLarge", err)
	}
}

func writtenBytes(t *testing.T, dest string) int64 {
	t.Helper()
	var total int64
	filepath.Walk(dest, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}

func TestTotalLimitBoundsBytesWrittenBeforeRejection(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			const totalLimit = 8
			const fileLimit = 64 // larger than totalLimit: the total must still bind
			content := strings.Repeat("x", 32)
			var data []byte
			if format == FormatTar {
				data = buildTar([]tarEntry{{name: "a.txt", content: content}})
			} else {
				data = buildZip([]zipEntry{{name: "a.txt", content: content}})
			}
			limits := Limits{MaxUncompressedBytes: totalLimit, MaxFileBytes: fileLimit, MaxFiles: 10, MaxDepth: 10}
			dest, _, err := extractInto(t, data, format, limits)
			if !errors.Is(err, ErrUncompressedTooLarge) {
				t.Fatalf("got %v, want ErrUncompressedTooLarge", err)
			}
			if written := writtenBytes(t, dest); written > totalLimit+1 {
				t.Fatalf("wrote %d bytes before rejecting; want at most %d (limit+1, for overrun detection)", written, totalLimit+1)
			}
		})
	}
}

func TestTotalLimitExactlyAtLimitSucceeds(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			content := strings.Repeat("x", 10)
			var data []byte
			if format == FormatTar {
				data = buildTar([]tarEntry{{name: "a.txt", content: content}})
			} else {
				data = buildZip([]zipEntry{{name: "a.txt", content: content}})
			}
			// fileLimit exceeds totalLimit, so the total is the binding
			// constraint (MaxFileBytes > MaxUncompressedBytes)
			limits := Limits{MaxUncompressedBytes: 10, MaxFileBytes: 100, MaxFiles: 10, MaxDepth: 10}
			_, res, err := extractInto(t, data, format, limits)
			if err != nil {
				t.Fatalf("got %v, want success at exactly the limit", err)
			}
			if res.UncompressedBytes != 10 {
				t.Fatalf("wrote %d bytes, want 10", res.UncompressedBytes)
			}
		})
	}
}

// One byte past the total limit is rejected, with the same
// MaxFileBytes > MaxUncompressedBytes configuration as the exactly-at-limit
// case above
func TestTotalLimitOneByteOverRejected(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			content := strings.Repeat("x", 11)
			var data []byte
			if format == FormatTar {
				data = buildTar([]tarEntry{{name: "a.txt", content: content}})
			} else {
				data = buildZip([]zipEntry{{name: "a.txt", content: content}})
			}
			limits := Limits{MaxUncompressedBytes: 10, MaxFileBytes: 100, MaxFiles: 10, MaxDepth: 10}
			_, _, err := extractInto(t, data, format, limits)
			if !errors.Is(err, ErrUncompressedTooLarge) {
				t.Fatalf("got %v, want ErrUncompressedTooLarge", err)
			}
		})
	}
}

func TestZeroRemainingBudgetRejectsNextEntry(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			entries := []struct{ name, content string }{
				{"a.txt", strings.Repeat("x", 10)},
				{"b.txt", "y"},
			}
			var data []byte
			if format == FormatTar {
				var te []tarEntry
				for _, e := range entries {
					te = append(te, tarEntry{name: e.name, content: e.content})
				}
				data = buildTar(te)
			} else {
				var ze []zipEntry
				for _, e := range entries {
					ze = append(ze, zipEntry{name: e.name, content: e.content})
				}
				data = buildZip(ze)
			}
			limits := Limits{MaxUncompressedBytes: 10, MaxFileBytes: 100, MaxFiles: 10, MaxDepth: 10}
			_, _, err := extractInto(t, data, format, limits)
			if !errors.Is(err, ErrUncompressedTooLarge) {
				t.Fatalf("got %v, want ErrUncompressedTooLarge", err)
			}
		})
	}
}

func TestDeeplyNestedPathRejected(t *testing.T) {
	name := strings.Repeat("a/", 100) + "file.txt"
	data := buildTar([]tarEntry{{name: name, content: "x"}})
	limits := DefaultLimits()
	limits.MaxDepth = 32
	_, _, err := extractInto(t, data, FormatTar, limits)
	if !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("got %v, want ErrNestingTooDeep", err)
	}
}

func TestTooManyFilesRejected(t *testing.T) {
	var entries []tarEntry
	for i := range 20 {
		entries = append(entries, tarEntry{name: filepath.Join("f", string(rune('a'+i))), content: "x"})
	}
	data := buildTar(entries)
	limits := DefaultLimits()
	limits.MaxFiles = 5
	_, _, err := extractInto(t, data, FormatTar, limits)
	if !errors.Is(err, ErrTooManyFiles) {
		t.Fatalf("got %v, want ErrTooManyFiles", err)
	}
}

func TestCompressedSizeLimitRejected(t *testing.T) {
	data := buildTar([]tarEntry{{name: "a.txt", content: strings.Repeat("x", 10000)}})
	limits := DefaultLimits()
	limits.MaxCompressedBytes = 100
	_, _, err := extractInto(t, data, FormatTar, limits)
	if !errors.Is(err, ErrCompressedTooLarge) {
		t.Fatalf("got %v, want ErrCompressedTooLarge", err)
	}
}

// A stream of exactly max bytes is within the limit, not
// over it
func TestCountingReaderAcceptsExactlyMaxBytes(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 100)
	r := &countingReader{r: bytes.NewReader(data), max: 100}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("exactly max bytes should be accepted, got: %v", err)
	}
	if len(got) != 100 {
		t.Fatalf("got %d bytes, want 100", len(got))
	}
}

func TestCountingReaderRejectsOneByteOverMax(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 101)
	r := &countingReader{r: bytes.NewReader(data), max: 100}
	_, err := io.ReadAll(r)
	if !errors.Is(err, ErrCompressedTooLarge) {
		t.Fatalf("got %v, want ErrCompressedTooLarge", err)
	}
}

func TestTwoHopSymlinkEscapeRejected(t *testing.T) {
	data := buildTar([]tarEntry{
		{name: "d/", typeflag: tar.TypeDir},
		{name: "d/up", typeflag: tar.TypeSymlink, linkname: ".."},
		{name: "esc", typeflag: tar.TypeSymlink, linkname: "d/up/.."},
		{name: "esc/PWNED", content: "pwned"},
	})
	root := t.TempDir()
	marker := filepath.Join(root, "marker")
	if err := os.MkdirAll(marker, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Extract(bytes.NewReader(data), FormatTar, dest, DefaultLimits())
	if err == nil {
		t.Fatal("a two-hop composed symlink escape was not rejected")
	}
	if _, statErr := os.Stat(filepath.Join(marker, "..", "PWNED")); !os.IsNotExist(statErr) {
		t.Fatalf("PWNED landed outside destDir (stat err = %v)", statErr)
	}
}

func TestThreeHopSymlinkEscapeRejected(t *testing.T) {
	data := buildTar([]tarEntry{
		{name: "d/", typeflag: tar.TypeDir},
		{name: "d/up", typeflag: tar.TypeSymlink, linkname: ".."},      // -> destDir
		{name: "hop2", typeflag: tar.TypeSymlink, linkname: "d/up/.."}, // -> destDir/..
		{name: "hop3", typeflag: tar.TypeSymlink, linkname: "hop2/.."}, // -> destDir/../..
		{name: "hop3/PWNED", content: "pwned"},
	})
	dest := filepath.Join(t.TempDir(), "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(bytes.NewReader(data), FormatTar, dest, DefaultLimits()); err == nil {
		t.Fatal("a three-hop composed symlink escape was not rejected")
	}
}

func TestSymlinkedParentDirectoryRejected(t *testing.T) {
	data := buildTar([]tarEntry{
		{name: "real/", typeflag: tar.TypeDir},
		{name: "real/up", typeflag: tar.TypeSymlink, linkname: ".."},     // -> destDir
		{name: "lib/", typeflag: tar.TypeDir},                            // a plain, legitimate-looking directory
		{name: "lib", typeflag: tar.TypeSymlink, linkname: "real/up/.."}, // same name, replaced by a symlink -> destDir/..
		{name: "lib/PWNED", content: "pwned"},
	})
	dest := filepath.Join(t.TempDir(), "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(bytes.NewReader(data), FormatTar, dest, DefaultLimits()); err == nil {
		t.Fatal("a directory swapped for an escaping symlink was not rejected")
	}
}

func TestOSRootEscapeErrorStillContainsExpectedText(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	_, err = root.Open("../outside")
	if err == nil {
		t.Fatal("expected os.Root to refuse a path that escapes it")
	}
	if !strings.Contains(err.Error(), "path escapes") {
		t.Fatalf("os.Root's escape error no longer contains %q (got %q) - update escapeSentinel's match text", "path escapes", err.Error())
	}
}

func TestDetectFormat(t *testing.T) {
	cases := map[string]Format{
		"pkg.tar.gz": FormatTarGz,
		"pkg.tgz":    FormatTarGz,
		"pkg.tar":    FormatTar,
		"pkg.zip":    FormatZip,
	}
	for in, want := range cases {
		got, err := DetectFormat(in)
		if err != nil || got != want {
			t.Fatalf("DetectFormat(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := DetectFormat("pkg.rar"); !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("got %v, want ErrUnknownFormat", err)
	}
}

func TestSymlinkEscapeLeftBehindRejected(t *testing.T) {
	data := buildTar([]tarEntry{
		{name: "d/", typeflag: tar.TypeDir},
		{name: "d/up", typeflag: tar.TypeSymlink, linkname: ".."},
		{name: "esc", typeflag: tar.TypeSymlink, linkname: "d/up/.."},
	})
	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(bytes.NewReader(data), FormatTar, dest, DefaultLimits()); err == nil {
		t.Fatal("extraction left an escaping symlink behind and reported success")
	}
}

func TestSymlinkPlantedBeforeItsHopRejected(t *testing.T) {
	data := buildTar([]tarEntry{
		{name: "esc", typeflag: tar.TypeSymlink, linkname: "d/up/.."},
		{name: "d/", typeflag: tar.TypeDir},
		{name: "d/up", typeflag: tar.TypeSymlink, linkname: ".."},
	})
	dest := t.TempDir()
	if _, err := Extract(bytes.NewReader(data), FormatTar, dest, DefaultLimits()); err == nil {
		t.Fatal("extraction left an escaping symlink behind and reported success")
	}
}

// A hard link to a symlink resolves its relative target from the new name's directory, which can
// turn an internal link into an escape
func TestHardlinkToSymlinkEscapeRejected(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "secret"), []byte("host secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(base, "a", "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	data := buildTar([]tarEntry{
		{name: "d/d/", typeflag: tar.TypeDir},
		{name: "d/d/l", typeflag: tar.TypeSymlink, linkname: "../../secret"},
		{name: "l2", typeflag: tar.TypeLink, linkname: "d/d/l"},
	})
	if _, err := Extract(bytes.NewReader(data), FormatTar, dest, DefaultLimits()); !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("got %v, want ErrSymlinkEscape", err)
	}
}

// Exercise ZIP-specific symlink handling and file limits
func TestZipSymlinkEscapeLeftBehindRejected(t *testing.T) {
	data := buildZip([]zipEntry{
		{name: "d/up", content: "..", symlink: true},
		{name: "esc", content: "d/up/..", symlink: true},
	})
	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(bytes.NewReader(data), FormatZip, dest, DefaultLimits()); !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("got %v, want ErrSymlinkEscape", err)
	}
}

func TestZipTooManyFilesRejected(t *testing.T) {
	data := buildZip([]zipEntry{{name: "a.txt", content: "a"}, {name: "b.txt", content: "b"}, {name: "c.txt", content: "c"}})
	limits := DefaultLimits()
	limits.MaxFiles = 2
	if _, _, err := extractInto(t, data, FormatZip, limits); !errors.Is(err, ErrTooManyFiles) {
		t.Fatalf("got %v, want ErrTooManyFiles", err)
	}
}

func TestDanglingSymlinkIsAllowed(t *testing.T) {
	data := buildTar([]tarEntry{
		{name: "link", typeflag: tar.TypeSymlink, linkname: "not-in-this-archive.txt"},
	})
	dest := t.TempDir()
	if _, err := Extract(bytes.NewReader(data), FormatTar, dest, DefaultLimits()); err != nil {
		t.Fatalf("a dangling symlink was rejected: %v", err)
	}
}
