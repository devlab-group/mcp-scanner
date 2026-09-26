// Package archive extracts hostile input under size and count limits. Lexical checks reject
// obvious escapes, while os.Root enforces the boundary. os.Root.Symlink does not validate the
// target, so a final pass resolves links after every archive entry exists. Extraction is not
// transactional: a caller receiving an error must discard destDir because it may be partial.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Format identifies the archive container
type Format string

const (
	FormatTar   Format = "tar"
	FormatTarGz Format = "tar.gz"
	FormatZip   Format = "zip"
)

// DetectFormat guesses the format from a file name
func DetectFormat(name string) (Format, error) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return FormatTarGz, nil
	case strings.HasSuffix(lower, ".tar"):
		return FormatTar, nil
	case strings.HasSuffix(lower, ".zip"):
		return FormatZip, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnknownFormat, name)
	}
}

// Limits bounds what Extract will do. Zero disables a given limit, which
// Extract treats as "unbounded" - callers scanning hostile input should
// always set every field.
type Limits struct {
	MaxCompressedBytes   int64
	MaxUncompressedBytes int64
	MaxFiles             int
	MaxFileBytes         int64
	MaxDepth             int
}

// DefaultLimits is a conservative ceiling for scanning a single published
// package or MCP-declared archive, not for general-purpose archive tools
func DefaultLimits() Limits {
	return Limits{
		MaxCompressedBytes:   100 << 20,
		MaxUncompressedBytes: 500 << 20,
		MaxFiles:             20000,
		MaxFileBytes:         100 << 20,
		MaxDepth:             32,
	}
}

// Result summarizes what Extract wrote
type Result struct {
	Files             int
	Dirs              int
	UncompressedBytes int64
}

var (
	ErrPathTraversal        = errors.New("archive: entry escapes the extraction root")
	ErrAbsolutePath         = errors.New("archive: entry has an absolute path")
	ErrSymlinkEscape        = errors.New("archive: symlink target escapes the extraction root")
	ErrHardlinkEscape       = errors.New("archive: hardlink target escapes the extraction root")
	ErrDeviceNode           = errors.New("archive: entry is a device, fifo or socket node")
	ErrUnsupportedType      = errors.New("archive: entry has an unsupported type")
	ErrTooManyFiles         = errors.New("archive: entry count exceeds the configured limit")
	ErrFileTooLarge         = errors.New("archive: a single entry exceeds the configured size limit")
	ErrUncompressedTooLarge = errors.New("archive: total uncompressed size exceeds the configured limit")
	ErrCompressedTooLarge   = errors.New("archive: compressed input exceeds the configured limit")
	ErrNestingTooDeep       = errors.New("archive: entry path nesting exceeds the configured limit")
	ErrUnknownFormat        = errors.New("archive: unrecognized archive format")
)

// Extract reads src and writes its regular files, directories and safe
// symlinks/hardlinks under destDir, which must already exist. Every write
// goes through an *os.Root opened on destDir, so the kernel - not a string
// comparison - refuses anything that would land outside it.
func Extract(src io.Reader, format Format, destDir string, limits Limits) (Result, error) {
	root, err := os.OpenRoot(destDir)
	if err != nil {
		return Result{}, fmt.Errorf("archive: open extraction root: %w", err)
	}
	defer root.Close()

	limited := &countingReader{r: src, max: limits.MaxCompressedBytes}

	switch format {
	case FormatTar:
		return extractTar(limited, root, limits)
	case FormatTarGz:
		gz, err := gzip.NewReader(limited)
		if err != nil {
			return Result{}, fmt.Errorf("archive: invalid gzip stream: %w", err)
		}
		defer gz.Close()
		return extractTar(gz, root, limits)
	case FormatZip:
		buf, err := io.ReadAll(limited)
		if err != nil {
			if errors.Is(err, ErrCompressedTooLarge) {
				return Result{}, err
			}
			return Result{}, fmt.Errorf("archive: read zip stream: %w", err)
		}
		zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			return Result{}, fmt.Errorf("archive: invalid zip stream: %w", err)
		}
		return extractZip(zr, root, limits)
	default:
		return Result{}, fmt.Errorf("%w: %s", ErrUnknownFormat, format)
	}
}

// countingReader errors once more than max bytes have been read from the underlying reader,
// catching an oversized or infinite compressed input before it can be decompressed into
// something worse. Exactly max bytes are valid; reading the next byte is what trips the limit.
type countingReader struct {
	r   io.Reader
	max int64
	n   int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.max > 0 && c.n > c.max {
		return 0, ErrCompressedTooLarge
	}
	if c.max > 0 && int64(len(p)) > c.max-c.n+1 {
		p = p[:c.max-c.n+1]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.max > 0 && c.n > c.max {
		return n, ErrCompressedTooLarge
	}
	return n, err
}

// sanitizedName cleans an archive entry name to a root-relative path and
// rejects an absolute path, any ".." component, or nesting deeper than
// maxDepth. It is a fast, specific-error rejection for the common cases;
// it does not by itself guarantee containment (see the package doc) - the
// *os.Root every caller resolves this name against does.
func sanitizedName(name string, maxDepth int) (clean string, err error) {
	if name == "" {
		return "", fmt.Errorf("%w: empty entry name", ErrPathTraversal)
	}
	if filepath.IsAbs(name) || isWindowsAbs(name) {
		return "", ErrAbsolutePath
	}
	clean = filepath.Clean(filepath.ToSlash(name))
	if clean == "." {
		return "", fmt.Errorf("%w: entry names the extraction root itself", ErrPathTraversal)
	}
	if slices.Contains(strings.Split(clean, "/"), "..") {
		return "", ErrPathTraversal
	}
	depth := strings.Count(clean, "/") + 1
	if maxDepth > 0 && depth > maxDepth {
		return "", ErrNestingTooDeep
	}
	return filepath.FromSlash(clean), nil
}

// isWindowsAbs catches a drive-letter path (C:\...) even when running on a
// platform where filepath.IsAbs would not recognize it, since an archive
// can be built on any OS
func isWindowsAbs(name string) bool {
	if len(name) < 3 {
		return false
	}
	drive := name[0]
	isLetter := (drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')
	return isLetter && name[1] == ':' && (name[2] == '\\' || name[2] == '/')
}

// validateLinkTargetLexical is the same fast, specific-error rejection as sanitizedName,
// applied to a symlink/hardlink target: a purely lexical join-and-clean relative to
// entryPath's directory. It cannot see an intermediate symlink, so os.Root and the final
// symlink verification remain the filesystem boundary.
func validateLinkTargetLexical(entryPath, target string, escapeErr error) error {
	if target == "" {
		return fmt.Errorf("%w: empty link target", escapeErr)
	}
	if filepath.IsAbs(target) || isWindowsAbs(target) {
		return escapeErr
	}
	linkDir := filepath.Dir(entryPath)
	resolved := filepath.Clean(filepath.Join(linkDir, filepath.FromSlash(target)))
	if resolved == ".." || strings.HasPrefix(resolved, ".."+string(filepath.Separator)) {
		return escapeErr
	}
	return nil
}

func extractTar(r io.Reader, root *os.Root, limits Limits) (Result, error) {
	tr := tar.NewReader(r)
	var res Result
	var links []string
	entries := 0

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, fmt.Errorf("archive: invalid tar entry: %w", err)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader || hdr.Typeflag == tar.TypeXHeader {
			continue
		}

		clean, err := sanitizedName(hdr.Name, limits.MaxDepth)
		if err != nil {
			return res, err
		}

		entries++
		if limits.MaxFiles > 0 && entries > limits.MaxFiles {
			return res, ErrTooManyFiles
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(clean, 0o755); err != nil {
				return res, escapeSentinel(err, ErrPathTraversal, "create dir")
			}
			res.Dirs++

		case tar.TypeSymlink:
			if err := validateLinkTargetLexical(clean, hdr.Linkname, ErrSymlinkEscape); err != nil {
				return res, err
			}
			if err := root.MkdirAll(filepath.Dir(clean), 0o755); err != nil {
				return res, escapeSentinel(err, ErrPathTraversal, "create dir")
			}
			if err := root.Symlink(hdr.Linkname, clean); err != nil {
				return res, escapeSentinel(err, ErrSymlinkEscape, "create symlink")
			}
			links = append(links, clean)
			res.Files++

		case tar.TypeLink:
			if err := validateLinkTargetLexical(clean, hdr.Linkname, ErrHardlinkEscape); err != nil {
				return res, err
			}
			targetClean, err := sanitizedName(hdr.Linkname, limits.MaxDepth)
			if err != nil {
				return res, err
			}
			if err := root.MkdirAll(filepath.Dir(clean), 0o755); err != nil {
				return res, escapeSentinel(err, ErrPathTraversal, "create dir")
			}
			if err := root.Link(targetClean, clean); err != nil {
				return res, escapeSentinel(err, ErrHardlinkEscape, "create hardlink")
			}
			// A hard link to a symlink creates another name for that symlink. Track the new name
			// because its relative target resolves from a different directory.
			if fi, err := root.Lstat(clean); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				links = append(links, clean)
			}
			res.Files++

		case tar.TypeReg, tar.TypeRegA:
			if limits.MaxFileBytes > 0 && hdr.Size > limits.MaxFileBytes {
				return res, ErrFileTooLarge
			}
			if err := declaredSizeFitsRemaining(limits, res.UncompressedBytes, hdr.Size); err != nil {
				return res, err
			}
			if err := root.MkdirAll(filepath.Dir(clean), 0o755); err != nil {
				return res, escapeSentinel(err, ErrPathTraversal, "create dir")
			}
			written, err := writeCapped(root, clean, tr, effectiveFileCap(limits, res.UncompressedBytes))
			if err != nil {
				return res, err
			}
			if limits.MaxFileBytes > 0 && written > limits.MaxFileBytes {
				return res, ErrFileTooLarge
			}
			res.Files++
			res.UncompressedBytes += written
			if limits.MaxUncompressedBytes > 0 && res.UncompressedBytes > limits.MaxUncompressedBytes {
				return res, ErrUncompressedTooLarge
			}

		case tar.TypeBlock, tar.TypeChar, tar.TypeFifo:
			return res, ErrDeviceNode

		default:
			return res, fmt.Errorf("%w: tar type %q for %s", ErrUnsupportedType, string(hdr.Typeflag), hdr.Name)
		}
	}
	if err := verifySymlinks(root, links); err != nil {
		return res, err
	}
	return res, nil
}

func extractZip(zr *zip.Reader, root *os.Root, limits Limits) (Result, error) {
	var res Result
	var links []string
	entries := 0

	for _, f := range zr.File {
		clean, err := sanitizedName(f.Name, limits.MaxDepth)
		if err != nil {
			return res, err
		}
		entries++
		if limits.MaxFiles > 0 && entries > limits.MaxFiles {
			return res, ErrTooManyFiles
		}

		mode := f.Mode()
		switch {
		case mode&os.ModeSymlink != 0:
			target, err := readEntryCapped(f, 4096)
			if err != nil {
				return res, fmt.Errorf("archive: read symlink target: %w", err)
			}
			if err := validateLinkTargetLexical(clean, string(target), ErrSymlinkEscape); err != nil {
				return res, err
			}
			if err := root.MkdirAll(filepath.Dir(clean), 0o755); err != nil {
				return res, escapeSentinel(err, ErrPathTraversal, "create dir")
			}
			if err := root.Symlink(string(target), clean); err != nil {
				return res, escapeSentinel(err, ErrSymlinkEscape, "create symlink")
			}
			links = append(links, clean)
			res.Files++

		case mode.IsDir():
			if err := root.MkdirAll(clean, 0o755); err != nil {
				return res, escapeSentinel(err, ErrPathTraversal, "create dir")
			}
			res.Dirs++

		case mode.IsRegular():
			declared, ok := zipDeclaredSize(f)
			if !ok {
				return res, ErrFileTooLarge
			}
			if limits.MaxFileBytes > 0 && declared > limits.MaxFileBytes {
				return res, ErrFileTooLarge
			}
			if err := declaredSizeFitsRemaining(limits, res.UncompressedBytes, declared); err != nil {
				return res, err
			}
			if err := root.MkdirAll(filepath.Dir(clean), 0o755); err != nil {
				return res, escapeSentinel(err, ErrPathTraversal, "create dir")
			}
			rc, err := f.Open()
			if err != nil {
				return res, fmt.Errorf("archive: open entry: %w", err)
			}
			written, err := writeCapped(root, clean, rc, effectiveFileCap(limits, res.UncompressedBytes))
			rc.Close()
			if err != nil {
				return res, err
			}
			if limits.MaxFileBytes > 0 && written > limits.MaxFileBytes {
				return res, ErrFileTooLarge
			}
			res.Files++
			res.UncompressedBytes += written
			if limits.MaxUncompressedBytes > 0 && res.UncompressedBytes > limits.MaxUncompressedBytes {
				return res, ErrUncompressedTooLarge
			}

		default:
			return res, fmt.Errorf("%w: zip mode %v for %s", ErrUnsupportedType, mode, f.Name)
		}
	}
	if err := verifySymlinks(root, links); err != nil {
		return res, err
	}
	return res, nil
}

// verifySymlinks runs after extraction because an earlier link may compose with one created later.
// Resolving the completed chain catches escapes os.Root.Symlink permits; dangling links are allowed.
func verifySymlinks(root *os.Root, links []string) error {
	for _, p := range links {
		if _, err := root.Stat(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrSymlinkEscape, p)
		}
	}
	return nil
}

// effectiveFileCap returns the cap writeCapped should enforce for the next entry: the
// tighter of the per-file limit and what remains of the total uncompressed budget. Zero means
// the budget is exhausted; -1 means neither limit is configured.
func effectiveFileCap(limits Limits, uncompressedSoFar int64) int64 {
	cap := int64(-1)
	if limits.MaxFileBytes > 0 {
		cap = limits.MaxFileBytes
	}
	if limits.MaxUncompressedBytes > 0 {
		remaining := max(limits.MaxUncompressedBytes-uncompressedSoFar, 0)
		if cap < 0 || remaining < cap {
			cap = remaining
		}
	}
	return cap
}

// zipDeclaredSize returns a zip entry's declared UncompressedSize64 as an int64, or
// ok=false if it does not fit. Rejecting the overflow prevents a huge uint64 declaration from
// wrapping into a small value that passes later size checks.
func zipDeclaredSize(f *zip.File) (int64, bool) {
	if f.UncompressedSize64 > math.MaxInt64 {
		return 0, false
	}
	return int64(f.UncompressedSize64), true
}

// declaredSizeFitsRemaining rejects an entry whose declared size alone
// already exceeds what remains of the total uncompressed budget, before
// anything is written. This is a fast path only - a declared size can lie,
// so writeCapped's streaming cap (via effectiveFileCap) stays the
// authoritative check for an entry that under-declares its own size.
func declaredSizeFitsRemaining(limits Limits, uncompressedSoFar, declaredSize int64) error {
	if limits.MaxUncompressedBytes <= 0 {
		return nil
	}
	remaining := max(limits.MaxUncompressedBytes-uncompressedSoFar, 0)
	if declaredSize > remaining {
		return ErrUncompressedTooLarge
	}
	return nil
}

// writeCapped copies from r to a new file at clean (resolved through root), refusing to
// write more than cap bytes even if the declared size lied - this is the actual zip/tar
// bomb defense, while the metadata check is only a fast path. Extracted files use mode 0644
// and are never made executable from archive-controlled mode bits.
func writeCapped(root *os.Root, clean string, r io.Reader, cap int64) (int64, error) {
	out, err := root.OpenFile(clean, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, escapeSentinel(err, ErrPathTraversal, "create file")
	}
	limit := int64(1<<63 - 1)
	if cap >= 0 {
		limit = cap + 1 // read one extra byte so the caller can detect the overrun
	}
	written, copyErr := io.Copy(out, io.LimitReader(r, limit))
	closeErr := out.Close()
	if copyErr != nil {
		return written, fmt.Errorf("archive: write file: %w", copyErr)
	}
	if closeErr != nil {
		return written, closeErr
	}
	return written, nil
}

func readEntryCapped(f *zip.File, max int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, max))
}

// escapeSentinel turns the *os.Root escape error - "path escapes from parent", unexported
// by the os package - into our own sentinel, so a composed multi-hop escape that only the
// kernel catches still produces the same specific error a lexically-obvious one does
func escapeSentinel(err error, sentinel error, verb string) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "path escapes") {
		return sentinel
	}
	return fmt.Errorf("archive: %s: %w", verb, err)
}
