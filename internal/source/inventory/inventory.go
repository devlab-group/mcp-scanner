// Package inventory walks regular source files within a hard root boundary and
// records reported skips. Fixed cache and dependency directories, unreadable
// directories, non-regular files, refused symlinks, source classification, and
// resource limits may omit files. Generated-file claims in names or contents and
// arbitrary dot paths do not.
package inventory

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Entry is one file worth parsing
type Entry struct {
	// Path is relative to the scan root, using forward slashes, so results
	// are stable across platforms
	Path string
	Abs  string
	Size int64
	Lang language.ID
	// MaxBytes truncates an oversized file instead of dropping it. The limit
	// still downgrades coverage.
	MaxBytes int64
}

// Limits bound how much of a hostile tree the walk will look at
type Limits struct {
	MaxFileSize     int64 // truncate a single file larger than this
	MaxTotalSize    int64 // stop once the sum of included file sizes reaches this
	MaxFiles        int   // stop once this many files have been included
	MaxSymlinkDepth int   // longest chain of directory symlinks followed
	MaxDirDepth     int   // longest chain of plain (non-symlink) directories descended
}

// DefaultLimits are generous enough for a real repository and small enough
// that a crafted tree (a symlink loop, a directory of many huge files)
// cannot turn a scan into a memory exhaustion attack
func DefaultLimits() Limits {
	return Limits{
		// Shape, not only size, can make parsing pathological; this bounds impact
		MaxFileSize:     512 << 10,
		MaxTotalSize:    256 << 20, // 256 MiB across the whole tree
		MaxFiles:        20000,
		MaxSymlinkDepth: 8,
		// Prevent unbounded recursion while staying above practical nesting
		MaxDirDepth: 1000,
	}
}

// silentSkipDirs are machine-generated and, under normal operation, hold no first-party
// source of their own - VCS metadata and interpreter caches - so excluding them costs
// nothing to look at first. The walker still counts source found inside them and turns that
// exclusion into a coverage gap; only a fixed allowlist may be silent.
var silentSkipDirs = map[string]bool{
	".git":          true,
	"__pycache__":   true,
	".mypy_cache":   true,
	".pytest_cache": true,
}

// reportedSkipDirs hold third-party code excluded to keep scans focused and bounded. Each hit is
// also a LimitsHit, not merely a SkipReason, because excluded executable code cannot support SAFE.
var reportedSkipDirs = map[string]bool{
	"vendor":       true,
	"node_modules": true,
	".venv":        true,
	"venv":         true,
}

// Result is what one walk found
type Result struct {
	Root     string
	Files    []Entry
	Coverage model.Coverage
}

// Walk collects the files under root that a language adapter claims, respecting root as a
// hard boundary: a symlink that resolves outside root is skipped and never followed. A deadline
// stops the walk as a recorded limit rather than returning an apparently complete partial list.
func Walk(ctx context.Context, root string, limits Limits) (*Result, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving scan root: %w", err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, fmt.Errorf("resolving scan root: %w", err)
	}

	w := &walker{
		root:       absRoot,
		canonical:  canonicalRoot,
		limits:     limits,
		res:        &Result{Root: absRoot},
		skipCounts: map[string]int{},
		dirSkips:   map[string]int{},
		extSkips:   map[string]int{},
		limitsHit:  map[string]bool{},
		seenDirs:   map[string]string{},
	}
	if err := w.walkDir(ctx, absRoot, canonicalRoot, 0, 0); err != nil {
		return nil, err
	}

	// One entry per distinct reason with a count, so a tree with ten
	// thousand vendored files does not produce ten thousand identical
	// strings in the report
	reasons := slices.Sorted(maps.Keys(w.skipCounts))
	for _, r := range reasons {
		n := w.skipCounts[r]
		if n == 1 {
			w.res.Coverage.SkipReasons = append(w.res.Coverage.SkipReasons, r)
		} else {
			w.res.Coverage.SkipReasons = append(w.res.Coverage.SkipReasons, fmt.Sprintf("%s (x%d)", r, n))
		}
	}
	// Directory exclusions are reported by how many source files they actually held, not by how
	// many directories matched: "1 directory skipped" hides a node_modules with ten thousand
	// files behind the same sentence as an empty one
	dirNames := slices.Sorted(maps.Keys(w.dirSkips))
	for _, name := range dirNames {
		n := w.dirSkips[name]
		if n == 0 {
			continue
		}
		w.res.Coverage.SkipReasons = append(w.res.Coverage.SkipReasons,
			fmt.Sprintf("%d source file(s) skipped in excluded directory %q", n, name))
	}
	if w.truncated > 0 {
		w.res.Coverage.LimitsHit = append(w.res.Coverage.LimitsHit,
			fmt.Sprintf("%d file(s) exceeded the %d byte size limit and were parsed only up to it", w.truncated, w.limits.MaxFileSize))
	}
	// Unsupported-language files, one entry per extension with how many were found - the same
	// shape as the dirSkips accounting above
	extNames := slices.Sorted(maps.Keys(w.extSkips))
	for _, ext := range extNames {
		reason := fmt.Sprintf("%d source file(s) with extension %q were not analyzed: no adapter in this build parses that language", w.extSkips[ext], ext)
		if ext == "" {
			reason = fmt.Sprintf("%d executable or shebang file(s) with no extension were not analyzed: no adapter in this build parses a bare script", w.extSkips[ext])
		}
		w.res.Coverage.SkipReasons = append(w.res.Coverage.SkipReasons, reason)
		w.res.Coverage.LimitsHit = append(w.res.Coverage.LimitsHit, reason)
	}
	return w.res, nil
}

type walker struct {
	root      string
	canonical string
	limits    Limits
	res       *Result
	totalSize int64
	stopped   bool // true once MaxFiles or MaxTotalSize was hit; no more files are added to res.Files, but the walk keeps going so it can still say how much that left out
	truncated int  // files included past MaxFileSize, read only up to it

	skipCounts map[string]int
	dirSkips   map[string]int // excluded directory name -> source files it held
	extSkips   map[string]int // unsupported-language extension -> source files it held; the "" key is the extensionless scripts looksLikeScript recognized
	limitsHit  map[string]bool

	// seenDirs bounds fan-out: canonical directory path -> the root-relative path the walk
	// first entered it under
	seenDirs map[string]string
}

func (w *walker) skip(reason string) {
	w.res.Coverage.FilesSkipped++
	w.skipCounts[reason]++
}

// skipSymlink counts a refused entry as both discovered and skipped so coverage
// accounting remains balanced
func (w *walker) skipSymlink(reason string) {
	w.res.Coverage.FilesDiscovered++
	w.skip(reason)
}

// skipDuplicateDir counts the duplicate entry without recounting content already
// reached through its canonical path. This is not a coverage limit.
func (w *walker) skipDuplicateDir(first string) {
	w.skipSymlink(fmt.Sprintf("directory already walked as %q; a second path to the same directory was not walked again", first))
}

// recordLimit notes that a hard resource limit stopped the walk from
// including more files. Unlike a skip reason, this always downgrades the
// scan (model.Coverage.Gaps()) - a limit is the scanner protecting itself,
// never grounds to call anything it did not get to look at safe.
func (w *walker) recordLimit(reason string) {
	if w.limitsHit[reason] {
		return
	}
	w.limitsHit[reason] = true
	w.res.Coverage.LimitsHit = append(w.res.Coverage.LimitsHit, reason)
}

// skipDir tallies every source file inside an excluded directory into both FilesDiscovered
// and FilesSkipped, so the report says how much was excluded rather than counting the
// directory as a single skip regardless of what it held
func (w *walker) skipDir(name, full string) (n int, truncated bool) {
	n, truncated = countSourceFiles(full, w.limits.MaxSymlinkDepth)
	w.res.Coverage.FilesDiscovered += n
	w.res.Coverage.FilesSkipped += n
	w.dirSkips[name] += n
	return n, truncated
}

// countSourceFiles counts source under an excluded directory without following symlinks. It can
// undercount after a read or depth failure; truncated reports that uncertainty so the caller
// still creates a coverage gap.
func countSourceFiles(dir string, depth int) (n int, truncated bool) {
	if depth <= 0 {
		return 0, true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Could not tell what this directory held - not the same thing as
		// finding it genuinely empty. Reporting truncated here means the
		// caller downgrades the scan instead of silently counting an
		// unreadable subdirectory the same as an empty one.
		return 0, true
	}
	for _, e := range entries {
		if e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			sub, subTruncated := countSourceFiles(full, depth-1)
			n += sub
			truncated = truncated || subTruncated
			continue
		}
		// Unsupported-language files count too. Otherwise placing one inside vendor,
		// node_modules, or another excluded directory could avoid the coverage downgrade.
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if language.ForExt(ext) != nil || language.IsUnsupportedSource(ext) || (ext == "" && looksLikeScript(full, e)) {
			n++
		}
	}
	return n, truncated
}

// walkDir bounds recursion depth and reads each canonical directory once,
// preventing symlink fan-out and duplicate traversal through aliases. Canonical paths, rather
// than lexical paths, ensure two aliases of the same directory cannot multiply the work.
func (w *walker) walkDir(ctx context.Context, dir, canonicalDir string, symlinkDepth, dirDepth int) error {
	if err := ctx.Err(); err != nil {
		// A walk cut short here is the scanner enforcing its own deadline, not an exclusion it can
		// explain - the same reason a timed-out parse (source.Build, parser.ParseTimeout) lands in
		// LimitsHit rather than SkipReasons
		w.recordLimit("scan deadline reached before the directory walk finished; the rest of the tree was not read")
		return nil
	}
	if first, ok := w.seenDirs[canonicalDir]; ok {
		w.skipDuplicateDir(first)
		return nil
	}
	rel, err := filepath.Rel(w.root, dir)
	if err != nil {
		rel = dir
	}
	w.seenDirs[canonicalDir] = rel

	if dirDepth > w.limits.MaxDirDepth {
		if n, truncated := countSourceFiles(dir, w.limits.MaxSymlinkDepth); n > 0 || truncated {
			w.res.Coverage.FilesDiscovered += n
			w.res.Coverage.FilesSkipped += n
			w.recordLimit(fmt.Sprintf(
				"directory nesting exceeded the %d-level depth limit at %q; it and its contents were not read",
				w.limits.MaxDirDepth, rel))
		}
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		// An unreadable directory is not a deliberate exclusion or an empty directory; like
		// MaxDirDepth, it means the scanner was blocked
		detail := err
		if pe, ok := err.(*fs.PathError); ok {
			// PathError.Error includes the absolute host path, which must not cross the report boundary
			detail = pe.Err
		}
		w.skip(fmt.Sprintf("could not read directory %q: %v", rel, detail))
		w.recordLimit(fmt.Sprintf(
			"directory %q could not be read (%v); any source it holds was not seen", rel, detail))
		return nil
	}
	for _, de := range entries {
		// w.stopped no longer aborts the walk early: once a limit is hit,
		// every remaining file is still visited, just not added to
		// res.Files - considerFile counts it as discovered and skipped
		// instead, so the walk can still say how much a limit left out
		// rather than going silent about the rest of the tree
		name := de.Name()
		full := filepath.Join(dir, name)

		if de.Type()&fs.ModeSymlink != 0 {
			w.handleSymlink(ctx, full, symlinkDepth, dirDepth)
			continue
		}

		if de.IsDir() {
			if silentSkipDirs[name] {
				if n, truncated := w.skipDir(name, full); n > 0 || truncated {
					w.recordLimit(fmt.Sprintf("directory %q was excluded from the scan and held source that was not read", name))
				}
				continue
			}
			if reportedSkipDirs[name] {
				w.skipDir(name, full)
				w.recordLimit(fmt.Sprintf("directory %q was excluded from the scan and not read", name))
				continue
			}
			// No symlink component was added going from dir to full - de is
			// confirmed not a symlink above - so the child's canonical form
			// is its parent's canonical form plus its own name, with no
			// second call to EvalSymlinks needed
			if err := w.walkDir(ctx, full, filepath.Join(canonicalDir, name), symlinkDepth, dirDepth+1); err != nil {
				return err
			}
			continue
		}

		w.considerFile(full, full, de)
	}
	return nil
}

func (w *walker) handleSymlink(ctx context.Context, full string, symlinkDepth, dirDepth int) {
	if symlinkDepth >= w.limits.MaxSymlinkDepth {
		w.skipSymlink("symlink chain too deep")
		return
	}
	target, err := filepath.EvalSymlinks(full)
	if err != nil {
		w.skipSymlink("dangling or unresolvable symlink")
		return
	}
	rel, err := filepath.Rel(w.canonical, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		w.skipSymlink("symlink escapes scan root")
		return
	}
	info, err := os.Stat(target)
	if err != nil {
		w.skipSymlink("symlink target unreadable")
		return
	}
	if info.IsDir() {
		// walkDir keys w.seenDirs by canonical target. A symlink to an already visited directory
		// is rejected there instead of being read and traversed again.
		if err := w.walkDir(ctx, full, target, symlinkDepth+1, dirDepth+1); err != nil {
			w.skipSymlink(fmt.Sprintf("error walking symlinked directory: %v", err))
		}
		return
	}
	// target is the canonical path EvalSymlinks checked above. considerFile records it as Entry.Abs,
	// and Build later opens that path instead of following the original link again. This narrows the
	// check-to-open TOCTOU window and keeps the report name separate from the path read.
	w.considerFile(full, target, statDirEntry{info})
}

// statDirEntry adapts os.FileInfo to fs.DirEntry for the resolved target of
// a symlink, so considerFile can treat it like any other entry
type statDirEntry struct{ os.FileInfo }

func (s statDirEntry) Type() fs.FileMode          { return s.FileInfo.Mode().Type() }
func (s statDirEntry) Info() (fs.FileInfo, error) { return s.FileInfo, nil }

// looksLikeScript identifies executable or shebang-prefixed extensionless files. Reading two
// content bytes can only add a coverage gap, never let scanned content exclude itself.
func looksLikeScript(path string, de fs.DirEntry) bool {
	info, err := de.Info()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if info.Mode().Perm()&0o111 != 0 {
		return true
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var head [2]byte
	n, _ := io.ReadFull(f, head[:])
	return n == 2 && head[0] == '#' && head[1] == '!'
}

// considerFile decides whether one file joins the inventory. Nothing here looks at the
// file's own name beyond its extension, or at its content, to decide it can be left out:
// what gets analyzed is not a decision scanned content, or whoever named its files, gets to
// make.
func (w *walker) considerFile(full, readPath string, de fs.DirEntry) {
	ext := strings.ToLower(filepath.Ext(full))
	adapter := language.ForExt(ext)
	if adapter == nil {
		if language.IsUnsupportedSource(ext) || (ext == "" && looksLikeScript(readPath, de)) {
			// Unsupported source is a coverage gap, unlike ordinary non-source files
			w.res.Coverage.FilesDiscovered++
			w.res.Coverage.FilesSkipped++
			w.extSkips[ext]++
			return
		}
		// Deliberately not a skip: a README or a PNG is not a gap in coverage, it is simply not
		// source code, and counting every non-source file as "skipped" would bury the exclusions
		// that do matter (reportedSkipDirs) in noise nobody can act on
		return
	}

	info, err := de.Info()
	if err != nil {
		w.res.Coverage.FilesDiscovered++
		w.skip(fmt.Sprintf("could not stat file: %v", err))
		return
	}
	w.res.Coverage.FilesDiscovered++

	// os.ReadFile on a FIFO blocks until something opens the other end,
	// which is forever in an operator-supplied tree, and no --timeout ends
	// it because the read is not watching a context. A device, a socket
	// and a FIFO are all "not a directory" and none of them is source.
	if !info.Mode().IsRegular() {
		w.skip(fmt.Sprintf("not a regular file (%s)", info.Mode().Type()))
		return
	}

	// Once MaxFiles or MaxTotalSize has been hit, nothing more is added to
	// the result - but the walk still reaches every remaining candidate
	// (w.stopped no longer aborts it early), so each one is still counted
	// here rather than never being examined at all
	if w.stopped {
		w.skip("scan limit already reached; not examined")
		return
	}
	if len(w.res.Files) >= w.limits.MaxFiles {
		w.recordLimit(fmt.Sprintf("file count limit reached (%d files)", w.limits.MaxFiles))
		w.stopped = true
		w.skip("scan limit already reached; not examined")
		return
	}
	readSize := min(info.Size(), w.limits.MaxFileSize) // only this much will actually be read
	if w.totalSize+readSize > w.limits.MaxTotalSize {
		w.recordLimit(fmt.Sprintf("total scan size limit reached (%d bytes)", w.limits.MaxTotalSize))
		w.stopped = true
		w.skip("scan limit already reached; not examined")
		return
	}

	rel, err := filepath.Rel(w.root, full)
	if err != nil {
		rel = full
	}
	entry := Entry{
		Path: filepath.ToSlash(rel),
		Abs:  readPath,
		Size: info.Size(),
		Lang: adapter.ID,
	}
	// A file over the size limit is still included rather than dropped
	// whole - whatever it holds past the limit is unread either way, so
	// this is downgraded the same as any other limit, not treated as a
	// skip with an excuse
	if info.Size() > w.limits.MaxFileSize {
		entry.MaxBytes = w.limits.MaxFileSize
		w.truncated++
	}
	w.totalSize += readSize
	w.res.Files = append(w.res.Files, entry)
}
