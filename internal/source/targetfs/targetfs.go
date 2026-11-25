// Package targetfs reads the files of a scanned tree after the inventory walk.
//
// The tree is hostile input. Git keeps symlinks, so a README.md or a package.json in a cloned
// repository may point at any file on the scanning machine, and a path may name something that
// never ends (/dev/zero, a FIFO) or a file far larger than the walk agreed to parse. The
// inventory walk refuses all of these; every later read of a target file goes through this
// package so it keeps the same promises:
//
//   - it stays under the scan root: the file is opened through an os.Root, so a symlink that
//     leaves the root fails to open, while one that stays inside it is followed;
//   - it reads regular files only, checked before the open, so a FIFO cannot block it;
//   - it never reads more than a cap, so a large file cannot exhaust memory.
package targetfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/devlab-group/mcp-scanner/internal/source/bundle"
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/inventory"
)

// ErrNotRegular is returned for a directory, a device, a FIFO or a socket
var ErrNotRegular = errors.New("not a regular file")

// ErrTooLarge is returned by ReadWhole for a file larger than its cap
var ErrTooLarge = errors.New("file is larger than the read limit")

// Read returns at most max bytes of rel, a path relative to root (either separator).
// truncated reports that the file has more than max bytes.
//
// An empty root reads rel as given: graphs built in memory, as tests do, have no root. The
// regular-file check and the cap still apply.
func Read(root, rel string, max int64) (data []byte, truncated bool, err error) {
	if max < 0 {
		max = 0
	}
	var f *os.File
	if root == "" {
		f, err = openRegular(osFS{}, rel)
	} else {
		var r *os.Root
		if r, err = os.OpenRoot(root); err != nil {
			return nil, false, err
		}
		defer r.Close()
		f, err = openRegular(rootFS{r}, rel)
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err = io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return data[:max], true, nil
	}
	return data, false, nil
}

// Refused reports whether err is a refusal rather than a missing file: a link out of the tree, a
// file that is not regular, one over the cap, or any other error but "does not exist". A caller
// must not read a refusal as "the file says nothing": a hostile tree can arrange one on purpose.
func Refused(err error) bool {
	return err != nil && !errors.Is(err, fs.ErrNotExist)
}

// ReadDirNames lists the names in directory rel of the tree, through the scan root
func ReadDirNames(root, rel string) ([]string, error) {
	if root == "" {
		return nil, errors.New("targetfs: no scan root to list a directory under")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	d, err := r.Open(filepath.FromSlash(rel))
	if err != nil {
		return nil, err
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// ReadWhole returns rel whole, or ErrTooLarge when it has more than max bytes
func ReadWhole(root, rel string, max int64) ([]byte, error) {
	data, truncated, err := Read(root, rel, max)
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf("%s: %w (%d bytes)", rel, ErrTooLarge, max)
	}
	return data, nil
}

// Cap is the number of bytes of a graph file that the source walk read, and so the most any
// analyzer reading the same file needs: the truncation point of a file the walk found over the
// per-file limit, the bundle limit for a bundle, and the per-file limit otherwise
func Cap(g *graph.Graph, rel string) int64 {
	if g != nil {
		if f := g.Files[filepath.ToSlash(rel)]; f != nil {
			switch {
			case f.MaxBytes > 0:
				return f.MaxBytes
			case f.Bundle:
				return bundle.MaxSize
			}
		}
	}
	return inventory.DefaultLimits().MaxFileSize
}

// ReadGraphFile reads a file of the graph's tree, at most Cap bytes of it: the bytes the source
// walk parsed, never a file outside the root
func ReadGraphFile(g *graph.Graph, rel string) ([]byte, error) {
	root := ""
	if g != nil {
		root = g.Root
	}
	data, _, err := Read(root, rel, Cap(g, rel))
	return data, err
}

// opener is the part of os and os.Root this package uses
type opener interface {
	Stat(name string) (fs.FileInfo, error)
	Open(name string) (*os.File, error)
}

type osFS struct{}

func (osFS) Stat(name string) (fs.FileInfo, error) { return os.Stat(name) }
func (osFS) Open(name string) (*os.File, error)    { return os.Open(name) }

type rootFS struct{ r *os.Root }

func (f rootFS) Stat(name string) (fs.FileInfo, error) { return f.r.Stat(name) }
func (f rootFS) Open(name string) (*os.File, error)    { return f.r.Open(name) }

// openRegular opens name only when it is a regular file, checked before the open (a FIFO would
// block the open itself) and again on the opened file (it may have been swapped in between)
func openRegular(o opener, name string) (*os.File, error) {
	name = filepath.FromSlash(name)
	info, err := o.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", name, ErrNotRegular)
	}
	f, err := o.Open(name)
	if err != nil {
		return nil, err
	}
	if info, err = f.Stat(); err != nil || !info.Mode().IsRegular() {
		f.Close()
		if err == nil {
			err = fmt.Errorf("%s: %w", name, ErrNotRegular)
		}
		return nil, err
	}
	return f, nil
}
