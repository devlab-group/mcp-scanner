// Package bundle reads a JavaScript bundle in esbuild's output shape - tsup and other tools built
// on esbuild write the same - where every bundled module opens with a comment line holding the
// path the bundler resolved it from:
//
//	// ../../node_modules/zod/v3/types.js
//	...
//	// src/tools/run_command.ts
//
// A published package is often only such a bundle: the server's own modules after megabytes of
// its dependencies. Blanking the modules whose path runs through node_modules leaves the server's
// own code, which is what a scan of its repository reads too, since that scan skips node_modules
// directories. Blanking keeps every byte offset and line number: each byte of a dependency
// module becomes a space and every newline stays, so a finding points at the bundle's real line
// and any reader of the raw file sees the same text at the same place.
//
// A module marker is only a comment, so a package can put one in front of its own code to have
// it blanked. The blanked modules are therefore reported as excluded code, like a node_modules
// directory, and never support a clean verdict.
package bundle

import (
	"bytes"
	"io"
	"regexp"
	"slices"
	"strings"
)

// MaxSize bounds the bundle read whole to look for module markers; a larger file is read only up
// to the per-file limit, as any other oversized file
const MaxSize = 32 << 20

// marker is esbuild's module comment: `// ` at column 0, then a relative path to a JavaScript,
// TypeScript or JSON module, and nothing else on the line
var marker = regexp.MustCompile(`^// ((?:\.\./)*[A-Za-z0-9@_.~+\-]+(?:/[A-Za-z0-9@_.~+\-]+)*\.(?:js|mjs|cjs|jsx|ts|mts|cts|tsx|json))\r?$`)

// Result is a bundle with its dependency modules blanked
type Result struct {
	// Masked is the bundle, the same length as the input, with every byte of a node_modules
	// module except newlines turned into a space
	Masked []byte
	// ThirdParty and Own count the modules blanked and the modules kept
	ThirdParty int
	Own        int
	// OwnBytes is how much of the bundle was kept: the modules outside node_modules and anything
	// before the first marker (the bundler's helpers, a shebang)
	OwnBytes int64
	// Packages are the distinct npm packages the blanked modules came from, such as
	// "@modelcontextprotocol/sdk" or "zod"
	Packages []string
}

// Split finds the modules of a bundle and blanks the ones from node_modules. It reports false
// when src has no node_modules module marker, so it is not a bundle this package can read.
func Split(src []byte) (Result, bool) {
	type module struct {
		start      int
		thirdParty bool
		pkg        string
	}
	var mods []module
	for off := 0; off < len(src); {
		end := bytes.IndexByte(src[off:], '\n')
		next := len(src)
		if end >= 0 {
			next = off + end + 1
		}
		line := src[off:next]
		if len(line) > 3 && line[0] == '/' && line[1] == '/' && line[2] == ' ' {
			if m := marker.FindSubmatch(bytes.TrimRight(line, "\n")); m != nil {
				pkg, third := packageOf(string(m[1]))
				mods = append(mods, module{start: off, thirdParty: third, pkg: pkg})
			}
		}
		off = next
	}
	res := Result{OwnBytes: int64(len(src))}
	seen := map[string]bool{}
	var blank [][2]int
	for i, m := range mods {
		end := len(src)
		if i+1 < len(mods) {
			end = mods[i+1].start
		}
		if !m.thirdParty {
			res.Own++
			continue
		}
		res.ThirdParty++
		res.OwnBytes -= int64(end - m.start)
		blank = append(blank, [2]int{m.start, end})
		if !seen[m.pkg] {
			seen[m.pkg] = true
			res.Packages = append(res.Packages, m.pkg)
		}
	}
	if res.ThirdParty == 0 {
		return Result{}, false
	}
	out := slices.Clone(src)
	for _, r := range blank {
		for i := r[0]; i < r[1]; i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	slices.Sort(res.Packages)
	res.Masked = out
	return res, true
}

// Read reads a file the inventory accepted as a bundle - at most MaxSize bytes - and blanks its
// node_modules modules. A file that no longer reads as a bundle whose own part fits ownLimit,
// because it changed after the walk looked at it, comes back as its first ownLimit bytes, the
// way any oversized file is read, and ok is false so the caller can report the truncation.
func Read(r io.Reader, ownLimit int64) (src []byte, packages []string, ok bool, err error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, nil, false, err
	}
	if int64(len(data)) <= MaxSize {
		if res, split := Split(data); split && res.OwnBytes <= ownLimit {
			return res.Masked, res.Packages, true, nil
		}
	}
	return data[:min(int64(len(data)), ownLimit)], nil, false, nil
}

// packageOf returns the npm package a module path comes from and whether it runs through
// node_modules: the segment after the last node_modules, or the two segments of a scoped name
func packageOf(path string) (string, bool) {
	parts := strings.Split(path, "/")
	last := -1
	for i, p := range parts {
		if p == "node_modules" {
			last = i
		}
	}
	if last < 0 || last+1 >= len(parts) {
		return "", false
	}
	name := parts[last+1]
	if strings.HasPrefix(name, "@") && last+2 < len(parts) {
		name += "/" + parts[last+2]
	}
	return name, true
}
