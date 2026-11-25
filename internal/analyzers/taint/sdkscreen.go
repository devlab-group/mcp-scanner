package taint

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/targetfs"
)

// Python MCP SDKs that screen resource-template parameters before the handler runs: their default
// ResourceSecurity rejects ".." path segments, absolute paths and NUL bytes after the value is
// percent-decoded. fastmcp added it in 4.0.0; the official SDK's mcpserver in 2.0.0. Older ones
// (fastmcp 2.x and 3.x, mcp 1.x) hand "%2E%2E%2F" to the handler decoded as "../".
var screeningSDKs = map[string]int{"fastmcp": 4, "mcp": 2}

var (
	pinnedVersion = regexp.MustCompile(`(?im)^\s*"?(fastmcp|mcp)(?:\[[^\]]*\])?\s*(?:==|>=|~=|===)\s*(\d+)\.`)
	lockedVersion = regexp.MustCompile(`(?m)^name = "(fastmcp|mcp)"\s*\nversion = "(\d+)\.`)
	// a project that switches the screening off, for a template or the whole server
	screeningOff = regexp.MustCompile(`\bresource_security\s*=\s*None\b|\bsecurity\s*=\s*None\b|\bexempt_params\s*=`)
)

// templateScreening reports the SDK and major version that screens resource-template parameters in
// this tree, read from its lock files and manifests, or "" when none is known to - an older SDK,
// none pinned, or the screening switched off somewhere in the tree's Python code.
//
// It reads only what the source walk already bounded: the Python files in the graph (at most 4
// directories deep, outside virtualenvs and caches), and the manifests in their directories and
// the directories above them, all through the scan root. A Python file that cannot be read may be
// the one that switches the screening off, so it counts as switching it off.
func templateScreening(g *graph.Graph) string {
	if g == nil || g.Root == "" {
		return ""
	}
	dirs := map[string]bool{".": true}
	for p, f := range g.Files {
		if f.Language != "python" || screeningSkipped(p) {
			continue
		}
		b, err := targetfs.ReadGraphFile(g, p)
		if err != nil || screeningOff.Match(b) {
			return ""
		}
		for d := path.Dir(p); d != "." && d != "/" && d != ""; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	found := map[string]bool{}
	for d := range dirs {
		names, err := targetfs.ReadDirNames(g.Root, d)
		if err != nil {
			continue
		}
		for _, name := range names {
			if !(name == "uv.lock" || name == "poetry.lock" || name == "pyproject.toml" || (strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"))) {
				continue
			}
			// a manifest only ever turns the marking on, so one that cannot be read is skipped
			b, err := targetfs.ReadWhole(g.Root, path.Join(d, name), 4<<20)
			if err != nil {
				continue
			}
			text := string(b)
			for _, m := range append(lockedVersion.FindAllStringSubmatch(text, -1), pinnedVersion.FindAllStringSubmatch(text, -1)...) {
				pkg := strings.ToLower(m[1])
				major, _ := strconv.Atoi(m[2])
				if min, ok := screeningSDKs[pkg]; ok && major >= min {
					found[pkg+" "+m[2]+".x"] = true
				}
			}
		}
	}
	if len(found) == 0 {
		return ""
	}
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, " and ")
}

// screeningSkipped keeps the reach of the walk this replaced: at most 4 directories deep, and not
// inside VCS metadata, node_modules, a virtualenv, site-packages or a bytecode cache
func screeningSkipped(p string) bool {
	parts := strings.Split(p, "/")
	if len(parts) > 5 {
		return true
	}
	for _, d := range parts[:len(parts)-1] {
		switch d {
		case ".git", "node_modules", ".venv", "venv", "site-packages", "__pycache__":
			return true
		}
	}
	return false
}
