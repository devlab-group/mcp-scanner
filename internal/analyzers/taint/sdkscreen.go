package taint

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
// none pinned, or the screening switched off somewhere in the tree's Python code
func templateScreening(root string) string {
	found := map[string]bool{}
	off := false
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".venv", "venv", "site-packages", "__pycache__":
				return filepath.SkipDir
			}
			if strings.Count(strings.TrimPrefix(p, root), string(filepath.Separator)) > 4 {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		isManifest := name == "uv.lock" || name == "poetry.lock" || name == "pyproject.toml" || (strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"))
		if !isManifest && !strings.HasSuffix(name, ".py") {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 4<<20 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		text := string(b)
		if strings.HasSuffix(name, ".py") {
			if screeningOff.MatchString(text) {
				off = true
			}
			return nil
		}
		for _, m := range append(lockedVersion.FindAllStringSubmatch(text, -1), pinnedVersion.FindAllStringSubmatch(text, -1)...) {
			pkg := strings.ToLower(m[1])
			major, _ := strconv.Atoi(m[2])
			if min, ok := screeningSDKs[pkg]; ok && major >= min {
				found[pkg+" "+m[2]+".x"] = true
			}
		}
		return nil
	})
	if off || len(found) == 0 {
		return ""
	}
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, " and ")
}
