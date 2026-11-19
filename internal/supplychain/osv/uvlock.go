package osv

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// uvPackage is one [[package]] block of a uv.lock
type uvPackage struct {
	name, version, source string
	deps                  []string // [package] dependencies, plus optional-dependencies (extras may be installed)
	devDeps               []string // [package.dev-dependencies], every group
}

var (
	uvSourceLine = regexp.MustCompile(`^source\s*=\s*\{\s*([a-z-]+)\s*=`)
	uvDepName    = regexp.MustCompile(`\{\s*name\s*=\s*"([^"]+)"`)
)

// parseUvLock reads uv.lock's [[package]] blocks: name, version, where the package comes from, and
// the names it depends on, split into production and development groups
func parseUvLock(data []byte) ([]uvPackage, error) {
	var out []uvPackage
	var cur *uvPackage
	section := "" // "", "optional-dependencies", "dev-dependencies", "other"
	inArray := "" // "deps" or "dev" while inside a multi-line array
	flush := func() {
		if cur != nil && cur.name != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	sc := lineScanner(data)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if inArray != "" {
			for _, m := range uvDepName.FindAllStringSubmatch(line, -1) {
				if inArray == "dev" {
					cur.devDeps = append(cur.devDeps, normalizePyName(m[1]))
				} else {
					cur.deps = append(cur.deps, normalizePyName(m[1]))
				}
			}
			if strings.HasPrefix(line, "]") {
				inArray = ""
			}
			continue
		}
		switch {
		case line == "[[package]]":
			flush()
			cur, section = &uvPackage{}, ""
			continue
		case strings.HasPrefix(line, "[package."):
			section = strings.TrimSuffix(strings.TrimPrefix(line, "[package."), "]")
			if section != "optional-dependencies" && section != "dev-dependencies" {
				section = "other"
			}
			continue
		case strings.HasPrefix(line, "["):
			flush()
			section = "other"
			continue
		}
		if cur == nil {
			continue
		}
		if section == "" {
			switch {
			case tomlNameLine.MatchString(line) && cur.name == "":
				cur.name = tomlNameLine.FindStringSubmatch(line)[1]
			case tomlVersionLine.MatchString(line) && cur.version == "":
				cur.version = tomlVersionLine.FindStringSubmatch(line)[1]
			case uvSourceLine.MatchString(line):
				cur.source = uvSourceLine.FindStringSubmatch(line)[1]
			case strings.HasPrefix(line, "dependencies"):
				names := uvDepName.FindAllStringSubmatch(line, -1)
				for _, m := range names {
					cur.deps = append(cur.deps, normalizePyName(m[1]))
				}
				if !strings.HasSuffix(line, "]") {
					inArray = "deps"
				}
			}
			continue
		}
		if section == "optional-dependencies" || section == "dev-dependencies" {
			if i := strings.Index(line, "="); i > 0 && strings.Contains(line[i:], "[") {
				kind := "deps"
				if section == "dev-dependencies" {
					kind = "dev"
				}
				for _, m := range uvDepName.FindAllStringSubmatch(line, -1) {
					if kind == "dev" {
						cur.devDeps = append(cur.devDeps, normalizePyName(m[1]))
					} else {
						cur.deps = append(cur.deps, normalizePyName(m[1]))
					}
				}
				if !strings.HasSuffix(line, "]") {
					inArray = kind
				}
			}
		}
	}
	if err := scanErr(sc, "uv.lock"); err != nil {
		return nil, err
	}
	flush()
	return out, nil
}

func normalizePyName(n string) string {
	return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(n))
}

// ParseUvLock extracts registry coordinates from a uv.lock. The project's own packages (editable,
// virtual, a local directory) are not on the registry; a git or URL source is a note, as in
// poetry.lock.
func ParseUvLock(data []byte) (coords []Coordinate, notes []string, err error) {
	pkgs, err := parseUvLock(data)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range pkgs {
		if p.version == "" {
			continue
		}
		switch p.source {
		case "editable", "virtual", "directory", "path":
			continue
		case "git", "url":
			notes = append(notes, fmt.Sprintf(
				"uv.lock installs %s %s from a %s source, so an OSV verdict on the registry release says nothing about the bytes installed",
				p.name, p.version, p.source))
			continue
		}
		coords = append(coords, Coordinate{Ecosystem: "PyPI", Name: p.name, Version: p.version})
	}
	sort.Slice(coords, func(i, j int) bool { return coords[i].Name < coords[j].Name })
	sort.Strings(notes)
	return coords, notes, nil
}

// UvLockDevOnly returns the registry packages reachable only through the project's development
// groups. The project's own packages are the roots: what their dependencies and extras reach is
// installed with the server; what only their dev-dependencies reach is not (uv sync --no-dev).
func UvLockDevOnly(data []byte) map[Coordinate]bool {
	pkgs, err := parseUvLock(data)
	if err != nil {
		return nil
	}
	byName := map[string][]uvPackage{}
	var roots []uvPackage
	for _, p := range pkgs {
		byName[normalizePyName(p.name)] = append(byName[normalizePyName(p.name)], p)
		switch p.source {
		case "editable", "virtual", "directory", "path":
			roots = append(roots, p)
		}
	}
	if len(roots) == 0 {
		return nil
	}
	walk := func(start []string) map[string]bool {
		seen := map[string]bool{}
		queue := append([]string(nil), start...)
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			if seen[n] {
				continue
			}
			seen[n] = true
			for _, p := range byName[n] {
				queue = append(queue, p.deps...)
			}
		}
		return seen
	}
	var prodStart, devStart []string
	for _, r := range roots {
		prodStart = append(prodStart, r.deps...)
		devStart = append(devStart, r.devDeps...)
	}
	prod, dev := walk(prodStart), walk(devStart)
	for _, r := range roots {
		prod[normalizePyName(r.name)] = true
	}
	out := map[Coordinate]bool{}
	for n := range dev {
		if prod[n] {
			continue
		}
		for _, p := range byName[n] {
			if p.version != "" {
				out[Coordinate{Ecosystem: "PyPI", Name: p.name, Version: p.version}] = true
			}
		}
	}
	return out
}

// PoetryLockDevOnly returns the packages a poetry.lock records as development-only: category =
// "dev" in lock files before Poetry 1.2, or a groups list without "main" in Poetry 2 lock files. A
// lock file that records neither marks nothing.
func PoetryLockDevOnly(data []byte) map[Coordinate]bool {
	out := map[Coordinate]bool{}
	var name, version string
	dev := false
	flush := func() {
		if name != "" && version != "" && dev {
			out[Coordinate{Ecosystem: "PyPI", Name: name, Version: version}] = true
		}
		name, version, dev = "", "", false
	}
	groupsLine := regexp.MustCompile(`^groups\s*=\s*\[(.*)\]`)
	inPkg := false
	sc := lineScanner(data)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			flush()
			inPkg = true
		case strings.HasPrefix(line, "["):
			if !strings.HasPrefix(line, "[package.") {
				flush()
				inPkg = false
			}
		case !inPkg:
		case tomlNameLine.MatchString(line) && name == "":
			name = tomlNameLine.FindStringSubmatch(line)[1]
		case tomlVersionLine.MatchString(line) && version == "":
			version = tomlVersionLine.FindStringSubmatch(line)[1]
		case line == `category = "dev"`:
			dev = true
		case groupsLine.MatchString(line):
			g := groupsLine.FindStringSubmatch(line)[1]
			dev = !strings.Contains(g, `"main"`)
		}
	}
	flush()
	return out
}
