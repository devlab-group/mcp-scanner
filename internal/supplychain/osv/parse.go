package osv

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// maxLockfileLineBytes bounds a single line of a line-oriented lockfile. Crossing it makes
// parsing fail instead of returning the dependencies found before the oversized line.
const maxLockfileLineBytes = 1 << 20 // 1 MiB

// lineScanner is the reader every line-oriented parser here uses, so the
// cap and the error check are one decision rather than four
func lineScanner(data []byte) *bufio.Scanner {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), maxLockfileLineBytes)
	return sc
}

// scanErr names the lockfile kind in a scan that stopped early, so the
// warning the caller reports says which file was not read to the end
// rather than only "token too long"
func scanErr(sc *bufio.Scanner, kind string) error {
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: stopped reading before the end of the file: %w", kind, err)
	}
	return nil
}

// ParseGoSum extracts module coordinates from a go.sum file. go.sum lists
// each module twice (a content hash and a "/go.mod" hash); the /go.mod line
// is skipped so each module@version is reported once
func ParseGoSum(data []byte) ([]Coordinate, error) {
	var out []Coordinate
	seen := map[string]bool{}
	sc := lineScanner(data)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		module, version := fields[0], fields[1]
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		version = strings.TrimPrefix(version, "v")
		key := module + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Coordinate{Ecosystem: "Go", Name: module, Version: "v" + version})
	}
	if err := scanErr(sc, "go.sum"); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var goModRequireLine = regexp.MustCompile(`^\s*([^\s]+)\s+(v[0-9][^\s]*)`)

// ParseGoMod extracts required-module coordinates from a go.mod file's
// require directives (both the single-line and block forms). Prefer
// ParseGoSum when a go.sum is available: it lists the versions actually
// selected, including transitive dependencies go.mod alone does not show.
func ParseGoMod(data []byte) (coords []Coordinate, notes []string, err error) {
	var out []Coordinate
	replaced := map[string]Coordinate{}
	sc := lineScanner(data)
	block := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "require ("):
			block = "require"
			continue
		case strings.HasPrefix(line, "replace ("):
			block = "replace"
			continue
		case block != "" && line == ")":
			block = ""
			continue
		case strings.HasPrefix(line, "require "):
			line, block = strings.TrimPrefix(line, "require "), ""
		case strings.HasPrefix(line, "replace "):
			if from, to, note := parseGoModReplace(strings.TrimPrefix(line, "replace ")); from != "" {
				replaced[from] = to
			} else if note != "" {
				notes = append(notes, note)
			}
			continue
		case block == "require":
			// fall through to the require match below
		case block == "replace":
			if from, to, note := parseGoModReplace(line); from != "" {
				replaced[from] = to
			} else if note != "" {
				notes = append(notes, note)
			}
			continue
		default:
			continue
		}
		if m := goModRequireLine.FindStringSubmatch(line); m != nil {
			out = append(out, Coordinate{Ecosystem: "Go", Name: m[1], Version: m[2]})
		}
	}
	if err := scanErr(sc, "go.mod"); err != nil {
		return nil, nil, err
	}
	// A replace directive decides what the build actually compiles, so
	// querying the required version asks about code that was never built
	for i := range out {
		if to, ok := replaced[out[i].Name]; ok {
			out[i] = to
		}
	}
	sort.Strings(notes)
	return out, notes, nil
}

var goModReplaceLine = regexp.MustCompile(`^(\S+)(?:\s+v\S+)?\s*=>\s*(\S+)(?:\s+(v\S+))?`)

// parseGoModReplace reads one replace directive. It returns the module
// being replaced and the coordinate to query instead, or a note when the
// replacement is a local path, which has no coordinate to query at all.
func parseGoModReplace(line string) (from string, to Coordinate, note string) {
	if i := strings.Index(line, "//"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	m := goModReplaceLine.FindStringSubmatch(line)
	if m == nil {
		return "", Coordinate{}, ""
	}
	if m[3] == "" {
		return "", Coordinate{}, fmt.Sprintf(
			"go.mod replaces %s with the local path %s, which has no release to look up", m[1], m[2])
	}
	return m[1], Coordinate{Ecosystem: "Go", Name: m[2], Version: m[3]}, ""
}

// ParsePackageLock extracts coordinates from an npm package-lock.json,
// handling both the v2/v3 "packages" map and the legacy v1 "dependencies"
// tree
func ParsePackageLock(data []byte) (coords []Coordinate, notes []string, err error) {
	var doc struct {
		// Name is set when the installed package's name differs from the
		// install path - an npm alias ("util-helper": {"name":"lodash"}),
		// or a workspace entry whose path is not a package name at all.
		// Deriving the name from the path alone queried OSV under a
		// coordinate that does not exist, which comes back clean.
		Packages map[string]struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
		} `json:"packages"`
		Dependencies map[string]lockDep `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}

	var out []Coordinate
	if len(doc.Packages) > 0 {
		for path, pkg := range doc.Packages {
			if path == "" || pkg.Version == "" {
				continue // the root project entry has no version
			}
			name := pkg.Name
			if name == "" {
				name = packageNameFromPath(path)
			}
			if src := nonRegistrySource(pkg.Resolved); src != "" {
				notes = append(notes, fmt.Sprintf(
					"package-lock.json entry %q resolves from %s, so an OSV verdict on the registry release of %s@%s says nothing about the bytes installed",
					path, src, name, pkg.Version))
				continue
			}
			out = append(out, Coordinate{Ecosystem: "npm", Name: name, Version: pkg.Version})
		}
	} else {
		collectLegacyDeps(doc.Dependencies, &out)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	sort.Strings(notes)
	return out, notes, nil
}

// nonRegistrySource names the kind of source a lockfile "resolved" value points at when it
// is not a registry tarball, or "" when it is one (or is absent). Querying OSV for the same
// name and version would otherwise describe registry bytes that were not installed.
func nonRegistrySource(resolved string) string {
	switch {
	case resolved == "":
		return ""
	case strings.HasPrefix(resolved, "git+"), strings.HasPrefix(resolved, "git:"),
		strings.Contains(resolved, "github.com") && strings.Contains(resolved, "#"):
		return "a git reference"
	case strings.HasPrefix(resolved, "file:"):
		return "a local path"
	case strings.HasPrefix(resolved, "http://"), strings.HasPrefix(resolved, "https://"):
		return ""
	}
	return "a non-registry source"
}

type lockDep struct {
	Version      string             `json:"version"`
	Dependencies map[string]lockDep `json:"dependencies"`
}

func collectLegacyDeps(deps map[string]lockDep, out *[]Coordinate) {
	for name, dep := range deps {
		if dep.Version != "" {
			*out = append(*out, Coordinate{Ecosystem: "npm", Name: name, Version: dep.Version})
		}
		if len(dep.Dependencies) > 0 {
			collectLegacyDeps(dep.Dependencies, out)
		}
	}
}

// packageNameFromPath turns a package-lock.json v2/v3 key such as
// "node_modules/@scope/name" or "node_modules/a/node_modules/b" into the
// package name it refers to
func packageNameFromPath(path string) string {
	idx := strings.LastIndex(path, "node_modules/")
	if idx == -1 {
		return path
	}
	rest := path[idx+len("node_modules/"):]
	if strings.HasPrefix(rest, "@") {
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return rest
	}
	parts := strings.SplitN(rest, "/", 2)
	return parts[0]
}

var requirementLine = regexp.MustCompile(`^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+-]+)`)

// ParseRequirementsTxt extracts pinned coordinates from a requirements.txt and counts,
// separately, the two kinds of dependency it cannot look up. Unpinned entries are reported as
// unqueryable; included files are unread content and therefore downgrade coverage.
func ParseRequirementsTxt(data []byte) (coords []Coordinate, unpinned, included int, err error) {
	sc := lineScanner(data)
	var joined string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// pip joins a line ending in a backslash with the next one before
		// parsing it. Matching line by line turned "requests \" and
		// "==2.19.0" into two lines that name nothing, so a file pinning a
		// known-vulnerable release decided by its own formatting that it
		// had nothing to look up.
		if before, ok := strings.CutSuffix(line, "\\"); ok {
			joined += before
			continue
		}
		if joined != "" {
			line, joined = joined+line, ""
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			switch strings.Fields(line)[0] {
			case "-r", "--requirement", "-c", "--constraint":
				included++
			case "-e", "--editable":
				// Unlike the options it is grouped with, -e names a
				// dependency - one this parser cannot resolve to a
				// registry coordinate. Counting it with the includes is
				// what makes it a gap rather than nothing at all.
				included++
			}
			continue // the rest of pip's options name no dependency at all
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if m := requirementLine.FindStringSubmatch(line); m != nil {
			coords = append(coords, Coordinate{Ecosystem: "PyPI", Name: m[1], Version: m[2]})
			continue
		}
		unpinned++
	}
	if joined != "" {
		// A file whose last line ends in a backslash: pip would join it
		// with nothing. Count it rather than dropping it.
		unpinned++
	}
	if err := scanErr(sc, "requirements.txt"); err != nil {
		return nil, 0, 0, err
	}
	return coords, unpinned, included, nil
}

// ParsePoetryLock extracts coordinates from a poetry.lock file
func ParsePoetryLock(data []byte) (coords []Coordinate, notes []string, err error) {
	blocks, err := parseTOMLPackageBlocks(data, "package", "poetry.lock")
	if err != nil {
		return nil, nil, err
	}
	var out []Coordinate
	for _, nv := range blocks {
		switch nv.source {
		case "git", "url", "file", "directory":
			notes = append(notes, fmt.Sprintf(
				"poetry.lock installs %s %s from a %s source, so an OSV verdict on the registry release says nothing about the bytes installed",
				nv.name, nv.version, nv.source))
			continue
		}
		out = append(out, Coordinate{Ecosystem: "PyPI", Name: nv.name, Version: nv.version})
	}
	sort.Strings(notes)
	return out, notes, nil
}

// ParseCargoLock extracts coordinates from a Cargo.lock file
func ParseCargoLock(data []byte) ([]Coordinate, error) {
	blocks, err := parseTOMLPackageBlocks(data, "package", "Cargo.lock")
	if err != nil {
		return nil, err
	}
	var out []Coordinate
	for _, nv := range blocks {
		out = append(out, Coordinate{Ecosystem: "crates.io", Name: nv.name, Version: nv.version})
	}
	return out, nil
}

type nameVersion struct{ name, version, source string }

var (
	tomlNameLine    = regexp.MustCompile(`^name\s*=\s*"([^"]*)"`)
	tomlVersionLine = regexp.MustCompile(`^version\s*=\s*"([^"]*)"`)
	tomlTypeLine    = regexp.MustCompile(`^type\s*=\s*"([^"]*)"`)
)

// parseTOMLPackageBlocks reads [[table]] blocks and captures their "name"
// and "version" string fields. It is not a general TOML parser: Cargo.lock
// and poetry.lock only ever put those two fields as plain quoted strings
// directly under a [[package]] header, which is all this needs to handle.
func parseTOMLPackageBlocks(data []byte, table, kind string) ([]nameVersion, error) {
	header := "[[" + table + "]]"
	var out []nameVersion
	var cur nameVersion
	flush := func() {
		if cur.name != "" && cur.version != "" {
			out = append(out, cur)
		}
		cur = nameVersion{}
	}
	sourceHeader := "[" + table + ".source]"
	inSource := false
	sc := lineScanner(data)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == header:
			flush()
			inSource = false
		case line == sourceHeader:
			// A sub-table of the block that is still open, not the end of
			// it: its "type" says where the package came from, and a
			// package that came from git or a URL is not the registry
			// release OSV would answer about
			inSource = true
		case strings.HasPrefix(line, "["):
			flush()
			inSource = false
		case inSource && tomlTypeLine.MatchString(line):
			cur.source = tomlTypeLine.FindStringSubmatch(line)[1]
		case tomlNameLine.MatchString(line) && cur.name == "":
			cur.name = tomlNameLine.FindStringSubmatch(line)[1]
		case tomlVersionLine.MatchString(line) && cur.version == "":
			cur.version = tomlVersionLine.FindStringSubmatch(line)[1]
		}
	}
	if err := scanErr(sc, kind); err != nil {
		return nil, err
	}
	flush()
	return out, nil
}
