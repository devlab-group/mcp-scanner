// Package supplychain finds pinned dependencies and reports matching OSV
// vulnerabilities. Package preparation downloads and extracts before analysis.
package supplychain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/supplychain"
	"github.com/devlab-group/mcp-scanner/internal/supplychain/osv"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// maxLockfileBytes bounds how much of one lockfile is read into memory. An oversized lockfile is
// rejected as a coverage gap instead of returning a partial dependency list that looks complete.
const maxLockfileBytes = 8 << 20 // 8 MiB

func init() { analyzer.Register(&Analyzer{}) }

const name = "supplychain"

// Analyzer implements analyzer.Analyzer for supply-chain checks
type Analyzer struct{}

func (a *Analyzer) Name() string { return name }

func (a *Analyzer) AppliesTo(kind model.TargetKind) bool {
	switch kind {
	case model.TargetSource, model.TargetPackage:
		return true
	}
	return false
}

func (a *Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name:            name,
		Purpose:         "Parses lockfiles (go.sum/go.mod, package-lock.json, requirements.txt/poetry.lock, Cargo.lock) and the scanned package's own coordinate, then checks them against the OSV vulnerability database.",
		Threats:         []string{"known_vulnerable_dependency", "known_vulnerable_package"},
		Evidence:        []model.EvidenceLevel{model.EvidenceStatic},
		Active:          false,
		Limitations:     []string{"only catches vulnerabilities OSV already knows about", "a lockfile format this parser does not recognize (pnpm-lock.yaml, yarn.lock, uv.lock, Pipfile.lock, pdm.lock, composer.lock, gradle.lockfile, Gemfile.lock) is reported as a coverage gap, not silently ignored", "vendor/ and node_modules/ trees are excluded from lockfile discovery - the same tradeoff internal/source/inventory makes for source code - which always downgrades the scan when one of those directories is present", "a package.json, pyproject.toml, setup.py or Cargo.toml with no lockfile beside it declares dependency ranges, not resolved versions - an ordinary checkout commonly ships only the manifest, and that gap is reported, not silently passed as clean", "a requirements.txt dependency without an exact == version is reported as a coverage gap"},
		RequiresNetwork: true,
	}
}

type lockfileParser struct {
	match func(base string) bool
	parse func(data []byte) (parsed, error)
}

// parsed is what one lockfile parser learned. It separates unpinned dependencies that were read
// but cannot be queried from included content that was never opened and must downgrade coverage.
type parsed struct {
	coords   []osv.Coordinate
	unpinned int
	unread   int
	// notes are gaps the parser found in what it could look up at all: a
	// dependency resolved from git or a local path, a replace directive
	// pointing off the registry. Each one is a coordinate the scan does
	// not have, so they are reported as limits.
	notes []string
}

var lockfileParsers = []lockfileParser{
	{match: eq("go.sum"), parse: coordsOnly(osv.ParseGoSum)},
	{match: eq("go.mod"), parse: withNotes(osv.ParseGoMod)},
	{match: eq("package-lock.json"), parse: withNotes(osv.ParsePackageLock)},
	// npm-shrinkwrap.json is package-lock.json's published twin, byte for
	// byte the same format: package-lock.json is never inside a published
	// tarball and this one is, which makes it the one an npm package
	// target actually ships
	{match: eq("npm-shrinkwrap.json"), parse: withNotes(osv.ParsePackageLock)},
	{match: eq("requirements.txt"), parse: parseRequirements},
	{match: eq("poetry.lock"), parse: withNotes(osv.ParsePoetryLock)},
	{match: eq("Cargo.lock"), parse: coordsOnly(osv.ParseCargoLock)},
}

// unrecognizedLockfileNames are lockfile formats this analyzer can identify by name but has
// no parser for. Finding one is not "nothing to check": a dependency tree pinned by it was
// never examined, so it must not read as clean just because nothing matched
// lockfileParsers.
var unrecognizedLockfileNames = map[string]bool{
	"pnpm-lock.yaml":  true,
	"yarn.lock":       true,
	"uv.lock":         true,
	"Pipfile.lock":    true,
	"pdm.lock":        true,
	"composer.lock":   true,
	"gradle.lockfile": true,
	"Gemfile.lock":    true,
	"bun.lock":        true,
	"bun.lockb":       true,
	"deno.lock":       true,
}

// manifestNames declare dependency version ranges rather than the exact versions a lockfile
// pins - a range has nothing single to query OSV for
var manifestNames = map[string]bool{
	"package.json":   true,
	"pyproject.toml": true,
	"setup.py":       true,
	"Cargo.toml":     true,
}

// supersededBy names, for a manifest or an unpinned go.mod, the lockfile
// in the same directory that makes parsing it redundant: the lockfile
// already lists what a range or a go.mod's own require lines only bound.
// Parsing (or, for a manifest, flagging) both would double-report the same
// gap or the same dependencies.
var supersededBy = map[string][]string{
	"go.mod":         {"go.sum"},
	"package.json":   {"package-lock.json", "npm-shrinkwrap.json"},
	"pyproject.toml": {"poetry.lock"},
	"Cargo.toml":     {"Cargo.lock"},
}

// excludedLockfileDirs mirrors internal/source/inventory's reportedSkipDirs:
// walking a vendored dependency tree would turn most scans into an audit of
// someone else's code, so these are excluded from lockfile discovery too -
// but, same as there, the exclusion is reported, never silent
var excludedLockfileDirs = map[string]bool{
	"vendor":       true,
	"node_modules": true,
	".venv":        true,
	"venv":         true,
}

func eq(name string) func(string) bool { return func(base string) bool { return base == name } }

// coordsOnly adapts a parser that has nothing to report beyond its
// coordinates. It passes the parser's error through: an adapter that
// swallowed it would make it structurally impossible for these parsers to
// report a problem, and a parser that cannot fail is one whose failures
// become clean results.
func coordsOnly(f func([]byte) ([]osv.Coordinate, error)) func([]byte) (parsed, error) {
	return func(data []byte) (parsed, error) {
		coords, err := f(data)
		return parsed{coords: coords}, err
	}
}

// withNotes adapts a parser that also reports coordinates it deliberately
// did not produce - see parsed.notes
func withNotes(f func([]byte) ([]osv.Coordinate, []string, error)) func([]byte) (parsed, error) {
	return func(data []byte) (parsed, error) {
		coords, notes, err := f(data)
		return parsed{coords: coords, notes: notes}, err
	}
}

func parseRequirements(data []byte) (parsed, error) {
	coords, unpinned, included, err := osv.ParseRequirementsTxt(data)
	return parsed{coords: coords, unpinned: unpinned, unread: included}, err
}

func querierFrom(ac *analyzer.AnalysisContext) osv.Querier {
	if v, ok := ac.Option(name, "querier"); ok {
		if q, ok := v.(osv.Querier); ok {
			return q
		}
	}
	return osv.NewHTTPClient()
}

// Analyze finds every recognized lockfile under ac.Root, adds the target's
// own coordinate for a package scan, queries OSV for each, and reports a
// finding per confirmed vulnerability
func (a *Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	res := model.AnalyzerResult{Analyzer: name, Status: model.AnalyzerCompleted, Required: true}

	type coordHit struct {
		coord osv.Coordinate
		file  string
	}
	var hits []coordHit

	if target.Kind == model.TargetPackage && target.Ecosystem != "" && target.Package != "" {
		res.Coverage.FilesDiscovered++
		version := target.Version
		if version == "" {
			// The preparer publishes what the registry actually resolved
			// "latest" to
			if v, ok := analyzer.Get[string](ac.Artifacts, supplychain.ResolvedVersionKey); ok {
				version = v
			}
		}
		if version == "" {
			// An unversioned OSV query answers about every release the
			// package ever had, so a target whose version could not be
			// pinned down would be reported against advisories fixed long
			// before the bytes on disk were published. No coordinate is
			// the honest answer, and it is a gap.
			res.Coverage.FilesFailed++
			res.Coverage.LimitsHit = append(res.Coverage.LimitsHit, fmt.Sprintf(
				"%s: the package version could not be resolved, so its own advisories were not looked up", target.Describe()))
		} else {
			res.Coverage.FilesParsed++
			hits = append(hits, coordHit{coord: osv.Coordinate{
				Ecosystem: normalizeEcosystem(target.Ecosystem),
				Name:      target.Package,
				Version:   version,
			}, file: target.Describe()})
		}
	}

	walkComplete := true
	if ac.Root != "" {
		// Every lockfile is opened through root, not through ac.Root by
		// name: a path resolved via root cannot be walked back out by a
		// symlink, matching internal/source/inventory's containment
		// boundary and internal/analyzers/virustotal's os.OpenRoot use
		root, rootErr := os.OpenRoot(ac.Root)
		if rootErr != nil {
			// Nothing under the root could be examined at all - the same
			// "looked at nothing" gap as an unreadable directory below, not
			// "found nothing"
			walkComplete = false
			res.Errors = append(res.Errors, model.AnalyzerError{Kind: "internal", Message: fmt.Sprintf("could not open scan root: %v", rootErr)})
		} else {
			defer root.Close()

			// Manifests are recognized on every target kind here too - see
			// manifestNames for why a bare manifest with no lockfile beside
			// it is a gap, not nothing to check. A tree with neither
			// manifest nor lockfile still reaches SKIPPED below, which stays
			// the honest answer for that case.
			found, excludedDirs, unreadable, symlinks, walkErr := findLockfiles(root)
			if walkErr != nil {
				res.Errors = append(res.Errors, model.AnalyzerError{Kind: "internal", Message: fmt.Sprintf("could not walk scan root: %v", walkErr)})
			}
			if len(excludedDirs) > 0 {
				res.Coverage.LimitsHit = append(res.Coverage.LimitsHit,
					fmt.Sprintf("lockfiles under vendored dependency directories were not examined: %s", strings.Join(excludedDirs, ", ")))
			}
			// An unreadable directory means part of the tree was never
			// enumerated, so any lockfile under it - found or not - is unknown,
			// not absent. Each one is its own gap, and walkComplete below stops
			// that from being read as "nothing to check" when it found zero
			// lockfiles for a tree it never finished walking.
			for _, p := range unreadable {
				walkComplete = false
				res.Coverage.LimitsHit = append(res.Coverage.LimitsHit,
					fmt.Sprintf("%s: could not be read, anything under it was not examined for lockfiles", p))
			}
			// A lockfile symlink is refused and counted as both discovered and skipped. Its reason goes
			// in LimitsHit, not SkipReasons, so balanced counters cannot turn this protective refusal
			// into complete coverage.
			for _, p := range symlinks {
				res.Coverage.FilesDiscovered++
				res.Coverage.FilesSkipped++
				res.Coverage.LimitsHit = append(res.Coverage.LimitsHit,
					fmt.Sprintf("%s: a symlink, not followed, dependencies were not checked", p))
			}
			for _, lf := range found {
				res.Coverage.FilesDiscovered++

				if lf.parser.parse == nil {
					// This is an unsupported lockfile or a manifest with no resolving lockfile. It is counted as
					// skipped but recorded in LimitsHit, because SkipReasons plus balanced counters would
					// otherwise treat unchecked dependencies as complete coverage.
					if lf.isManifest {
						// A manifest that declares nothing has nothing
						// unresolved, and a bare {"name":..,"type":"module"}
						// marker beside a source file is an ordinary shape.
						// Recording a gap for it would downgrade a scan over
						// dependencies that do not exist, which is as wrong
						// as staying quiet about ones that do.
						declares, known := manifestDeclaresDependencies(root, lf.rel)
						if known && !declares {
							// Read, understood, and empty. That is a parsed
							// file with no coordinates in it, not a skipped
							// one: counting it as skipped leaves the analyzer
							// with nothing parsed, which trips the floor that
							// exists to catch a scan that examined nothing.
							res.Coverage.FilesParsed++
							continue
						}
						res.Coverage.FilesSkipped++
						res.Coverage.LimitsHit = append(res.Coverage.LimitsHit, fmt.Sprintf(
							"%s: dependency ranges declared here were not resolved against a lockfile and were not checked", lf.rel))
						continue
					}
					res.Coverage.FilesSkipped++
					res.Coverage.LimitsHit = append(res.Coverage.LimitsHit, fmt.Sprintf(
						"%s: lockfile format is not supported by this analyzer, dependencies were not checked", lf.rel))
					continue
				}

				data, truncated, err := readLockfileCapped(root, lf.rel)
				if err != nil {
					res.Coverage.FilesFailed++
					res.Warnings = append(res.Warnings, fmt.Sprintf("%s: could not read: %v", lf.rel, err))
					continue
				}
				if truncated {
					res.Coverage.FilesFailed++
					res.Coverage.LimitsHit = append(res.Coverage.LimitsHit,
						fmt.Sprintf("%s: exceeds the %d byte lockfile read limit, dependencies were not checked", lf.rel, maxLockfileBytes))
					continue
				}
				// A parser that stopped early read part of the file and none of the rest, and the
				// dependencies it never reached are unknown rather than absent
				out, err := lf.parser.parse(data)
				if err != nil {
					res.Coverage.FilesFailed++
					res.Warnings = append(res.Warnings, fmt.Sprintf("%s: could not parse: %v", lf.rel, err))
					continue
				}
				res.Coverage.FilesParsed++
				if out.unpinned > 0 {
					// A range names no version to look up, so the installed version was not checked. This
					// is the same coverage gap as a manifest without a lockfile.
					res.Coverage.LimitsHit = append(res.Coverage.LimitsHit,
						fmt.Sprintf("%s: %d dependency line(s) carry no exact version, so the installed version was not checked; pin them or add a lockfile", lf.rel, out.unpinned))
				}
				for _, note := range out.notes {
					// A dependency whose bytes did not come from the
					// registry release named beside it is a coordinate
					// this scan does not have, which is a gap, not a
					// clean answer
					res.Coverage.LimitsHit = append(res.Coverage.LimitsHit, lf.rel+": "+note)
				}
				if out.unread > 0 {
					// An included requirements file is content this analyzer
					// never opened, so whatever it pins is unknown rather
					// than unqueryable. That is a gap.
					res.Coverage.LimitsHit = append(res.Coverage.LimitsHit,
						fmt.Sprintf("%s: %d included requirements file(s) were not opened, their dependencies were not checked", lf.rel, out.unread))
				}
				for _, c := range out.coords {
					hits = append(hits, coordHit{coord: c, file: lf.rel})
				}
			}
		}
	}

	if len(hits) == 0 {
		// Nothing to query. That's only a skip when every file this analyzer set out to look at was
		// actually read: a lockfile it couldn't parse or open, an unsupported format, an excluded
		// vendored tree, or an unfinished walk all mean there's a dependency list it didn't see.
		if walkComplete && res.Coverage.FilesFailed == 0 && res.Coverage.FilesSkipped == 0 && len(res.Coverage.LimitsHit) == 0 {
			res.Status = model.AnalyzerSkipped
			res.Warnings = append(res.Warnings, "no package coordinate or dependency version found to check")
			return res
		}
		return res
	}

	querier := querierFrom(ac)
	fileByCoord := make(map[osv.Coordinate]string, len(hits))
	coords := make([]osv.Coordinate, 0, len(hits))
	for _, l := range hits {
		if _, dup := fileByCoord[l.coord]; dup {
			continue
		}
		fileByCoord[l.coord] = l.file
		coords = append(coords, l.coord)
	}

	results, err := osv.QueryAll(ctx, querier, coords)
	if err != nil {
		return model.Errorf(name, classify(err), "OSV lookup failed: %v", err)
	}

	for coord, vulns := range results {
		for _, v := range vulns {
			res.Findings = append(res.Findings, toFinding(coord, fileByCoord[coord], v))
		}
	}
	model.SortFindings(res.Findings)
	return res
}

// classify reports the AnalyzerError kind for an OSV lookup failure. A
// canceled/deadline-exceeded context means the scan ran out of time, not
// that the network failed.
func classify(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	return "network"
}

type foundLockfile struct {
	rel        string
	parser     lockfileParser
	isManifest bool
}

// findLockfiles walks within os.Root for known lockfiles. It reports excluded
// directories, unreadable entries, and symlinks without following them, while
// continuing through readable siblings.
func findLockfiles(root *os.Root) (found []foundLockfile, excludedDirs []string, unreadable []string, symlinks []string, err error) {
	var out []foundLockfile
	excluded := map[string]bool{}
	walkErr := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			unreadable = append(unreadable, p)
			if d != nil && d.IsDir() {
				return fs.SkipDir // only this subtree is unreadable; keep walking siblings
			}
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			if p != "." && excludedLockfileDirs[d.Name()] {
				excluded[d.Name()] = true
				return fs.SkipDir
			}
			return nil
		}
		base := d.Name()
		var parser lockfileParser
		known := false
		for _, lp := range lockfileParsers {
			if lp.match(base) {
				parser, known = lp, true
				break
			}
		}
		isManifest := !known && manifestNames[base]
		if !known && !isManifest && !unrecognizedLockfileNames[base] {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			symlinks = append(symlinks, p)
			return nil
		}
		out = append(out, foundLockfile{rel: p, parser: parser, isManifest: isManifest})
		return nil
	})
	// Drop whichever entries supersededBy marks redundant - see its doc
	// comment for why
	byDir := map[string]map[string]bool{}
	for _, f := range out {
		dir := path.Dir(f.rel)
		if byDir[dir] == nil {
			byDir[dir] = map[string]bool{}
		}
		byDir[dir][path.Base(f.rel)] = true
	}
	filtered := out[:0]
	for _, f := range out {
		base := path.Base(f.rel)
		supersededHere := false
		for _, by := range supersededBy[base] {
			if byDir[path.Dir(f.rel)][by] {
				supersededHere = true
				break
			}
		}
		if supersededHere {
			continue
		}
		filtered = append(filtered, f)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].rel < filtered[j].rel })

	dirs := slices.Sorted(maps.Keys(excluded))
	sort.Strings(unreadable)
	sort.Strings(symlinks)
	return filtered, dirs, unreadable, symlinks, walkErr
}

// readLockfileCapped reads rel - a path resolved through root, so it cannot name anything
// outside the scan root - up to maxLockfileBytes. It reports truncation instead of handing the
// parser a prefix that could silently omit dependencies near the end.
func readLockfileCapped(root *os.Root, rel string) (data []byte, truncated bool, err error) {
	f, err := root.Open(rel)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err = io.ReadAll(io.LimitReader(f, maxLockfileBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxLockfileBytes {
		return nil, true, nil
	}
	return data, false, nil
}

func normalizeEcosystem(e string) string {
	switch strings.ToLower(e) {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "go":
		return "Go"
	case "cargo":
		return "crates.io"
	default:
		return e
	}
}

func toFinding(coord osv.Coordinate, file string, v osv.Vuln) model.Finding {
	sev, err := model.ParseSeverity(v.Severity())
	if err != nil {
		sev = model.SeverityMedium // OSV confirmed the match; unclassified is not the same as harmless
	}
	fixed := v.FixedVersions(coord.Name)

	tax := []model.TaxonomyReference{{Scheme: schemeFor(v.ID), ID: v.ID, URL: "https://osv.dev/vulnerability/" + v.ID}}
	for _, alias := range v.Aliases {
		tax = append(tax, model.TaxonomyReference{Scheme: schemeFor(alias), ID: alias})
	}

	desc := v.Summary
	if desc == "" {
		desc = v.Details
	}
	remediation := ""
	if len(fixed) > 0 {
		remediation = "Upgrade " + coord.Name + " to " + strings.Join(fixed, " or ")
	}

	return model.Finding{
		RuleID:   "supplychain.osv_vulnerability",
		Category: "known_vulnerability",
		// coord.Name/Version come from a parsed lockfile - target-controlled
		// text - so they are quoted rather than interpolated raw; v.ID comes
		// from OSV, not the scanned target
		Title:         fmt.Sprintf("%q@%q is affected by %s", coord.Name, coord.Version, v.ID),
		Severity:      sev,
		Confidence:    0.9,
		EvidenceLevel: model.EvidenceStatic,
		File:          file,
		Description:   desc,
		Remediation:   remediation,
		Analyzer:      name,
		Taxonomy:      tax,
		Evidence: []model.Evidence{{
			Level:       model.EvidenceStatic,
			Kind:        "osv_match",
			Description: desc,
			File:        file,
			Data: map[string]any{
				"osv_id":         v.ID,
				"ecosystem":      coord.Ecosystem,
				"package":        coord.Name,
				"version":        coord.Version,
				"fixed_versions": fixed,
			},
		}},
	}
}

func schemeFor(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "CVE"
	case strings.HasPrefix(id, "GHSA-"):
		return "GHSA"
	default:
		return "OSV"
	}
}

var (
	_ analyzer.Applicable = (*Analyzer)(nil)
	_ analyzer.Describer  = (*Analyzer)(nil)
	_ analyzer.Analyzer   = (*Analyzer)(nil)
)

// manifestDeclaresDependencies reports whether a manifest names dependencies and whether this
// analyzer could tell. Unknown or unreadable formats fail toward a coverage gap; package.json is
// parsed precisely to avoid downgrading common dependency-free projects.
func manifestDeclaresDependencies(root *os.Root, rel string) (declares, known bool) {
	if filepath.Base(rel) != "package.json" {
		return false, false
	}
	data, truncated, err := readLockfileCapped(root, rel)
	if err != nil || truncated {
		return false, false
	}
	var m struct {
		Dependencies         map[string]any `json:"dependencies"`
		DevDependencies      map[string]any `json:"devDependencies"`
		PeerDependencies     map[string]any `json:"peerDependencies"`
		OptionalDependencies map[string]any `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return false, false
	}
	n := len(m.Dependencies) + len(m.DevDependencies) + len(m.PeerDependencies) + len(m.OptionalDependencies)
	return n > 0, true
}
