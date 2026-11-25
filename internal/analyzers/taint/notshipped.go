package taint

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// notShippedDir and notShippedFile match code a released server usually does not run: test
// suites, evaluation harnesses, fixtures and benchmarks. The folder's name alone proves nothing,
// though: an evaluation server can be the package's own command, and a benchmark server can have
// its own image. shipping weighs the rest of the evidence.
var (
	notShippedDir  = regexp.MustCompile(`(^|/)(tests?|__tests__|spec|specs|e2e|evals?|fixtures?|testdata|test_data|benchmarks?)/`)
	notShippedFile = regexp.MustCompile(`\.(test|spec)\.[cm]?[jt]sx?$|_test\.(go|py)$|(^|/)conftest\.py$`)
	pyTestName     = regexp.MustCompile(`(^|/)test_[^/]*\.py$`)
	pyTestMarkers  = regexp.MustCompile(`(?m)^\s*(import pytest|from pytest|import unittest|from unittest|def test_|async def test_|class Test)`)
	// a JavaScript test: an import of a test framework, or the describe/it/test blocks they run
	jsTestMarkers = regexp.MustCompile("(?m)(?:from\\s+[\"'](?:vitest|@jest/globals|node:test|mocha|chai|supertest)[\"']|require\\(\\s*[\"'](?:vitest|node:test|mocha|chai|supertest)[\"']\\s*\\)|^\\s*(?:describe|it|test)\\s*\\(\\s*[\"'`])")
	// package.json scripts that run tests, benchmarks, evaluations or linters rather than the program
	testScript = regexp.MustCompile(`(?i)^(?:pre|post)?(?:test|tests|e2e|bench|benchmark|benchmarks|eval|evals|coverage|lint|format|typecheck)(?:[:._-].*)?$`)
	// files that deploy or start a program: images, compose files, registry and hosting manifests
	deployFile = regexp.MustCompile(`^(?:Dockerfile(?:[.-].*)?|.*\.dockerfile|(?:docker-)?compose(?:[.-][\w.-]*)?\.ya?ml|smithery\.ya?ml|server\.json|Procfile)$`)
	// the words of a command line or of a deployment file
	commandWord = regexp.MustCompile("[^\\s\"'`\\[\\](),;&|=]+")
)

// shipState is what a file's path and the tree's manifests say about whether a released server
// runs the file
type shipState int

const (
	// shipped: not test or evaluation code by its path, or a package manifest or a deployment
	// file outside such folders starts it
	shipped shipState = iota
	// testCode: test or evaluation code by its path, nothing starts it, and it is a test of a test
	// framework or the tree's server lives elsewhere
	testCode
	// unsureShip: test or evaluation code by its path, but a deployment file inside such a folder
	// starts it, or no server of the tree lives outside such folders, so the folder's name is all
	// that says a released server does not run it
	unsureShip
)

// shipping weighs one file for the not-shipped rule; why says what the state rests on
func (gi *guardIndex) shipping(file string) (shipState, string) {
	if file == "" || !gi.notShippedPath(file) {
		return shipped, ""
	}
	strong, weak := gi.launch(file)
	switch {
	case strong != "":
		return shipped, ""
	case weak != "":
		return unsureShip, weak
	case notShippedFile.MatchString(file) || gi.testFramework(file):
		return testCode, "it is a test of a test framework"
	}
	if other := gi.serverElsewhere(); other != "" {
		return testCode, "the tree's server lives elsewhere (" + other + ")"
	}
	return unsureShip, "no server of the tree lives outside test or evaluation folders, and nothing shows this one is not it"
}

// notShippedPath reports whether a file is test or evaluation code by its path alone
func (gi *guardIndex) notShippedPath(file string) bool {
	switch {
	case notShippedDir.MatchString(file), notShippedFile.MatchString(file):
		return true
	case pyTestName.MatchString(file):
		// a production module can be called test_runner.py; a test module imports a test framework
		// or defines test functions
		return pyTestMarkers.MatchString(strings.Join(gi.lines(file), "\n"))
	}
	return false
}

func (gi *guardIndex) testFramework(file string) bool {
	text := strings.Join(gi.lines(file), "\n")
	return pyTestMarkers.MatchString(text) || jsTestMarkers.MatchString(text)
}

// serverElsewhere names a file outside test and evaluation folders, or one a manifest starts, that
// registers an MCP handler; "" when the tree has none
func (gi *guardIndex) serverElsewhere() string {
	if gi.elsewhere != nil {
		return *gi.elsewhere
	}
	var files []string
	if gi.g != nil {
		for _, c := range gi.g.Capabilities {
			f := c.File
			if s := gi.g.Symbols[c.Handler]; s != nil {
				f = s.File
			}
			if f != "" {
				files = append(files, f)
			}
		}
	}
	sort.Strings(files)
	other := ""
	for _, f := range files {
		if !gi.notShippedPath(f) {
			other = f
			break
		}
	}
	if other == "" {
		for _, f := range files {
			if strong, _ := gi.launch(f); strong != "" {
				other = f
				break
			}
		}
	}
	gi.elsewhere = &other
	return other
}

// launch looks in the folders above a file for what starts it. strong names a package manifest
// whose entry point or script is the file, or a deployment file outside test and evaluation
// folders that names it. weak says why a person should look: a deployment file inside such a
// folder names it, or a package manifest names it without starting it (files, workspaces, an
// include list). A manifest that exists but cannot be read counts as starting the file: an unread
// manifest is no evidence that nothing starts it.
func (gi *guardIndex) launch(file string) (strong, weak string) {
	for dir := path.Dir(file); ; dir = path.Dir(dir) {
		rel := file
		if dir != "." {
			rel = strings.TrimPrefix(file, dir+"/")
		}
		for _, name := range gi.dirNames(dir) {
			p := name
			if dir != "." {
				p = dir + "/" + name
			}
			switch {
			case name == "package.json":
				text, refused := gi.manifestText(p)
				if refused || packageStarts(text, rel) {
					return p, ""
				}
				if weak == "" && mentions(withoutTestScripts(text), rel) {
					weak = p + " names it without starting it"
				}
			case name == "pyproject.toml", name == "setup.cfg", name == "setup.py":
				text, refused := gi.manifestText(p)
				if refused || pythonStarts(text, rel) {
					return p, ""
				}
				if weak == "" && mentions(text, rel) {
					weak = p + " names it without starting it"
				}
			case deployFile.MatchString(name):
				if text, refused := gi.manifestText(p); refused || commandStarts(text, rel) {
					if !notShippedDir.MatchString(p) {
						return p, ""
					}
					if weak == "" {
						weak = p + " in that folder starts it"
					}
				}
			}
		}
		if dir == "." || dir == "/" || dir == "" {
			return "", weak
		}
	}
}

// packageStarts reports whether a package.json runs rel (a path relative to its folder): main,
// module, bin or exports name it, or a script other than a test or tooling script runs it
func packageStarts(text, rel string) bool {
	var pkg struct {
		Main    any            `json:"main"`
		Module  any            `json:"module"`
		Bin     any            `json:"bin"`
		Exports any            `json:"exports"`
		Scripts map[string]any `json:"scripts"`
	}
	if json.Unmarshal([]byte(text), &pkg) != nil {
		return false
	}
	for _, e := range stringLeaves(pkg.Main, pkg.Module, pkg.Bin, pkg.Exports) {
		if samePath(e, rel) {
			return true
		}
	}
	for name, cmd := range pkg.Scripts {
		if s, ok := cmd.(string); ok && !testScript.MatchString(name) && commandStarts(s, rel) {
			return true
		}
	}
	return false
}

// pythonStarts reports whether a pyproject.toml, setup.cfg or setup.py starts rel: an entry point
// (module:function) or a python -m names the file's module
func pythonStarts(text, rel string) bool {
	for _, mod := range pyModules(rel) {
		q := regexp.QuoteMeta(mod)
		if regexp.MustCompile(`(?:^|[\s"'=])` + q + `:[A-Za-z_]|(?:^|\s)-m\s+` + q + `(?:$|[\s"',\]])`).MatchString(text) {
			return true
		}
	}
	return false
}

// commandStarts reports whether a command line or a deployment file names rel: as a word, as the
// end of an absolute path inside an image (/app/tests/server.py), or as the module after -m
func commandStarts(text, rel string) bool {
	mods := pyModules(rel)
	words := commandWord.FindAllString(text, -1)
	for i, w := range words {
		w = strings.TrimPrefix(w, "./")
		if samePath(w, rel) || strings.HasSuffix(w, "/"+rel) {
			return true
		}
		if i > 0 && words[i-1] == "-m" && hasString(mods, w) {
			return true
		}
	}
	return false
}

// mentions reports whether a manifest names rel by its path or its module, not by a bare word:
// evals/harness.py, evals/harness or evals.harness, but not harness in a description
func mentions(text, rel string) bool {
	needles := append([]string{rel}, pyModules(rel)...)
	if stem := sourceExt.ReplaceAllString(rel, ""); strings.Contains(stem, "/") {
		needles = append(needles, stem)
	}
	for _, n := range needles {
		if (strings.Contains(n, "/") || strings.Contains(n, ".")) && strings.Contains(text, n) {
			return true
		}
	}
	return false
}

// withoutTestScripts is a package.json without the scripts that run tests or tooling, which name
// test files without shipping them
func withoutTestScripts(text string) string {
	var pkg map[string]any
	if json.Unmarshal([]byte(text), &pkg) != nil {
		return text
	}
	if scripts, ok := pkg["scripts"].(map[string]any); ok {
		for name := range scripts {
			if testScript.MatchString(name) {
				delete(scripts, name)
			}
		}
	}
	b, err := json.Marshal(pkg)
	if err != nil {
		return text
	}
	return string(b)
}

// pyModules are the module names a Python file is imported or run as: mypkg/evals/server.py is
// mypkg.evals.server, and with a src/ layout also without src; a package's __init__ or __main__
// is the package
func pyModules(rel string) []string {
	if !strings.HasSuffix(rel, ".py") {
		return nil
	}
	m := strings.TrimSuffix(rel, ".py")
	m = strings.TrimSuffix(strings.TrimSuffix(m, "/__init__"), "/__main__")
	if m == "" || m == "__init__" || m == "__main__" {
		return nil
	}
	out := []string{strings.ReplaceAll(m, "/", ".")}
	if rest, ok := strings.CutPrefix(m, "src/"); ok && rest != "" {
		out = append(out, strings.ReplaceAll(rest, "/", "."))
	}
	return out
}

// samePath reports whether a manifest entry names rel, the source of a build output included:
// dist/evals/server.js is built from src/evals/server.ts
func samePath(entry, rel string) bool {
	entry = path.Clean(strings.TrimPrefix(entry, "./"))
	if entry == rel {
		return true
	}
	return buildStem(entry) != "" && buildStem(entry) == buildStem(rel)
}

var sourceExt = regexp.MustCompile(`\.(?:[cm]?[jt]sx?|py)$`)

func buildStem(p string) string {
	if !sourceExt.MatchString(p) {
		return ""
	}
	p = sourceExt.ReplaceAllString(p, "")
	if first, rest, ok := strings.Cut(p, "/"); ok {
		switch first {
		case "dist", "build", "lib", "out", "src":
			p = rest
		}
	}
	return p
}

// stringLeaves are the strings in JSON values: a bin map's commands, an exports tree's targets
func stringLeaves(vs ...any) []string {
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	for _, v := range vs {
		walk(v)
	}
	return out
}

// manifestText and dirNames are this file's only reads of the scanned tree. A manifest over 1 MiB
// is refused rather than read.
func (gi *guardIndex) manifestText(rel string) (string, bool) {
	if t, ok := gi.manifests[rel]; ok {
		return t.text, t.refused
	}
	var t manifestRead
	b, err := os.ReadFile(filepath.Join(gi.root, filepath.FromSlash(rel)))
	switch {
	case err != nil:
	case len(b) >= 1<<20:
		t.refused = true
	default:
		t.text = string(b)
	}
	if gi.manifests == nil {
		gi.manifests = map[string]manifestRead{}
	}
	gi.manifests[rel] = t
	return t.text, t.refused
}

type manifestRead struct {
	text    string
	refused bool
}

func (gi *guardIndex) dirNames(rel string) []string {
	if names, ok := gi.dirs[rel]; ok {
		return names
	}
	var names []string
	if es, err := os.ReadDir(filepath.Join(gi.root, filepath.FromSlash(rel))); err == nil {
		for _, e := range es {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
	}
	if gi.dirs == nil {
		gi.dirs = map[string][]string{}
	}
	gi.dirs[rel] = names
	return names
}
