package targetfs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// checkedDirs hold all the scanner's own packages, relative to the module root
var checkedDirs = []string{"internal", "pkg"}

// forbidden are the ways to reach a file by name: each follows a symbolic link out of a scanned
// tree, reads its metadata, or runs a program that does. A package's local name for the import
// is resolved, so an alias or a function value counts as well as a call.
var forbidden = map[string]map[string]bool{
	"os": {
		"ReadFile": true, "Open": true, "OpenFile": true, "ReadDir": true, "Stat": true, "Lstat": true,
		"Readlink": true, "DirFS": true, "OpenRoot": true, "OpenInRoot": true, "CopyFS": true,
	},
	"path/filepath": {"EvalSymlinks": true},
	"os/exec":       {"Command": true, "CommandContext": true, "LookPath": true},
	"syscall": {
		"Open": true, "Openat": true, "Stat": true, "Lstat": true, "Fstatat": true, "Readlink": true,
		"Read": true, "Pread": true, "Getdents": true, "Getdirentries": true,
	},
	"io/ioutil": nil, // every function of it
}

// allowed are the functions that may still use one, each for a reason of its own. A function is
// named "file:Func" or "file:Type.Method"; an entry nothing matches any more is itself an error.
var allowed = map[string]string{
	// the walk itself: it resolves every link and drops the ones that leave the root
	"internal/source/inventory/inventory.go:Walk":                 "the inventory walk",
	"internal/source/inventory/inventory.go:countSourceFiles":     "the inventory walk",
	"internal/source/inventory/inventory.go:looksLikeScript":      "the inventory walk",
	"internal/source/inventory/inventory.go:walker.bundleFits":    "the inventory walk",
	"internal/source/inventory/inventory.go:walker.handleSymlink": "the inventory walk",
	"internal/source/inventory/inventory.go:walker.walkDir":       "the inventory walk",
	"internal/source/analyzer.go:ResolveRoot":                     "resolves the scan root itself",
	// files the walk accepted, by the absolute path it recorded
	"internal/source/build.go:readBundle": "a file the inventory walk accepted",
	"internal/source/build.go:readFile":   "a file the inventory walk accepted",
	// open the tree through an os.Root
	"internal/source/targetfs/targetfs.go:Read":                      "this package",
	"internal/source/targetfs/targetfs.go:ReadDirNames":              "this package",
	"internal/source/targetfs/targetfs.go:osFS.Open":                 "this package, for a graph with no root",
	"internal/source/targetfs/targetfs.go:osFS.Stat":                 "this package, for a graph with no root",
	"internal/analyzers/taint/walk.go:newCtx":                        "opens the os.Root the taint walk reads through",
	"internal/analyzers/taint/walk.go:ctx.readSource":                "os.Root; a plain open only for a graph with no root",
	"internal/analyzers/taint/walk.go:ctx.readBundle":                "os.Root; a plain open only for a graph with no root",
	"internal/analyzers/transport/scan.go:newReader":                 "opens the os.Root transport reads through",
	"internal/analyzers/transport/scan.go:reader.open":               "os.Root; a plain open only for a graph with no root",
	"internal/analyzers/transport/transport.go:reader.exists":        "os.Root; a plain stat only for a graph with no root",
	"internal/analyzers/iac/iac.go:walk":                             "opens the os.Root iac walks",
	"internal/analyzers/supplychain/supplychain.go:Analyzer.Analyze": "opens the os.Root supplychain reads lock files through",
	"internal/analyzers/virustotal/virustotal.go:Analyzer.Analyze":   "opens the os.Root virustotal hashes files through",
	"internal/dossier/dossier.go:readme":                             "lists the root's names; the README itself is read through targetfs",
	"internal/supplychain/archive/archive.go:Extract":                "opens the os.Root a package archive is extracted into",
	"internal/runtime/canary/canary.go:Set.Materialize":              "opens the os.Root of its own temporary directory",
	// not a scanned tree: the scanner's configuration, rules, corpus and the operator's own input
	"internal/analyzers/promptdefense/rules.go:LoadRules":      "the rules directory from the scanner's configuration",
	"internal/analyzers/yara/yara_enabled.go:loadCached":       "the rules directory from the scanner's configuration",
	"internal/config/config.go:Load":                           "the scanner's own config file",
	"internal/config/config.go:Config.Validate":                "paths in the scanner's own config",
	"internal/config/config.go:RulesDirBesideExecutable":       "the scanner's own install directory",
	"internal/evals/corpus.go:loadCase":                        "the scanner's own evaluation corpus",
	"internal/app/prepare.go:ReadCapped":                       "a snapshot, baseline or client config the operator names",
	"internal/app/prepare.go:Preparer.Prepare":                 "lists the scanner's own extraction directory",
	"internal/api/handlers.go:resolveWithinBase":               "the API's own containment check of a requested path against BaseDir",
	"internal/api/handlers.go:redactBaseDir":                   "the API's own BaseDir",
	"internal/mcp/transport/transport.go:stdioTransport":       "the stdio command the operator names",
	"internal/runtime/sandbox/sandbox.go:copyExecutable":       "the stdio command the operator names, copied into the sandbox",
	"internal/runtime/sandbox/sandbox.go:Docker.Available":     "the docker command line",
	"internal/runtime/sandbox/sandbox.go:Docker.Execute":       "the docker command line",
	"internal/runtime/sandbox/sandbox.go:Docker.dockerCleanup": "the docker command line",
	"internal/runtime/sandbox/sandbox.go:Docker.ensureImage":   "the docker command line",
	"internal/runtime/sandbox/sandbox.go:Docker.imagePresent":  "the docker command line",
	"internal/testutil/testutil.go:CountPackageExtractionDirs": "test helper over the scanner's own temporary directories",
}

// TestNoDirectReadsOfTargetFiles keeps every read of a scanned tree's files on this package: a
// README.md or package.json that links out of the tree must never be read, and any by-name read
// would follow it
func TestNoDirectReadsOfTargetFiles(t *testing.T) {
	moduleRoot := filepath.Join("..", "..", "..")
	var bad []string
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range checkedDirs {
		err := filepath.WalkDir(filepath.Join(moduleRoot, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(moduleRoot, p)
			rel = filepath.ToSlash(rel)
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			local := map[string]string{} // local name -> watched import path
			for _, im := range f.Imports {
				path, _ := strconv.Unquote(im.Path.Value)
				if _, watched := forbidden[path]; !watched {
					continue
				}
				name := filepath.Base(path)
				if im.Name != nil {
					name = im.Name.Name
				}
				if name == "." {
					bad = append(bad, fset.Position(im.Pos()).String()+": dot-import of "+path)
					continue
				}
				local[name] = path
			}
			for _, decl := range f.Decls {
				where := declName(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkg, ok := sel.X.(*ast.Ident)
					if !ok {
						return true
					}
					path, ok := local[pkg.Name]
					if !ok {
						return true
					}
					if names := forbidden[path]; names != nil && !names[sel.Sel.Name] {
						return true
					}
					key := rel + ":" + where
					if _, ok := allowed[key]; ok {
						seen[key] = true
						return true
					}
					bad = append(bad, fset.Position(sel.Pos()).String()+": "+path+"."+sel.Sel.Name+" in "+where)
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s: read a scanned tree's file through targetfs (Read, ReadWhole, ReadGraphFile, ReadDirNames), "+
			"or add the function to allowed with the reason it is safe", b)
	}
	var stale []string
	for key := range allowed {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("allowed has %s, which no longer reads a file by name: remove the entry", key)
	}
}

// declName is "Func", "Type.Method", or "<package>" for a declaration outside any function
// (a package-level var holding a function literal counts there)
func declName(decl ast.Decl) string {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok {
		return "<package>"
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	if st, ok := t.(*ast.StarExpr); ok {
		t = st.X
	}
	if ix, ok := t.(*ast.IndexExpr); ok {
		t = ix.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}
