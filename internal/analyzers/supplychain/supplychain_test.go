package supplychain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/internal/supplychain"
	"github.com/revinand/mcp-scanner/internal/supplychain/osv"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

type fakeQuerier struct {
	byCoord map[osv.Coordinate][]osv.Vuln
	calls   []osv.Coordinate
}

func (f *fakeQuerier) Query(ctx context.Context, c osv.Coordinate) ([]osv.Vuln, error) {
	f.calls = append(f.calls, c)
	return f.byCoord[c], nil
}

func acWithQuerier(root string, q osv.Querier) *analyzer.AnalysisContext {
	return &analyzer.AnalysisContext{Root: root, Options: map[string]map[string]any{name: {"querier": q}}}
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSkippedWhenNothingToCheck(t *testing.T) {
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(t.TempDir(), &fakeQuerier{}))
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("status = %s, want SKIPPED", res.Status)
	}
}

func TestPackageTargetChecksItsOwnCoordinate(t *testing.T) {
	bad := osv.Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}
	q := &fakeQuerier{byCoord: map[osv.Coordinate][]osv.Vuln{bad: {{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2020-1234"}, Summary: "bad thing", Affected: []osv.Affected{{
		Package: struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Purl      string `json:"purl,omitempty"`
		}{Ecosystem: "npm", Name: "left-pad"},
		Ranges: []osv.Range{{Type: "SEMVER", Events: []osv.Event{{Introduced: "0"}, {Fixed: "1.0.1"}}}},
	}}}}}}

	target := model.Target{Kind: model.TargetPackage, Ecosystem: "npm", Package: "left-pad", Version: "1.0.0"}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), target, acWithQuerier("", q))
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (%v)", res.Status, res.Errors)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if err := f.Validate(); err != nil {
		t.Fatalf("finding failed Validate: %v", err)
	}
	if len(f.Taxonomy) != 2 {
		t.Fatalf("taxonomy = %v, want an OSV/GHSA entry plus the CVE alias", f.Taxonomy)
	}
	foundCVE, foundGHSA := false, false
	for _, tx := range f.Taxonomy {
		if tx.Scheme == "CVE" && tx.ID == "CVE-2020-1234" {
			foundCVE = true
		}
		if tx.Scheme == "GHSA" && tx.ID == "GHSA-aaaa-bbbb-cccc" {
			foundGHSA = true
		}
	}
	if !foundCVE || !foundGHSA {
		t.Fatalf("missing expected taxonomy references: %v", f.Taxonomy)
	}
	if f.Remediation == "" {
		t.Fatal("expected a remediation naming the fixed version")
	}
}

func TestPackageTargetManifestWithNoLockfileIsCoverageGap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name": "x", "dependencies": {"left-pad": "^1.0.0"}}`)

	target := model.Target{Kind: model.TargetPackage, Ecosystem: "npm", Package: "x", Version: "1.0.0"}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), target, acWithQuerier(dir, &fakeQuerier{}))
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (%v)", res.Status, res.Errors)
	}
	if res.Coverage.FilesDiscovered != 2 {
		t.Fatalf("FilesDiscovered = %d, want 2 (the coordinate plus package.json)", res.Coverage.FilesDiscovered)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("a manifest with no lockfile to resolve it must land in LimitsHit")
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("a manifest whose dependency ranges were never resolved must downgrade the scan")
	}

	// The gap must actually reach the scan-level verdict, not just sit
	// unread in the analyzer's own Coverage
	scan := &model.ScanResult{Analyzers: []model.AnalyzerResult{res}}
	scan.Aggregate(model.DefaultBlockingSeverity)
	if scan.Status != model.StatusPartial {
		t.Fatalf("scan status = %s, want PARTIAL", scan.Status)
	}
}

func TestManifestSupersededByLockfileIsNotReported(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name": "x", "dependencies": {"lodash": "^4.0.0"}}`)
	writeFile(t, dir, "package-lock.json", `{"packages": {"": {}, "node_modules/lodash": {"version": "4.17.21"}}}`)

	target := model.Target{Kind: model.TargetPackage, Ecosystem: "npm", Package: "x", Version: "1.0.0"}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), target, acWithQuerier(dir, &fakeQuerier{}))
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (%v)", res.Status, res.Errors)
	}
	// The coordinate itself plus package-lock.json; package.json is
	// dropped rather than counted a second time
	if res.Coverage.FilesDiscovered != 2 {
		t.Fatalf("FilesDiscovered = %d, want 2 (the coordinate and package-lock.json; package.json dropped in favor of it)", res.Coverage.FilesDiscovered)
	}
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "package.json") {
			t.Fatalf("package.json must not be reported once package-lock.json resolves it: %v", res.Coverage.LimitsHit)
		}
	}
}

func TestManifestWithNoLockfileIsCoverageGapForSourceTarget(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "server.js", `const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const server = new McpServer({ name: "x", version: "1.0.0" });
server.tool("echo", "Echoes text back unchanged", (args) => args.text);
`)
	writeFile(t, dir, "package.json", `{"name": "x", "dependencies": {"left-pad": "^1.0.0", "lodash": "^4.0.0"}}`)

	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, &fakeQuerier{}))
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (%v)", res.Status, res.Errors)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("a manifest with no lockfile to resolve it must land in LimitsHit")
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("a manifest whose dependency ranges were never resolved must downgrade the scan")
	}

	// The gap must actually reach the scan-level verdict, not just sit
	// unread in the analyzer's own Coverage
	scan := &model.ScanResult{Analyzers: []model.AnalyzerResult{res}}
	scan.Aggregate(model.DefaultBlockingSeverity)
	if scan.Status != model.StatusPartial {
		t.Fatalf("scan status = %s, want PARTIAL", scan.Status)
	}
}

func TestGoSumSupersedesGoModInSameDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module x\n\nrequire github.com/foo/bar v1.0.0\n")
	writeFile(t, dir, "go.sum", "github.com/foo/bar v1.2.3 h1:abc=\ngithub.com/foo/bar v1.2.3/go.mod h1:def=\n")

	q := &fakeQuerier{}
	a := &Analyzer{}
	a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, q))

	if len(q.calls) != 1 {
		t.Fatalf("got %d OSV queries, want 1 (go.mod must be superseded by go.sum): %v", len(q.calls), q.calls)
	}
	if q.calls[0].Version != "v1.2.3" {
		t.Fatalf("queried version = %s, want v1.2.3 from go.sum, not go.mod's v1.0.0", q.calls[0].Version)
	}
}

func TestMultipleLockfilesAreAllChecked(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "flask==2.0.0\n")
	writeFile(t, dir, "package-lock.json", `{"packages": {"": {}, "node_modules/lodash": {"version": "4.17.21"}}}`)

	q := &fakeQuerier{}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, q))
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (%v)", res.Status, res.Errors)
	}
	if res.Coverage.FilesDiscovered != 2 || res.Coverage.FilesParsed != 2 {
		t.Fatalf("coverage = %+v, want 2 discovered and 2 parsed", res.Coverage)
	}
	if len(q.calls) != 2 {
		t.Fatalf("got %d OSV queries, want 2 (one per lockfile's coordinate)", len(q.calls))
	}
}

func TestUnreadableLockfileIsCoverageGapNotSilentPass(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "flask==2.0.0\n")
	// Make it unreadable to force a read failure
	if err := os.Chmod(filepath.Join(dir, "requirements.txt"), 0o000); err != nil {
		t.Skip("cannot make file unreadable in this environment")
	}
	defer os.Chmod(filepath.Join(dir, "requirements.txt"), 0o644)
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not block reads")
	}

	q := &fakeQuerier{}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, q))
	if res.Coverage.FilesFailed != 1 {
		t.Fatalf("FilesFailed = %d, want 1", res.Coverage.FilesFailed)
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("a failed lockfile read must show up as a coverage gap")
	}
}

func TestOSVFailureIsError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "flask==2.0.0\n")
	a := &Analyzer{}
	ac := &analyzer.AnalysisContext{Root: dir, Options: map[string]map[string]any{name: {"querier": failingQuerier{}}}}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	if res.Status != model.AnalyzerFailed {
		t.Fatalf("status = %s, want ERROR", res.Status)
	}
}

type failingQuerier struct{}

func (failingQuerier) Query(ctx context.Context, c osv.Coordinate) ([]osv.Vuln, error) {
	return nil, os.ErrDeadlineExceeded
}

func TestUnrecognizedLockfileIsCoverageGapNotSkip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")

	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, &fakeQuerier{}))
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (a recognized-but-unparsed lockfile is not \"nothing to check\")", res.Status)
	}
	if res.Coverage.FilesDiscovered != 1 {
		t.Fatalf("FilesDiscovered = %d, want 1", res.Coverage.FilesDiscovered)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("an unrecognized lockfile format must land in LimitsHit")
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("an unrecognized lockfile format must downgrade the scan")
	}
}

func TestUnrecognizedLockfileNextToRecognizedOneStillGaps(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	writeFile(t, dir, "yarn.lock", "# yarn lockfile v1\n")
	writeFile(t, dir, "requirements.txt", "flask==2.0.0\n")

	q := &fakeQuerier{}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, q))
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED", res.Status)
	}
	if len(q.calls) != 1 {
		t.Fatalf("got %d OSV queries, want 1 (only requirements.txt is parseable)", len(q.calls))
	}
	if res.Coverage.FilesDiscovered != 3 {
		t.Fatalf("FilesDiscovered = %d, want 3 (2 unrecognized + 1 parsed)", res.Coverage.FilesDiscovered)
	}
	if len(res.Coverage.LimitsHit) != 2 {
		t.Fatalf("LimitsHit = %v, want one entry per unrecognized lockfile", res.Coverage.LimitsHit)
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("an unparsed Node lockfile next to a parsed one must still downgrade the scan")
	}
}

// TestOversizedLockfileIsNotSilentlyTruncated: a
// lockfile larger than the read cap must not be parsed on a truncated
// prefix and reported as a complete dependency list
func TestOversizedLockfileIsNotSilentlyTruncated(t *testing.T) {
	dir := t.TempDir()
	huge := strings.Repeat("flask==2.0.0\n", (maxLockfileBytes/13)+100)
	writeFile(t, dir, "requirements.txt", huge)

	q := &fakeQuerier{}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, q))
	if len(q.calls) != 0 {
		t.Fatalf("got %d OSV queries, want 0: an oversized lockfile must not be parsed on a truncated prefix", len(q.calls))
	}
	if res.Coverage.FilesFailed != 1 {
		t.Fatalf("FilesFailed = %d, want 1", res.Coverage.FilesFailed)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("an oversized lockfile must land in LimitsHit")
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("an oversized lockfile must downgrade the scan")
	}
}

func TestVendoredDirsAreExcludedAndReported(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "flask==2.0.0\n")
	writeFile(t, dir, "node_modules/some-dep/package-lock.json", `{"packages": {"": {}}}`)

	q := &fakeQuerier{}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, q))
	if res.Coverage.FilesDiscovered != 1 {
		t.Fatalf("FilesDiscovered = %d, want 1: node_modules must not be walked into", res.Coverage.FilesDiscovered)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("excluding node_modules from lockfile discovery must be recorded in LimitsHit")
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("excluding node_modules from lockfile discovery must downgrade the scan")
	}
}

func TestUnreadableDirectoryDoesNotAbortDiscoveryOfLaterLockfiles(t *testing.T) {
	dir := t.TempDir()
	locked := filepath.Join(dir, "aaa_locked") // sorts before zzz_app lexically
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	defer os.Chmod(locked, 0o755) // let TempDir's cleanup remove it
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not block reads")
	}
	writeFile(t, dir, "zzz_app/requirements.txt", "flask==2.0.0\n")

	bad := osv.Coordinate{Ecosystem: "PyPI", Name: "flask", Version: "2.0.0"}
	q := &fakeQuerier{byCoord: map[osv.Coordinate][]osv.Vuln{bad: {{ID: "GHSA-xxxx", Summary: "known bad"}}}}

	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, q))

	if res.Status == model.AnalyzerSkipped {
		t.Fatal("status = SKIPPED: the unreadable directory must not read as \"nothing to check\" while a lockfile behind it was never reached")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: requirements.txt behind the unreadable directory must still be discovered and checked", len(res.Findings))
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("an unreadable directory must downgrade the scan, whatever else was found")
	}
	found := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "aaa_locked") {
			found = true
		}
	}
	if !found {
		t.Fatalf("LimitsHit = %v, want an entry naming the unreadable directory", res.Coverage.LimitsHit)
	}
}

func TestUnreadableDirectoryAloneIsNotReportedAsSkipped(t *testing.T) {
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	defer os.Chmod(locked, 0o755)
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not block reads")
	}

	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, &fakeQuerier{}))

	if res.Status == model.AnalyzerSkipped {
		t.Fatalf("status = SKIPPED (warnings: %v): a tree that was never fully enumerated is not the same as one with nothing to check", res.Warnings)
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("an unreadable directory must downgrade the scan even when nothing else was found")
	}
}

func TestSymlinkedLockfileOutsideRootIsRefusedNotFollowed(t *testing.T) {
	outside := t.TempDir()
	writeFile(t, outside, "Cargo.lock", "[[package]]\nname = \"leaked-from-outside-root\"\nversion = \"9.9.9\"\n")

	scanRoot := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "Cargo.lock"), filepath.Join(scanRoot, "Cargo.lock")); err != nil {
		t.Fatal(err)
	}

	q := &fakeQuerier{}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(scanRoot, q))

	if len(q.calls) != 0 {
		t.Fatalf("got %d OSV queries, want 0: a symlinked lockfile must never be read, got %v", len(q.calls), q.calls)
	}
	if res.Coverage.FilesParsed != 0 {
		t.Fatalf("FilesParsed = %d, want 0", res.Coverage.FilesParsed)
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("a refused symlink must downgrade the scan, not report a clean pass")
	}
	found := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "Cargo.lock") && strings.Contains(l, "symlink") {
			found = true
		}
	}
	if !found {
		t.Fatalf("LimitsHit = %v, want an entry naming the refused symlink", res.Coverage.LimitsHit)
	}
}

func TestSymlinkedLockfileInsideRootIsStillRefused(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "real/Cargo.lock", "[[package]]\nname = \"inside-root\"\nversion = \"1.0.0\"\n")
	if err := os.Symlink(filepath.Join(dir, "real", "Cargo.lock"), filepath.Join(dir, "Cargo.lock")); err != nil {
		t.Fatal(err)
	}

	q := &fakeQuerier{}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, q))

	if len(q.calls) != 1 {
		t.Fatalf("got %d OSV queries, want 1 (only the real file, not the symlink)", len(q.calls))
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("the refused symlink must still downgrade the scan even though a real lockfile was also found")
	}
}

func TestRegisteredUnderPublicName(t *testing.T) {
	a, ok := analyzer.Default.Get("supplychain")
	if !ok || a.Name() != "supplychain" {
		t.Fatal("analyzer did not self-register as \"supplychain\"")
	}
}

func TestLongLineLockfileIsNotCountedAsParsed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "# "+strings.Repeat("a", 2<<20)+"\nflask==2.0.0\n")

	q := &fakeQuerier{}
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, q))
	if len(q.calls) != 0 {
		t.Fatalf("got %d OSV queries, want 0: a truncated parse must not be queried as if it were the whole file", len(q.calls))
	}
	if res.Coverage.FilesParsed != 0 || res.Coverage.FilesFailed != 1 {
		t.Fatalf("coverage = %+v, want FilesParsed 0 and FilesFailed 1", res.Coverage)
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("a lockfile that could not be read to the end must downgrade the scan")
	}
}

// A version range leaves the installed version unchecked and creates a gap. pip options such as
// --index-url are not dependencies.
func TestUnpinnedRequirementsAreAGap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "flask>=2.0\nrequests~=2.31\n--index-url https://example.invalid/simple\n")

	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, &fakeQuerier{}))
	if res.Coverage.FilesParsed != 1 {
		t.Fatalf("FilesParsed = %d, want 1: the file itself was read to the end", res.Coverage.FilesParsed)
	}
	if len(res.Coverage.LimitsHit) != 1 || !strings.Contains(res.Coverage.LimitsHit[0], "2 dependency line(s)") {
		t.Fatalf("LimitsHit = %v, want one entry naming the 2 ranges and not the --index-url option", res.Coverage.LimitsHit)
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("dependencies whose installed version was never checked left no gap")
	}
}

// An included requirements file is content this analyzer never opened, so
// unlike a range it is a real gap
func TestIncludedRequirementsFileDowngrades(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "requests==2.31.0\n-r other.txt\n")

	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, acWithQuerier(dir, &fakeQuerier{}))
	if len(res.Coverage.LimitsHit) != 1 || !strings.Contains(res.Coverage.LimitsHit[0], "1 included") {
		t.Fatalf("LimitsHit = %v, want one entry naming the unopened include", res.Coverage.LimitsHit)
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("a requirements file this analyzer never opened must downgrade the scan")
	}
}

// Map CLI ecosystem names to OSV names so casing differences cannot produce an empty query
func TestPackageTargetQueriesOSVsEcosystemName(t *testing.T) {
	for given, want := range map[string]string{"npm": "npm", "pypi": "PyPI", "PyPI": "PyPI", "go": "Go", "cargo": "crates.io"} {
		q := &fakeQuerier{}
		target := model.Target{Kind: model.TargetPackage, Ecosystem: given, Package: "demo", Version: "1.0.0"}
		(&Analyzer{}).Analyze(context.Background(), target, acWithQuerier("", q))
		if len(q.calls) != 1 || q.calls[0].Ecosystem != want {
			t.Errorf("ecosystem %q was queried as %+v, want %q", given, q.calls, want)
		}
	}
}

// Check an unversioned package at the registry-resolved version. Without that version, report a
// gap instead of querying every release.
func TestPackageTargetVersionComesFromTheRegistry(t *testing.T) {
	target := model.Target{Kind: model.TargetPackage, Ecosystem: "npm", Package: "demo"}

	q := &fakeQuerier{}
	ac := acWithQuerier("", q)
	ac.Artifacts = analyzer.NewArtifacts()
	ac.Artifacts.Set(supplychain.ResolvedVersionKey, "2.3.4")
	(&Analyzer{}).Analyze(context.Background(), target, ac)
	if len(q.calls) != 1 || q.calls[0].Version != "2.3.4" {
		t.Fatalf("queried %+v, want version 2.3.4 from the registry", q.calls)
	}

	q = &fakeQuerier{}
	res := (&Analyzer{}).Analyze(context.Background(), target, acWithQuerier("", q))
	if len(q.calls) != 0 {
		t.Errorf("an unversioned package was queried anyway: %+v", q.calls)
	}
	// Check the named limit directly because another coverage gap could hide its absence
	found := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "version could not be resolved") {
			found = true
		}
	}
	if !found {
		t.Errorf("an unresolved version left no limit: %+v", res.Coverage)
	}
}
