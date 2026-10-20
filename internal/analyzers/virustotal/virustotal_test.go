package virustotal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

const testKeyEnv = "VT_TEST_KEY"
const testKeyValue = "vt-super-secret-value-24680"

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func acWithServer(t *testing.T, root string, handler http.HandlerFunc, extraOpts map[string]any) *analyzer.AnalysisContext {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv(testKeyEnv, testKeyValue)
	opts := map[string]any{"base_url": srv.URL, "api_key_env": testKeyEnv, "allow_insecure_endpoint": true}
	maps.Copy(opts, extraOpts)
	return &analyzer.AnalysisContext{Root: root, Options: map[string]map[string]any{name: opts}}
}

func TestSkippedWhenNoKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "hello")
	a := &Analyzer{}
	ac := &analyzer.AnalysisContext{Root: dir, Options: map[string]map[string]any{name: {"api_key_env": "VT_NOT_SET_XYZ"}}}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("status = %s, want SKIPPED", res.Status)
	}
}

func TestSkippedWhenNoRoot(t *testing.T) {
	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, &analyzer.AnalysisContext{})
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("status = %s, want SKIPPED", res.Status)
	}
}

func TestUnknownHashProducesNoFinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "clean.txt", "nothing to see here")
	a := &Analyzer{}
	ac := acWithServer(t, dir, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}, nil)
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (%v)", res.Status, res.Errors)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("a 404 (unknown hash) must not produce a finding, got %d", len(res.Findings))
	}
	if res.Coverage.FilesParsed != 1 {
		t.Fatalf("FilesParsed = %d, want 1", res.Coverage.FilesParsed)
	}
}

func TestMaliciousHashProducesFinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bad.exe", "totally not malware")
	a := &Analyzer{}
	ac := acWithServer(t, dir, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"attributes": map[string]any{
					"last_analysis_stats": map[string]any{"malicious": 12, "suspicious": 2, "harmless": 60, "undetected": 6},
				},
			},
		})
	}, nil)
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (%v)", res.Status, res.Errors)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != model.SeverityCritical {
		t.Fatalf("severity = %s, want CRITICAL for 12 malicious detections", f.Severity)
	}
	if f.File != "bad.exe" {
		t.Fatalf("File = %q, want bad.exe", f.File)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("finding failed Validate: %v", err)
	}
}

func TestNeverUploadsWhenAllowUploadIsFalse(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "unknown.bin", "mystery bytes")
	uploaded := false
	a := &Analyzer{}
	ac := acWithServer(t, dir, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			uploaded = true
		}
		w.WriteHeader(http.StatusNotFound)
	}, map[string]any{"allow_upload": false})
	a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	if uploaded {
		t.Fatal("analyzer uploaded a file though allow_upload was false")
	}
}

func TestUploadsOnlyWhenExplicitlyAllowed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "unknown.bin", "mystery bytes")
	uploaded := false
	a := &Analyzer{}
	ac := acWithServer(t, dir, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			uploaded = true
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "abc123"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, map[string]any{"allow_upload": true})
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	if !uploaded {
		t.Fatal("analyzer did not upload the file though allow_upload was true")
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "submitted for analysis") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a warning noting the file was submitted for analysis")
	}
}

func TestAPIKeyNeverLeaks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "x")
	a := &Analyzer{}
	ac := acWithServer(t, dir, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, nil)
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	for _, e := range res.Errors {
		if strings.Contains(e.Message, testKeyValue) {
			t.Fatalf("API key leaked into error message: %s", e.Message)
		}
	}
}

func TestSha256ReaderMatchesStdlib(t *testing.T) {
	got, size, err := sha256Reader(strings.NewReader("known content"))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("known content"))
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("hash mismatch: got %s", got)
	}
	if size != int64(len("known content")) {
		t.Fatalf("size = %d, want %d", size, len("known content"))
	}
}

func TestPerScanFileCapIsCountedAndDowngrades(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "a")
	writeFile(t, dir, "b.txt", "b")
	writeFile(t, dir, "c.txt", "c")
	a := &Analyzer{}
	ac := acWithServer(t, dir, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}, map[string]any{"max_files": 2})
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (%v)", res.Status, res.Errors)
	}
	if res.Coverage.FilesSkipped != 1 {
		t.Fatalf("FilesSkipped = %d, want 1", res.Coverage.FilesSkipped)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("the file cap must be recorded as a limit, not silently excused")
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("a capped scan must downgrade, not report clean coverage")
	}
}

func TestGitDirectoryExcludedFromFileList(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git", "objects", "ab"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, ".git/HEAD", "ref: refs/heads/main\n")
	writeFile(t, dir, ".git/config", "[core]\n")
	writeFile(t, dir, ".git/objects/ab/cdef", "blob")
	writeFile(t, dir, "main.go", "package main\n")
	writeFile(t, dir, "server.py", "print('hi')\n")

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	files, excludedDirs, err := listFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f == ".git" || strings.HasPrefix(f, ".git/") {
			t.Fatalf("listFiles returned a path under .git: %q (files = %v)", f, files)
		}
	}
	if len(excludedDirs) != 0 {
		t.Fatalf("excludedDirs = %v, want none - .git is excluded silently, not reported", excludedDirs)
	}
	if len(files) != 2 {
		t.Fatalf("files = %v, want exactly main.go and server.py", files)
	}
}

func TestVendoredDirIsExcludedAndReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "node_modules", "left-pad"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "node_modules/left-pad/index.js", "module.exports = 1;\n")
	writeFile(t, dir, "main.go", "package main\n")

	a := &Analyzer{}
	ac := acWithServer(t, dir, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}, nil)
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (%v)", res.Status, res.Errors)
	}
	if res.Coverage.FilesDiscovered != 1 {
		t.Fatalf("FilesDiscovered = %d, want 1 (node_modules excluded)", res.Coverage.FilesDiscovered)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("excluding node_modules must be recorded as a limit, not silently dropped")
	}
	if len(res.Coverage.Gaps()) == 0 {
		t.Fatal("excluding a vendored directory must downgrade the scan")
	}
}

func TestClaimedFilesOrderedBeforeUnclaimedWhenBudgetIsTight(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "aaa_unclaimed.dat", "junk")
	source := "package main\n"
	writeFile(t, dir, "zzz_main.go", source)

	sum := sha256.Sum256([]byte(source))
	wantHash := hex.EncodeToString(sum[:])

	var requested []string
	a := &Analyzer{}
	ac := acWithServer(t, dir, func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}, map[string]any{"max_files": 1})
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, want COMPLETED (%v)", res.Status, res.Errors)
	}
	if res.Coverage.FilesParsed != 1 {
		t.Fatalf("FilesParsed = %d, want 1", res.Coverage.FilesParsed)
	}
	if len(requested) != 1 || !strings.Contains(requested[0], wantHash) {
		t.Fatalf("requested = %v, want a single lookup for the claimed .go file's hash (%s)", requested, wantHash)
	}
}

func TestUploadSendsExactlyWhatWasHashed(t *testing.T) {
	dir := t.TempDir()
	original := "original content, this is what should be hashed and uploaded"
	target := writeFile(t, dir, "unknown.bin", original)

	// Outside dir, so it is never itself something listFiles walks and
	// scans - only the rename below should make it relevant
	replacement := filepath.Join(t.TempDir(), "replacement.bin")
	if err := os.WriteFile(replacement, []byte("attacker-controlled replacement content"), 0o644); err != nil {
		t.Fatal(err)
	}

	var uploadedBody string
	a := &Analyzer{}
	ac := acWithServer(t, dir, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {

			if err := os.Rename(replacement, target); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f, _, err := r.FormFile("file")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		b, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		uploadedBody = string(b)
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "abc123"}})
	}, map[string]any{"allow_upload": true})

	a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)

	if uploadedBody != original {
		t.Fatalf("uploaded %q, want the originally hashed content %q", uploadedBody, original)
	}
}

// Observation regression (plaintext provider endpoints): base_url carries
// the API key on every request, so a plain http base_url must be rejected
// unless allow_insecure_endpoint opted in
func TestPlainHTTPBaseURLRejectedByDefault(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "hello")
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dialed = true }))
	defer srv.Close()
	t.Setenv(testKeyEnv, testKeyValue)
	a := &Analyzer{}
	ac := &analyzer.AnalysisContext{
		Root:    dir,
		Options: map[string]map[string]any{name: {"base_url": srv.URL, "api_key_env": testKeyEnv}},
	}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource}, ac)
	if res.Status != model.AnalyzerFailed {
		t.Fatalf("status = %s, want ERROR for a rejected plain http base_url (%v)", res.Status, res.Errors)
	}
	if dialed {
		t.Fatal("must reject the base_url before dialing, not after")
	}
}

func TestRegisteredUnderPublicName(t *testing.T) {
	a, ok := analyzer.Default.Get("virustotal")
	if !ok || a.Name() != "virustotal" {
		t.Fatal("analyzer did not self-register as \"virustotal\"")
	}
}
