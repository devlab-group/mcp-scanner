package pypi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/httpx"
)

func newFetcher(srv *httptest.Server) *Fetcher {
	f := New()
	f.Index = srv.URL
	f.Client = srv.Client()
	f.Policy = httpx.Policy{AllowPrivateNetworks: true}
	return f
}

func buildSdist(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{Name: "evil_pkg-1.0.0/" + name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func newIndex(t *testing.T, sdist []byte, sha256hex string) *httptest.Server {
	t.Helper()
	var mux http.ServeMux
	mux.HandleFunc("/evil-pkg-1.0.0.tar.gz", func(w http.ResponseWriter, r *http.Request) { w.Write(sdist) })
	srv := httptest.NewServer(&mux)
	mux.HandleFunc("/evil-pkg/json", func(w http.ResponseWriter, r *http.Request) {
		file := map[string]any{
			"url":         srv.URL + "/evil-pkg-1.0.0.tar.gz",
			"filename":    "evil-pkg-1.0.0.tar.gz",
			"packagetype": "sdist",
			"digests":     map[string]string{"sha256": sha256hex},
		}
		json.NewEncoder(w).Encode(map[string]any{
			"info":     map[string]string{"version": "1.0.0"},
			"urls":     []any{file},
			"releases": map[string]any{"1.0.0": []any{file}},
		})
	})
	return srv
}

func TestDownloadExtractsAndVerifiesChecksum(t *testing.T) {
	sdist := buildSdist(t, map[string]string{"setup.py": "print('hi')", "evil_pkg/__init__.py": "x = 1"})
	sum := sha256.Sum256(sdist)
	srv := newIndex(t, sdist, hex.EncodeToString(sum[:]))
	defer srv.Close()

	f := newFetcher(srv)

	dest := t.TempDir()
	res, _, err := f.Download(context.Background(), "evil-pkg", "", dest)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if res.Files != 2 {
		t.Fatalf("Files = %d, want 2", res.Files)
	}
	if _, err := os.Stat(filepath.Join(dest, "evil_pkg-1.0.0", "evil_pkg", "__init__.py")); err != nil {
		t.Fatalf("expected extracted file, stat error: %v", err)
	}
}

func TestChecksumMismatchIsRejected(t *testing.T) {
	sdist := buildSdist(t, map[string]string{"setup.py": "print('hi')"})
	srv := newIndex(t, sdist, "0000000000000000000000000000000000000000000000000000000000000000")
	defer srv.Close()

	f := newFetcher(srv)

	if _, _, err := f.Download(context.Background(), "evil-pkg", "", t.TempDir()); err == nil {
		t.Fatal("expected a checksum mismatch error")
	}
}

func TestBuildNeverRuns(t *testing.T) {
	markerDir := t.TempDir()
	marker := filepath.Join(markerDir, "BUILD_RAN")
	setupPy := fmt.Sprintf("import os\nos.system('touch %s')\n", marker)

	sdist := buildSdist(t, map[string]string{"setup.py": setupPy})
	sum := sha256.Sum256(sdist)
	srv := newIndex(t, sdist, hex.EncodeToString(sum[:]))
	defer srv.Close()

	f := newFetcher(srv)

	if _, _, err := f.Download(context.Background(), "evil-pkg", "", t.TempDir()); err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("build marker file exists: setup.py ran (stat err = %v)", err)
	}
}

func TestMaliciousReleaseURLSchemeIsRejected(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/evil-pkg/json", func(w http.ResponseWriter, r *http.Request) {
		file := map[string]any{"url": "file:///etc/passwd", "filename": "evil-pkg-1.0.0.tar.gz", "packagetype": "sdist"}
		json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]string{"version": "1.0.0"}, "urls": []any{file},
		})
	})
	srv := httptest.NewServer(&mux)
	defer srv.Close()

	f := newFetcher(srv)
	if _, _, err := f.Download(context.Background(), "evil-pkg", "", t.TempDir()); err == nil {
		t.Fatal("expected a file:// release url to be rejected")
	}
}

// The production default must not reach a private-network release URL
func TestDefaultPolicyBlocksPrivateReleaseURL(t *testing.T) {
	sdist := buildSdist(t, map[string]string{"setup.py": "print('hi')"})
	sum := sha256.Sum256(sdist)
	srv := newIndex(t, sdist, hex.EncodeToString(sum[:]))
	defer srv.Close()

	f := New() // default policy: no AllowPrivateNetworks override
	f.Index = srv.URL
	// Allow the index request so the release URL check is the refusal under test
	f.Client = srv.Client()

	_, _, err := f.Download(context.Background(), "evil-pkg", "", t.TempDir())
	if err == nil {
		t.Fatal("expected the default policy to reject a loopback release url")
	}
	if !strings.Contains(err.Error(), "release file url rejected") {
		t.Fatalf("refused somewhere else than the release URL check: %v", err)
	}
}

func TestMissingSHA256IsRejected(t *testing.T) {
	sdist := buildSdist(t, map[string]string{"setup.py": "print('hi')"})
	srv := newIndex(t, sdist, "")
	defer srv.Close()

	f := newFetcher(srv)
	if _, _, err := f.Download(context.Background(), "evil-pkg", "", t.TempDir()); err == nil {
		t.Fatal("expected a release file with no sha256 digest to be rejected rather than extracted unverified")
	}
}

func TestFormatForWheel(t *testing.T) {
	format, err := formatFor("evil_pkg-1.0.0-py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	if format != "zip" {
		t.Fatalf("format = %s, want zip (a wheel is a zip file)", format)
	}
}
