package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/internal/httpx"
	"github.com/revinand/mcp-scanner/internal/supplychain/archive"
)

func newFetcher(srv *httptest.Server) *Fetcher {
	f := New()
	f.Registry = srv.URL
	f.Client = srv.Client()
	f.Policy = httpx.Policy{AllowPrivateNetworks: true}
	return f
}

// buildTarball builds a gzip-compressed tar in the shape npm publishes:
// everything nested under a "package/" prefix
func buildTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(content))}
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

func newRegistry(t *testing.T, tarball []byte, shasum string) *httptest.Server {
	t.Helper()
	return newRegistryDist(t, tarball, map[string]string{"shasum": shasum})
}

// newRegistryDist is newRegistry with full control over the dist object,
// for tests that need to set integrity, omit shasum, or both
func newRegistryDist(t *testing.T, tarball []byte, dist map[string]string) *httptest.Server {
	t.Helper()
	var mux http.ServeMux
	mux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, r *http.Request) {
		w.Write(tarball)
	})
	srv := httptest.NewServer(&mux)
	// The metadata handler needs the server's own base URL for the tarball
	// link, which only exists once the server is up
	mux.HandleFunc("/evil-pkg/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		d := map[string]string{"tarball": srv.URL + "/tarball.tgz"}
		maps.Copy(d, dist)
		json.NewEncoder(w).Encode(map[string]any{"version": "1.0.0", "dist": d})
	})
	return srv
}

func TestDownloadExtractsAndVerifiesChecksum(t *testing.T) {
	tarball := buildTarball(t, map[string]string{"package.json": `{"name":"evil-pkg","version":"1.0.0"}`, "index.js": "console.log(1)"})
	sum := sha1.Sum(tarball)
	srv := newRegistry(t, tarball, hex.EncodeToString(sum[:]))
	defer srv.Close()

	f := newFetcher(srv)

	dest := t.TempDir()
	res, _, err := f.Download(context.Background(), "evil-pkg", "1.0.0", dest)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if res.Files != 2 {
		t.Fatalf("Files = %d, want 2", res.Files)
	}
	if _, err := os.Stat(filepath.Join(dest, "package", "index.js")); err != nil {
		t.Fatalf("expected extracted file, stat error: %v", err)
	}
}

func TestChecksumMismatchIsRejected(t *testing.T) {
	tarball := buildTarball(t, map[string]string{"package.json": "{}"})
	srv := newRegistry(t, tarball, "0000000000000000000000000000000000000000")
	defer srv.Close()

	f := newFetcher(srv)

	if _, _, err := f.Download(context.Background(), "evil-pkg", "1.0.0", t.TempDir()); err == nil {
		t.Fatal("expected a checksum mismatch error")
	}
}

func TestInstallScriptNeverRuns(t *testing.T) {
	markerDir := t.TempDir()
	marker := filepath.Join(markerDir, "INSTALL_RAN")
	pkgJSON := fmt.Sprintf(`{
		"name": "evil-pkg",
		"version": "1.0.0",
		"scripts": {"preinstall": "touch %s", "install": "touch %s", "postinstall": "touch %s"}
	}`, marker, marker, marker)

	tarball := buildTarball(t, map[string]string{
		"package.json":   pkgJSON,
		"postinstall.sh": fmt.Sprintf("#!/bin/sh\ntouch %s\n", marker),
	})
	sum := sha1.Sum(tarball)
	srv := newRegistry(t, tarball, hex.EncodeToString(sum[:]))
	defer srv.Close()

	f := newFetcher(srv)

	dest := t.TempDir()
	if _, _, err := f.Download(context.Background(), "evil-pkg", "1.0.0", dest); err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("install script marker file exists: a lifecycle script ran (stat err = %v)", err)
	}
}

func TestArchiveLimitsAreEnforced(t *testing.T) {
	tarball := buildTarball(t, map[string]string{"big.txt": string(make([]byte, 10000))})
	sum := sha1.Sum(tarball)
	srv := newRegistry(t, tarball, hex.EncodeToString(sum[:]))
	defer srv.Close()

	f := newFetcher(srv)
	f.Limits = archive.DefaultLimits()
	f.Limits.MaxFileBytes = 100

	if _, _, err := f.Download(context.Background(), "evil-pkg", "1.0.0", t.TempDir()); err == nil {
		t.Fatal("expected the archive file-size limit to reject the oversized member")
	}
}

func TestMaliciousTarballSchemeIsRejected(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/evil-pkg/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"version": "1.0.0",
			"dist":    map[string]string{"tarball": "file:///etc/passwd"},
		})
	})
	srv := httptest.NewServer(&mux)
	defer srv.Close()

	f := newFetcher(srv)
	if _, _, err := f.Download(context.Background(), "evil-pkg", "1.0.0", t.TempDir()); err == nil {
		t.Fatal("expected a file:// tarball url to be rejected")
	}
}

func TestDefaultPolicyBlocksPrivateTarballURL(t *testing.T) {
	tarball := buildTarball(t, map[string]string{"package.json": "{}"})
	sum := sha1.Sum(tarball)
	srv := newRegistry(t, tarball, hex.EncodeToString(sum[:]))
	defer srv.Close()

	f := New() // default policy: no AllowPrivateNetworks override
	f.Registry = srv.URL
	// Allow the metadata request so the tarball URL check is the refusal under test
	f.Client = srv.Client()

	_, _, err := f.Download(context.Background(), "evil-pkg", "1.0.0", t.TempDir())
	if err == nil {
		t.Fatal("expected the default policy to reject a loopback tarball url")
	}
	if !strings.Contains(err.Error(), "tarball url rejected") {
		t.Fatalf("refused somewhere else than the tarball URL check: %v", err)
	}
}

func TestDownloadVerifiesIntegrityOverShasum(t *testing.T) {
	tarball := buildTarball(t, map[string]string{"package.json": "{}"})
	sum := sha512.Sum512(tarball)
	srv := newRegistryDist(t, tarball, map[string]string{
		"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
		"shasum":    "0000000000000000000000000000000000000000",
	})
	defer srv.Close()

	f := newFetcher(srv)
	if _, _, err := f.Download(context.Background(), "evil-pkg", "1.0.0", t.TempDir()); err != nil {
		t.Fatalf("Download failed: %v (integrity should have been used, not the deliberately wrong shasum)", err)
	}
}

func TestIntegrityMismatchIsRejected(t *testing.T) {
	tarball := buildTarball(t, map[string]string{"package.json": "{}"})
	wrong := make([]byte, sha512.Size)
	srv := newRegistryDist(t, tarball, map[string]string{"integrity": "sha512-" + base64.StdEncoding.EncodeToString(wrong)})
	defer srv.Close()

	f := newFetcher(srv)
	if _, _, err := f.Download(context.Background(), "evil-pkg", "1.0.0", t.TempDir()); err == nil {
		t.Fatal("expected an integrity mismatch error")
	}
}

func TestUnsupportedIntegrityAlgorithmIsRejected(t *testing.T) {
	tarball := buildTarball(t, map[string]string{"package.json": "{}"})
	srv := newRegistryDist(t, tarball, map[string]string{"integrity": "sha1-" + base64.StdEncoding.EncodeToString(make([]byte, sha1.Size))})
	defer srv.Close()

	f := newFetcher(srv)
	if _, _, err := f.Download(context.Background(), "evil-pkg", "1.0.0", t.TempDir()); err == nil {
		t.Fatal("expected an unsupported-algorithm integrity string to be rejected, not silently skipped")
	}
}

func TestMissingIntegrityAndShasumIsRejected(t *testing.T) {
	tarball := buildTarball(t, map[string]string{"package.json": "{}"})
	srv := newRegistryDist(t, tarball, map[string]string{})
	defer srv.Close()

	f := newFetcher(srv)
	if _, _, err := f.Download(context.Background(), "evil-pkg", "1.0.0", t.TempDir()); err == nil {
		t.Fatal("expected a download with neither integrity nor shasum to be rejected rather than extracted unverified")
	}
}
