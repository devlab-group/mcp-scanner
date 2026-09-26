// Package pypi downloads and extracts PyPI sdists and wheels. It treats
// packages as data and never runs setup.py, pip, or build hooks.
package pypi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/revinand/mcp-scanner/internal/httpx"
	"github.com/revinand/mcp-scanner/internal/supplychain/archive"
)

const defaultIndex = "https://pypi.org/pypi"

// Fetcher downloads packages from a PyPI-compatible JSON API. Metadata and
// release requests use httpx.DefaultPolicy to block private destinations and
// cross-origin redirects.
type Fetcher struct {
	Index  string
	Client *http.Client
	Limits archive.Limits
	// Policy validates release URLs. Tests permit private addresses for
	// httptest servers; production uses the default restrictions.
	Policy httpx.Policy
}

// New returns a public-index fetcher with default archive limits
func New() *Fetcher {
	policy := httpx.DefaultPolicy()
	return &Fetcher{Index: defaultIndex, Client: policy.Client(30 * time.Second), Limits: archive.DefaultLimits(), Policy: policy}
}

type releaseFile struct {
	URL         string `json:"url"`
	Filename    string `json:"filename"`
	PackageType string `json:"packagetype"` // "sdist" | "bdist_wheel"
	Digests     struct {
		SHA256 string `json:"sha256"`
	} `json:"digests"`
}

type projectMeta struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	URLs     []releaseFile            `json:"urls"`
	Releases map[string][]releaseFile `json:"releases"`
}

func (f *Fetcher) fetchMeta(ctx context.Context, name string) (*projectMeta, error) {
	target := fmt.Sprintf("%s/%s/json", strings.TrimSuffix(f.Index, "/"), url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("pypi: build metadata request: %w", err)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pypi: fetch metadata for %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi: index returned status %d for %s", resp.StatusCode, name)
	}
	var meta projectMeta
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&meta); err != nil {
		return nil, fmt.Errorf("pypi: could not parse metadata for %s: %w", name, err)
	}
	return &meta, nil
}

// pickFile prefers an sdist, then falls back to the first wheel
func pickFile(files []releaseFile) (releaseFile, error) {
	var wheel releaseFile
	haveWheel := false
	for _, rf := range files {
		if rf.PackageType == "sdist" {
			return rf, nil
		}
		if rf.PackageType == "bdist_wheel" && !haveWheel {
			wheel, haveWheel = rf, true
		}
	}
	if haveWheel {
		return wheel, nil
	}
	return releaseFile{}, fmt.Errorf("pypi: no sdist or wheel found for this release")
}

func (f *Fetcher) fetchBytes(ctx context.Context, fileURL string) ([]byte, error) {
	// The index controls fileURL, so validate it before dialing. The client
	// applies the same policy again during connection setup.
	if err := f.Policy.CheckURL(fileURL); err != nil {
		return nil, fmt.Errorf("pypi: release file url rejected: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return nil, fmt.Errorf("pypi: build download request: %w", err)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pypi: download release file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi: index returned status %d for the release file", resp.StatusCode)
	}
	max := f.Limits.MaxCompressedBytes
	if max <= 0 {
		max = archive.DefaultLimits().MaxCompressedBytes
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("pypi: read release file: %w", err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("pypi: release file exceeds the configured compressed size limit (%d bytes)", max)
	}
	return data, nil
}

func formatFor(filename string) (archive.Format, error) {
	if strings.HasSuffix(strings.ToLower(filename), ".whl") {
		return archive.FormatZip, nil // a wheel is a zip file with a different extension
	}
	return archive.DetectFormat(filename)
}

// Download fetches an sdist or wheel, verifies its SHA-256 digest, and extracts
// it into an existing destDir. An empty version selects the latest release.
func (f *Fetcher) Download(ctx context.Context, name, version, destDir string) (archive.Result, string, error) {
	meta, err := f.fetchMeta(ctx, name)
	if err != nil {
		return archive.Result{}, "", err
	}

	resolved := version
	files := meta.URLs
	if version == "" {
		// meta.URLs and info.version describe the current release
		resolved = meta.Info.Version
	}
	if version != "" {
		var ok bool
		files, ok = meta.Releases[version]
		if !ok || len(files) == 0 {
			return archive.Result{}, "", fmt.Errorf("pypi: no release %s@%s found", name, version)
		}
	}
	if len(files) == 0 {
		return archive.Result{}, "", fmt.Errorf("pypi: %s has no downloadable release files", name)
	}

	rf, err := pickFile(files)
	if err != nil {
		return archive.Result{}, "", err
	}

	data, err := f.fetchBytes(ctx, rf.URL)
	if err != nil {
		return archive.Result{}, "", err
	}

	// Refuse artifacts without a digest, including responses from custom or
	// mirrored indexes. Otherwise the index could bypass verification.
	if rf.Digests.SHA256 == "" {
		return archive.Result{}, "", fmt.Errorf("pypi: %s (%s) has no sha256 digest - refusing to extract unverified bytes", name, rf.Filename)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(rf.Digests.SHA256) {
		return archive.Result{}, "", fmt.Errorf("pypi: checksum mismatch for %s (%s): index declared a sha256 that does not match the downloaded bytes", name, rf.Filename)
	}

	format, err := formatFor(rf.Filename)
	if err != nil {
		return archive.Result{}, "", err
	}
	res, err := archive.Extract(bytes.NewReader(data), format, destDir, f.Limits)
	return res, resolved, err
}
