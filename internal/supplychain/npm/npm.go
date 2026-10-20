// Package npm downloads a published npm package's tarball and unpacks it
// with internal/supplychain/archive. It never runs npm install, a lifecycle
// script (preinstall/install/postinstall), or any other package code - the
// tarball is treated purely as data to extract and hand to other analyzers.
package npm

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/httpx"
	"github.com/devlab-group/mcp-scanner/internal/supplychain/archive"
)

const defaultRegistry = "https://registry.npmjs.org"

// Fetcher downloads packages from an npm registry. Both the registry metadata request and
// the tarball download - whose URL the registry response names, not the caller - go through
// httpx.DefaultPolicy: no private-network destination, guarded at dial time, no
// cross-origin redirect followed.
type Fetcher struct {
	Registry string
	Client   *http.Client
	Limits   archive.Limits
	// Policy is what CheckURL runs the tarball URL through. Tests point it
	// at an httptest.Server and so need AllowPrivateNetworks; production
	// use leaves it at its default.
	Policy httpx.Policy
}

// New builds a Fetcher pointed at the public npm registry with the
// package's default archive safety limits
func New() *Fetcher {
	policy := httpx.DefaultPolicy()
	return &Fetcher{Registry: defaultRegistry, Client: policy.Client(30 * time.Second), Limits: archive.DefaultLimits(), Policy: policy}
}

type packageMeta struct {
	Version string `json:"version"`
	Dist    struct {
		Tarball   string `json:"tarball"`
		Shasum    string `json:"shasum"`
		Integrity string `json:"integrity"`
	} `json:"dist"`
}

func (f *Fetcher) resolve(ctx context.Context, name, version string) (*packageMeta, error) {
	ref := version
	if ref == "" {
		ref = "latest"
	}
	target := fmt.Sprintf("%s/%s/%s", strings.TrimSuffix(f.Registry, "/"), url.PathEscape(name), url.PathEscape(ref))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("npm: build metadata request: %w", err)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm: fetch metadata for %s@%s: %w", name, ref, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm: registry returned status %d for %s@%s", resp.StatusCode, name, ref)
	}
	var meta packageMeta
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return nil, fmt.Errorf("npm: could not parse metadata for %s@%s: %w", name, ref, err)
	}
	return &meta, nil
}

func (f *Fetcher) fetchBytes(ctx context.Context, tarballURL string) ([]byte, error) {
	// tarballURL came out of the registry's own JSON response, not
	// something the caller of this package chose - check it explicitly
	// before dialing, on top of the guard already built into f.Client
	if err := f.Policy.CheckURL(tarballURL); err != nil {
		return nil, fmt.Errorf("npm: tarball url rejected: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	if err != nil {
		return nil, fmt.Errorf("npm: build tarball request: %w", err)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm: download tarball: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm: registry returned status %d for the tarball", resp.StatusCode)
	}
	max := f.Limits.MaxCompressedBytes
	if max <= 0 {
		max = archive.DefaultLimits().MaxCompressedBytes
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("npm: read tarball: %w", err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("npm: tarball exceeds the configured compressed size limit (%d bytes)", max)
	}
	return data, nil
}

// Download fetches name@version's tarball, verifies it against the
// registry's declared integrity (preferred) or shasum, and extracts it
// under destDir. destDir must already exist. Nothing in the package is
// ever executed: this is a download and an archive.Extract call, nothing
// else.
func (f *Fetcher) Download(ctx context.Context, name, version, destDir string) (archive.Result, string, error) {
	meta, err := f.resolve(ctx, name, version)
	if err != nil {
		return archive.Result{}, "", err
	}
	if meta.Dist.Tarball == "" {
		return archive.Result{}, "", fmt.Errorf("npm: registry response for %s had no dist.tarball", name)
	}

	data, err := f.fetchBytes(ctx, meta.Dist.Tarball)
	if err != nil {
		return archive.Result{}, "", err
	}

	switch {
	case meta.Dist.Integrity != "":
		if err := verifyIntegrity(data, meta.Dist.Integrity); err != nil {
			return archive.Result{}, "", fmt.Errorf("npm: %s@%s: %w", name, orLatest(version), err)
		}
	case meta.Dist.Shasum != "":
		sum := sha1.Sum(data)
		if hex.EncodeToString(sum[:]) != strings.ToLower(meta.Dist.Shasum) {
			return archive.Result{}, "", fmt.Errorf("npm: tarball checksum mismatch for %s@%s: registry declared a shasum that does not match the downloaded bytes", name, orLatest(version))
		}
	default:
		return archive.Result{}, "", fmt.Errorf("npm: registry response for %s@%s had no integrity or shasum - refusing to extract unverified bytes", name, orLatest(version))
	}

	res, err := archive.Extract(bytes.NewReader(data), archive.FormatTarGz, destDir, f.Limits)
	return res, meta.Version, err
}

// verifyIntegrity checks data against an npm dist.integrity string
// (https://www.w3.org/TR/SRI/): one or more space-separated "algorithm-base64digest"
// entries. Unsupported algorithms fail closed; the caller must not fall back to the weaker
// shasum when the registry supplied an integrity value it cannot verify.
func verifyIntegrity(data []byte, integrity string) error {
	for entry := range strings.FieldsSeq(integrity) {
		algo, encoded, ok := strings.Cut(entry, "-")
		if !ok {
			continue
		}
		var sum []byte
		switch algo {
		case "sha512":
			s := sha512.Sum512(data)
			sum = s[:]
		case "sha256":
			s := sha256.Sum256(data)
			sum = s[:]
		default:
			return fmt.Errorf("integrity entry uses an unsupported algorithm %q", algo)
		}
		want, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("could not decode %s integrity digest: %w", algo, err)
		}
		if !bytes.Equal(sum, want) {
			return fmt.Errorf("tarball integrity mismatch: registry declared %s integrity that does not match the downloaded bytes", algo)
		}
		return nil
	}
	return fmt.Errorf("integrity string %q had no entry in a supported algorithm", integrity)
}

func orLatest(version string) string {
	if version == "" {
		return "latest"
	}
	return version
}
